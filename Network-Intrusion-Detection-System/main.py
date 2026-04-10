"""
Network Intrusion Detection System — entry point.

Usage
-----
  # Live capture on default interface (requires root / Npcap admin)
  python main.py

  # Specify interface and BPF filter
  python main.py --interface eth0 --filter "tcp or udp"

  # Read from a PCAP file (no privileges required — great for demos)
  python main.py --pcap captures/sample.pcap

  # Quiet mode: suppress dashboard, write alerts to SIEM only
  python main.py --no-ui --siem alerts.ndjson

  # List available interfaces
  python main.py --list-interfaces

Architecture
------------
Three concurrent asyncio tasks share the event loop:

  capture_task  — PacketSniffer thread → asyncio.Queue (raw Scapy packets)
  process_task  — consumes queue, ParsedPacket, DetectionEngine, alert_queue
  alert_task    — consumes alert_queue, AlertManager, SIEMWriter

A fourth task (dashboard_task) renders the Rich live UI if --no-ui is not set.

The sniffer runs in its own OS thread (via Scapy's AsyncSniffer); all
other logic runs on the single asyncio event loop thread.  No shared
mutable state crosses the thread boundary except the asyncio.Queue,
which uses loop.call_soon_threadsafe internally for thread safety.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from typing import Optional

# ── Module-level logging setup ────────────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("nids")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="nids",
        description="Network Intrusion Detection System — statistical anomaly + signature detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                          # live capture, all interfaces
  python main.py -i eth0                  # specific interface
  python main.py --pcap sample.pcap       # replay a PCAP file
  python main.py --list-interfaces        # show available interfaces
        """,
    )
    p.add_argument(
        "-i", "--interface",
        default=None,
        metavar="IFACE",
        help="Network interface to capture on (default: all)",
    )
    p.add_argument(
        "--filter",
        default="tcp or udp or icmp or arp",
        metavar="BPF",
        help="Berkeley Packet Filter expression (default: tcp or udp or icmp or arp)",
    )
    p.add_argument(
        "--pcap",
        default=None,
        metavar="FILE",
        help="Read packets from a PCAP file instead of live capture",
    )
    p.add_argument(
        "--siem",
        default="alerts.ndjson",
        metavar="FILE",
        help="NDJSON alert output file (default: alerts.ndjson)",
    )
    p.add_argument(
        "--no-ui",
        action="store_true",
        help="Disable the live dashboard (headless / CI mode)",
    )
    p.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Print available network interfaces and exit",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return p.parse_args()


def _list_interfaces() -> None:
    """Print available network interfaces detected by Scapy."""
    try:
        from scapy.arch import get_if_list  # type: ignore
        ifaces = get_if_list()
        print("\nAvailable interfaces:")
        for iface in ifaces:
            print(f"  {iface}")
        print()
    except ImportError:
        print("Scapy is not installed.  Run: pip install scapy")
    sys.exit(0)


def _replay_pcap(
    path: str,
    engine: object,
    alert_mgr: object,
    siem: object,
) -> None:
    """
    Replay a PCAP file synchronously.  Used when --pcap is specified.
    Bypasses the async sniffer — no privileges required.
    """
    from nids.capture.parser import parse_packet
    from nids.detection.engine import DetectionEngine
    from nids.alerts.manager import AlertManager
    from nids.alerts.siem import SIEMWriter

    try:
        from scapy.utils import rdpcap  # type: ignore
    except ImportError:
        print("[error] Scapy is required to read PCAP files.")
        sys.exit(1)

    print(f"[*] Replaying {path} …")
    try:
        packets = rdpcap(path)
    except FileNotFoundError:
        print(f"[error] File not found: {path}")
        sys.exit(1)

    eng: DetectionEngine = engine   # type: ignore[assignment]
    amgr: AlertManager   = alert_mgr  # type: ignore[assignment]
    sw: SIEMWriter       = siem  # type: ignore[assignment]

    for raw_pkt in packets:
        parsed = parse_packet(raw_pkt)
        if parsed:
            alerts = eng.process(parsed)
            for alert in alerts:
                amgr.add(alert)
                sw.write(alert)

    print(f"[+] Replayed {eng.packets_processed:,} packets → {amgr.total()} alerts")
    print(f"[+] Alerts written to {sw._path}")

    # Print alert summary
    print("\nAlert summary:")
    for sev, count in sorted(
        amgr.by_severity().items(),
        key=lambda x: {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}.get(x[0], 0),
        reverse=True,
    ):
        if count:
            print(f"  {sev:<10} {count}")

    print("\nRecent alerts:")
    for alert in amgr.recent(10):
        import time
        ts = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
        print(f"  [{ts}] [{alert.severity.value:<8}] {alert.title:<30}  {alert.description[:60]}")


# ── Async runtime ─────────────────────────────────────────────────────────────

async def _run_live(args: argparse.Namespace) -> None:
    """
    Full async runtime for live capture mode.

    Three producer/consumer stages connected by asyncio.Queues:

      sniffer thread ──→ packet_queue ──→ process_task ──→ alert_queue ──→ alert_task
                                                                            ↓
                                                                        dashboard_task
    """
    from nids.alerts.manager import AlertManager
    from nids.alerts.siem import SIEMWriter
    from nids.capture.parser import parse_packet
    from nids.capture.sniffer import PacketSniffer
    from nids.dashboard.ui import NIDSDashboard
    from nids.detection.engine import DetectionEngine

    engine    = DetectionEngine()
    alert_mgr = AlertManager()

    with SIEMWriter(args.siem) as siem:
        packet_queue: asyncio.Queue = asyncio.Queue(maxsize=20_000)
        alert_queue:  asyncio.Queue = asyncio.Queue(maxsize=2_000)
        loop = asyncio.get_running_loop()

        sniffer = PacketSniffer(
            interface  = args.interface,
            bpf_filter = args.filter,
            loop       = loop,
            queue      = packet_queue,
        )

        stop_event = asyncio.Event()

        # ── Graceful shutdown on SIGINT / SIGTERM ──────────────────────
        def _signal_handler() -> None:
            stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _signal_handler)
            except (NotImplementedError, RuntimeError):
                # Windows does not support add_signal_handler for all signals
                pass

        # ── Task: parse packets and run detection ──────────────────────
        async def process_packets() -> None:
            while not stop_event.is_set():
                try:
                    raw_pkt = await asyncio.wait_for(packet_queue.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    continue
                parsed = parse_packet(raw_pkt)
                if parsed:
                    alerts = engine.process(parsed)
                    for alert in alerts:
                        try:
                            alert_queue.put_nowait(alert)
                        except asyncio.QueueFull:
                            pass  # drop; dashboard still accurate
                packet_queue.task_done()

        # ── Task: persist alerts ───────────────────────────────────────
        async def handle_alerts() -> None:
            while not stop_event.is_set():
                try:
                    alert = await asyncio.wait_for(alert_queue.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    continue
                alert_mgr.add(alert)
                siem.write(alert)
                alert_queue.task_done()

        # ── Task: render dashboard ─────────────────────────────────────
        async def run_dashboard() -> None:
            dashboard = NIDSDashboard(
                engine    = engine,
                alert_mgr = alert_mgr,
                interface = args.interface or "all",
                siem_path = args.siem,
                sniffer   = sniffer,
            )
            # Wrap in stop_event check so it exits cleanly
            dashboard_task = asyncio.create_task(dashboard.run())
            await stop_event.wait()
            dashboard_task.cancel()
            try:
                await dashboard_task
            except asyncio.CancelledError:
                pass

        # ── Start capture and gather all tasks ────────────────────────
        try:
            sniffer.start()
        except RuntimeError as exc:
            print(f"[error] Failed to start capture: {exc}")
            print("[hint]  On Windows, install Npcap from https://npcap.com")
            print("[hint]  On Linux, run as root or: sudo setcap cap_net_raw+ep python3")
            sys.exit(1)

        tasks: list[asyncio.Task] = [
            asyncio.create_task(process_packets(), name="process"),
            asyncio.create_task(handle_alerts(),   name="alerts"),
        ]
        if not args.no_ui:
            tasks.append(asyncio.create_task(run_dashboard(), name="dashboard"))
        else:
            tasks.append(asyncio.create_task(
                stop_event.wait(), name="headless_stop"
            ))

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass
        finally:
            sniffer.stop()
            for t in tasks:
                t.cancel()

        # Print final summary when running headless
        if args.no_ui:
            print(
                f"\n[+] Captured {engine.packets_processed:,} packets  "
                f"| {alert_mgr.total()} alerts  "
                f"| {len(engine.active_hosts)} hosts"
            )


# ── Interactive startup menu ──────────────────────────────────────────────────

def _show_menu(args: argparse.Namespace) -> argparse.Namespace:
    """
    Full-screen startup menu shown when main.py is run with no arguments.

    Lets users choose live capture, PCAP analysis, or test-PCAP generation
    without needing to remember CLI flags — good for demos and first runs.
    """
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt

    console = Console()
    console.clear()

    # ── Banner ────────────────────────────────────────────────────────────
    console.print(Panel.fit(
        "[bold red]NETWORK INTRUSION DETECTION SYSTEM[/bold red]\n"
        "[dim]Statistical anomaly detection  ·  MITRE ATT&CK mapped alerts[/dim]\n"
        "[dim]Welford baselines  ·  Shannon entropy  ·  Sliding-window analysis[/dim]",
        border_style="red",
        padding=(1, 4),
    ))

    console.print()
    console.print("  [bold cyan][1][/bold cyan]  Live capture          "
                  "[dim](requires Npcap + run as Administrator)[/dim]")
    console.print("  [bold cyan][2][/bold cyan]  Analyze a PCAP file")
    console.print("  [bold cyan][3][/bold cyan]  Generate test PCAP and analyze  "
                  "[dim](no privileges needed — great for demos)[/dim]")
    console.print("  [bold cyan][4][/bold cyan]  List network interfaces")
    console.print("  [bold cyan][5][/bold cyan]  Exit")
    console.print()

    choice = Prompt.ask(
        "  [bold]Select[/bold]",
        choices=["1", "2", "3", "4", "5"],
        default="1",
    )

    if choice == "1":
        # Live capture — use args as-is (interface/filter may be set via flags)
        pass

    elif choice == "2":
        # Prompt for a PCAP file path
        path = Prompt.ask("  [bold]PCAP file path[/bold]")
        args.pcap = path.strip()

    elif choice == "3":
        # Generate a synthetic attack PCAP and replay it
        from tools.generate_test_pcap import generate
        out = "test_traffic.pcap"
        console.print(f"\n  [dim]Generating synthetic attack traffic → {out}[/dim]")
        generate(out)
        args.pcap = out

    elif choice == "4":
        _list_interfaces()

    elif choice == "5":
        sys.exit(0)

    console.print()
    return args


def _needs_menu(args: argparse.Namespace) -> bool:
    """
    Return True when no action flag was provided on the command line,
    i.e. the user just typed `python main.py` with nothing else.
    """
    explicit_flags = (
        args.pcap is not None
        or args.interface is not None
        or args.list_interfaces
        or args.no_ui
    )
    return not explicit_flags


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    args = _parse_args()

    if args.verbose:
        logging.getLogger("nids").setLevel(logging.DEBUG)

    # Show the interactive menu whenever the user runs `python main.py`
    # with no meaningful arguments — skip it when flags were provided explicitly.
    if _needs_menu(args):
        args = _show_menu(args)

    if args.list_interfaces:
        _list_interfaces()
        return

    if args.pcap:
        # ── PCAP replay mode (no elevated privileges required) ─────────────
        from nids.alerts.manager import AlertManager
        from nids.alerts.siem import SIEMWriter
        from nids.detection.engine import DetectionEngine

        engine    = DetectionEngine()
        alert_mgr = AlertManager()
        with SIEMWriter(args.siem) as siem:
            _replay_pcap(args.pcap, engine, alert_mgr, siem)
        return

    # ── Live capture mode ──────────────────────────────────────────────────
    try:
        asyncio.run(_run_live(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
