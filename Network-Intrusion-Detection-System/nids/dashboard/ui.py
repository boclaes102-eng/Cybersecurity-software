"""
Rich live terminal dashboard.

Layout (full-screen)
--------------------
┌─────────────────────────────────────────────────────────────────────┐
│  NIDS vX.X  |  Interface: eth0  |  Uptime  |  Packets  |  Alerts  │
│  [CRITICAL: 0]  [HIGH: 0]  [MEDIUM: 0]  [LOW: 0]                  │
├──────────────────────────────────┬──────────────────────────────────┤
│                                  │  HOST BASELINES (top 10)        │
│        LIVE ALERTS               │  IP  Pkts  Rate  Base  Protos   │
│  Time  Sev  Det  Title  Source   │  ...                            │
│  ...                             ├─────────────────────────────────┤
│                                  │  PROTOCOL DISTRIBUTION          │
│                                  │  TCP  ███████████  67%          │
│                                  │  UDP  ████████     23%          │
│                                  │  DNS  ████         8%           │
├──────────────────────────────────┴──────────────────────────────────┤
│  [q] Quit   MITRE ATT&CK mapped   SIEM → alerts.ndjson             │
└─────────────────────────────────────────────────────────────────────┘

Rendering is driven by a single async loop that calls build_renderable()
every 0.5 seconds and hands the result to rich.live.Live.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from nids.alerts.manager import AlertManager
    from nids.capture.sniffer import PacketSniffer
    from nids.detection.engine import DetectionEngine
    from nids.detection.models import Alert

_PROTO_COLORS: dict[str, str] = {
    "TCP":   "blue",
    "UDP":   "green",
    "DNS":   "cyan",
    "ICMP":  "yellow",
    "ARP":   "magenta",
    "OTHER": "dim",
}


class NIDSDashboard:
    """
    Full-screen Rich Live dashboard for the NIDS.

    Parameters
    ----------
    engine      : DetectionEngine — source of global traffic stats
    alert_mgr   : AlertManager   — source of recent alerts
    sniffer     : PacketSniffer  — source of capture stats (optional)
    interface   : str            — interface name displayed in header
    siem_path   : str            — SIEM output path displayed in footer
    """

    REFRESH_HZ: float = 2.0

    def __init__(
        self,
        engine: "DetectionEngine",
        alert_mgr: "AlertManager",
        interface: str = "all",
        siem_path: str = "alerts.ndjson",
        sniffer: object = None,
    ) -> None:
        self._engine    = engine
        self._alert_mgr = alert_mgr
        self._interface = interface
        self._siem_path = siem_path
        self._sniffer   = sniffer
        self._started   = time.time()
        self._console   = Console()

    # ── Layout builders ───────────────────────────────────────────────

    def _make_layout(self) -> Layout:
        layout = Layout(name="root")
        layout.split_column(
            Layout(name="header",  size=4),
            Layout(name="body"),
            Layout(name="footer",  size=3),
        )
        layout["body"].split_row(
            Layout(name="alerts", ratio=3),
            Layout(name="right",  ratio=2),
        )
        layout["right"].split_column(
            Layout(name="hosts",     ratio=3),
            Layout(name="protocols", ratio=2),
        )
        return layout

    # ── Individual panels ──────────────────────────────────────────────

    def _render_header(self) -> Panel:
        elapsed = int(time.time() - self._started)
        h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60

        eng   = self._engine
        amgr  = self._alert_mgr
        sev   = amgr.by_severity()

        # Capture stats (if sniffer is available)
        captured = getattr(getattr(self._sniffer, "stats", None), "received", eng.packets_processed)
        dropped  = getattr(getattr(self._sniffer, "stats", None), "dropped", 0)

        t = Text(justify="left")
        t.append("  NIDS  ", style="bold white on dark_red")
        t.append(f"  Interface: {self._interface}", style="bold cyan")
        t.append(f"  Uptime: {h:02d}:{m:02d}:{s:02d}", style="green")
        t.append(f"  Captured: {captured:,}", style="white")
        if dropped:
            t.append(f"  Dropped: {dropped:,}", style="yellow")
        t.append(f"  Hosts: {len(eng.active_hosts)}", style="cyan")
        t.append(f"  Total alerts: {amgr.total()}", style="red" if amgr.total() else "dim")
        t.append("\n  ")

        severity_badges = {
            "CRITICAL": ("bold white on red",  "■"),
            "HIGH":     ("red",                "■"),
            "MEDIUM":   ("yellow",             "■"),
            "LOW":      ("cyan",               "■"),
            "INFO":     ("dim",                "·"),
        }
        for sev_name, (style, glyph) in severity_badges.items():
            count = sev.get(sev_name, 0)
            t.append(f" {glyph} {sev_name}: {count} ", style=style if count else "dim")

        return Panel(t, border_style="red", padding=(0, 1))

    def _render_alerts(self) -> Panel:
        alerts = self._alert_mgr.recent(18)

        if not alerts:
            content = Text(
                "\n  No alerts yet — monitoring network traffic …",
                style="dim",
                justify="center",
            )
            return Panel(
                content,
                title="[bold]Live Alerts[/bold]",
                border_style="green",
            )

        tbl = Table(
            show_header=True,
            header_style="bold dim",
            box=box.MINIMAL_HEAVY_HEAD,
            expand=True,
            padding=(0, 1),
        )
        tbl.add_column("Time",     width=8,  no_wrap=True)
        tbl.add_column("Severity", width=9,  no_wrap=True)
        tbl.add_column("Detector", width=11, no_wrap=True)
        tbl.add_column("Title",    width=24, no_wrap=True)
        tbl.add_column("Source",   width=15, no_wrap=True)
        tbl.add_column("Details")

        for alert in alerts:
            ts_str = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))

            sev_text = Text(f"[{alert.severity.value[:4]}]", style=alert.severity.color)

            desc = alert.description
            if len(desc) > 65:
                desc = desc[:62] + "…"

            tbl.add_row(
                ts_str,
                sev_text,
                alert.detector,
                Text(alert.title, style="bold"),
                alert.src_ip or "—",
                Text(desc, style="dim"),
            )

        total = self._alert_mgr.total()
        return Panel(
            tbl,
            title=f"[bold]Live Alerts[/bold]  [{total} total]",
            border_style="red" if total else "green",
        )

    def _render_hosts(self) -> Panel:
        hosts = sorted(
            self._engine.active_hosts.values(),
            key=lambda h: h.total_packets,
            reverse=True,
        )[:10]

        tbl = Table(
            show_header=True,
            header_style="bold dim",
            box=box.MINIMAL,
            expand=True,
            padding=(0, 1),
        )
        tbl.add_column("Host IP",   width=16)
        tbl.add_column("Packets",   width=7,  justify="right")
        tbl.add_column("Rate/s",    width=7,  justify="right")
        tbl.add_column("Baseline",  width=8,  justify="right")
        tbl.add_column("σ",         width=5,  justify="right")
        tbl.add_column("Protos",    ratio=1)

        for host in hosts:
            rate     = host.current_rate
            baseline = host.pkt_rate_stats.mean
            z        = host.pkt_rate_stats.z_score(rate)

            if abs(z) > 4.0:
                rate_style = "bold red"
            elif abs(z) > 2.5:
                rate_style = "yellow"
            else:
                rate_style = "green"

            proto_parts = sorted(
                host.protocol_counts.items(), key=lambda x: -x[1]
            )[:3]
            proto_str = " ".join(
                f"[{_PROTO_COLORS.get(k, 'white')}]{k}[/]:{v}"
                for k, v in proto_parts
            )

            tbl.add_row(
                host.ip,
                f"{host.total_packets:,}",
                Text(f"{rate:.1f}", style=rate_style),
                f"{baseline:.1f}",
                Text(f"{z:+.1f}", style=rate_style),
                Text.from_markup(proto_str or "—"),
            )

        if not hosts:
            return Panel("[dim]No hosts observed yet[/dim]", title="[bold]Host Baselines[/bold]")

        return Panel(tbl, title="[bold]Host Baselines[/bold]", border_style="blue")

    def _render_protocols(self) -> Panel:
        counts = dict(self._engine.protocol_counts)
        total  = max(sum(counts.values()), 1)

        tbl = Table(
            show_header=False,
            box=None,
            expand=True,
            padding=(0, 1),
        )
        tbl.add_column("Proto",  width=6)
        tbl.add_column("Bar",    ratio=1)
        tbl.add_column("Pct",    width=5,  justify="right")
        tbl.add_column("Count",  width=9,  justify="right")

        for proto, count in sorted(counts.items(), key=lambda x: -x[1]):
            pct     = count / total
            filled  = int(pct * 28)
            color   = _PROTO_COLORS.get(proto, "white")
            bar     = Text("█" * filled + "░" * (28 - filled), style=color)
            tbl.add_row(
                Text(proto, style=f"bold {color}"),
                bar,
                f"{pct:.0%}",
                f"{count:,}",
            )

        if not counts:
            return Panel("[dim]Awaiting traffic…[/dim]", title="[bold]Protocol Distribution[/bold]")

        return Panel(tbl, title="[bold]Protocol Distribution[/bold]", border_style="cyan")

    def _render_footer(self) -> Panel:
        detector_counts = self._alert_mgr.by_detector()
        det_text = "  ".join(
            f"{k}:{v}" for k, v in sorted(detector_counts.items(), key=lambda x: -x[1]) if v
        )
        t = Text()
        t.append(" [q] Quit  ", style="dim")
        t.append("MITRE ATT&CK mapped  ", style="bold green")
        t.append(f"SIEM → {self._siem_path}", style="cyan")
        if det_text:
            t.append(f"  │  {det_text}", style="dim")
        return Panel(t, border_style="dim", padding=(0, 1))

    # ── Main entry point ───────────────────────────────────────────────

    def build_renderable(self) -> Layout:
        layout = self._make_layout()
        layout["header"].update(self._render_header())
        layout["alerts"].update(self._render_alerts())
        layout["hosts"].update(self._render_hosts())
        layout["protocols"].update(self._render_protocols())
        layout["footer"].update(self._render_footer())
        return layout

    async def run(self) -> None:
        """
        Async render loop — refreshes the display every 0.5 s.
        Designed to run concurrently alongside capture and processing tasks.
        """
        with Live(
            self.build_renderable(),
            console=self._console,
            refresh_per_second=self.REFRESH_HZ,
            screen=True,
        ) as live:
            while True:
                live.update(self.build_renderable())
                await asyncio.sleep(1.0 / self.REFRESH_HZ)
