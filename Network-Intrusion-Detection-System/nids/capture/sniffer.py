"""
Async-safe Scapy packet capture.

Architecture
------------
Scapy's AsyncSniffer runs in a background thread.  Its `prn` callback
uses `loop.call_soon_threadsafe` to hand each raw Scapy packet over to
the asyncio event loop via an asyncio.Queue.  The consumer side
(process_packets in main.py) awaits packets without ever blocking the loop.

Windows note: requires Npcap ≥ 1.71 (https://npcap.com).
Linux note:   requires CAP_NET_RAW (run as root or `setcap`).
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from scapy.sendrecv import AsyncSniffer  # type: ignore
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False
    logger.warning("Scapy not available — packet capture disabled.")


@dataclass
class CaptureStats:
    """Running counters maintained by the sniffer thread."""
    received:  int   = 0
    dropped:   int   = 0   # queue overflow drops (not kernel drops)
    start_time: float = field(default_factory=time.time)

    @property
    def uptime(self) -> float:
        return time.time() - self.start_time


class PacketSniffer:
    """
    Thread-safe bridge between Scapy's blocking capture loop and asyncio.

    Parameters
    ----------
    interface:
        Network interface name (e.g. "eth0", "\\Device\\NPF_{...}" on Windows).
        Pass None to sniff on all interfaces.
    bpf_filter:
        Berkeley Packet Filter expression applied in-kernel for efficiency.
        Default captures TCP, UDP, ICMP, and ARP — skipping spanning-tree
        and other irrelevant layer-2 chatter.
    loop:
        The running asyncio event loop.  Must be passed explicitly so the
        sniffer thread can schedule coroutines safely.
    queue:
        Destination asyncio.Queue for raw Scapy packets.
    """

    DEFAULT_BPF = "tcp or udp or icmp or arp"

    def __init__(
        self,
        interface: Optional[str],
        bpf_filter: str,
        loop: asyncio.AbstractEventLoop,
        queue: "asyncio.Queue[object]",
    ) -> None:
        self._iface  = interface
        self._filter = bpf_filter or self.DEFAULT_BPF
        self._loop   = loop
        self._queue  = queue
        self.stats   = CaptureStats()
        self._sniffer: Optional[object] = None

    # ------------------------------------------------------------------ #

    def _on_packet(self, pkt: object) -> None:
        """
        Called from the sniffer thread for every captured frame.

        call_soon_threadsafe is the only safe way to enqueue work onto
        an asyncio loop from a foreign thread — it wakes the selector
        and schedules the callback without any lock contention.
        """
        self.stats.received += 1
        try:
            self._loop.call_soon_threadsafe(self._queue.put_nowait, pkt)
        except asyncio.QueueFull:
            # Back-pressure: drop rather than block the capture thread
            self.stats.dropped += 1

    def start(self) -> None:
        if not _SCAPY_OK:
            raise RuntimeError(
                "Scapy is not installed.  Run: pip install scapy"
            )
        kwargs: dict = dict(
            filter=self._filter,
            prn=self._on_packet,
            store=False,           # never buffer packets in memory
        )
        if self._iface:
            kwargs["iface"] = self._iface

        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()  # type: ignore[union-attr]
        logger.info(
            "Capture started — interface=%s  filter=%r",
            self._iface or "all",
            self._filter,
        )

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()  # type: ignore[union-attr]
            except Exception:
                pass
        logger.info(
            "Capture stopped — %d packets received, %d dropped",
            self.stats.received,
            self.stats.dropped,
        )
