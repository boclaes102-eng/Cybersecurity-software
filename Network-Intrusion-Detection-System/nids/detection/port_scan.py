"""
Port scan and network sweep detector.

Detection model
---------------
For every source IP, two sliding-window sets (60 s) track:
  • unique (dst_ip, dst_port) contact tuples  → raw footprint
  • unique destination IPs                    → horizontal spread

Three scan archetypes are recognised:

  Vertical scan     — one target, many ports
                      Signature: unique_contacts high, unique_hosts low
                      Maps to: nmap -sS, -sV, mass service enumeration

  Horizontal sweep  — many targets, one or few ports
                      Signature: unique_hosts high, unique_ports low
                      Maps to: nmap -p 22 192.168.0.0/16, shodan-style sweep

  Distributed scan  — many targets AND many ports (full mesh)
                      Maps to: masscan, zmap

Additionally, we track raw SYN-only packets per source.  A SYN/contact
ratio near 1.0 means nearly every contact attempt resulted in no reply —
strong evidence of stealth scanning (RST or no response = closed/filtered).

MITRE ATT&CK: T1046 — Network Service Scanning (Discovery)
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Optional

from nids.capture.parser import ParsedPacket
from nids.detection.models import Alert, Severity
from nids.utils.stats import SlidingWindowCounter, SlidingWindowSet

# Thresholds — tunable without touching detection logic
_SCAN_WINDOW_S: float = 60.0       # observation window
_VERT_THRESHOLD: int  = 25         # unique ports → vertical scan
_HORIZ_THRESHOLD: int = 20         # unique hosts → horizontal sweep
_DIST_THRESHOLD: int  = 15         # both dimensions → distributed
_SUPPRESSION_S:  float = 30.0      # per-source cooldown after firing


class PortScanDetector:
    """
    Sliding-window port scan detector.

    Supports vertical, horizontal, and distributed scan patterns.
    Uses a per-source SlidingWindowSet for unique-contact counting —
    O(n) space per source, O(1) amortised per packet.
    """

    def __init__(self) -> None:
        # (src_ip) → set of (dst_ip, dst_port) tuples in the last 60 s
        self._contacts: dict[str, SlidingWindowSet] = defaultdict(
            lambda: SlidingWindowSet(_SCAN_WINDOW_S)
        )
        # (src_ip) → set of distinct destination IPs in the last 60 s
        self._dst_ips: dict[str, SlidingWindowSet] = defaultdict(
            lambda: SlidingWindowSet(_SCAN_WINDOW_S)
        )
        # (src_ip) → SYN-only packet count in the last 60 s
        self._syn_only: dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(_SCAN_WINDOW_S)
        )
        self._last_alert: dict[str, float] = {}

    # ------------------------------------------------------------------ #

    def process(self, pkt: ParsedPacket) -> list[Alert]:
        if pkt.protocol not in ("TCP", "UDP") or not pkt.src_ip:
            return []

        src = pkt.src_ip
        ts  = pkt.timestamp

        # Record contact
        if pkt.dst_ip and pkt.dst_port:
            self._contacts[src].add((pkt.dst_ip, pkt.dst_port), ts)
            self._dst_ips[src].add(pkt.dst_ip, ts)

        # Count SYN-only (stealth / half-open) packets
        if pkt.is_syn:
            self._syn_only[src].add(ts)

        if self._is_suppressed(src):
            return []

        unique_contacts = self._contacts[src].unique_count()
        unique_hosts    = self._dst_ips[src].unique_count()
        syn_count       = self._syn_only[src].count()

        # SYN ratio: high ratio → nearly all contacts are one-way probes
        syn_ratio = syn_count / max(unique_contacts, 1)

        alert = self._evaluate(src, unique_contacts, unique_hosts, syn_count, syn_ratio)
        if alert:
            self._suppress(src)
        return [alert] if alert else []

    def _evaluate(
        self,
        src: str,
        unique_contacts: int,
        unique_hosts: int,
        syn_count: int,
        syn_ratio: float,
    ) -> Optional[Alert]:

        # ── Distributed (large footprint in both dimensions) ──────────────
        if unique_contacts >= _DIST_THRESHOLD and unique_hosts >= _DIST_THRESHOLD:
            return Alert(
                severity=Severity.CRITICAL,
                title="Distributed Port Scan",
                description=(
                    f"{src} contacted {unique_hosts} hosts across "
                    f"{unique_contacts} (host, port) pairs in 60 s"
                ),
                detector="port_scan",
                mitre_key="port_scan",
                src_ip=src,
                evidence={
                    "scan_type":       "distributed",
                    "unique_contacts": unique_contacts,
                    "unique_hosts":    unique_hosts,
                    "syn_count":       syn_count,
                    "syn_ratio":       round(syn_ratio, 3),
                },
            )

        # ── Horizontal sweep (many hosts, same port) ──────────────────────
        if unique_hosts >= _HORIZ_THRESHOLD:
            sev = Severity.HIGH if unique_hosts >= 50 else Severity.MEDIUM
            return Alert(
                severity=sev,
                title="Network Sweep Detected",
                description=(
                    f"{src} swept {unique_hosts} unique hosts in 60 s "
                    f"(syn_ratio={syn_ratio:.0%})"
                ),
                detector="port_scan",
                mitre_key="port_scan",
                src_ip=src,
                evidence={
                    "scan_type":    "horizontal_sweep",
                    "unique_hosts": unique_hosts,
                    "syn_count":    syn_count,
                    "syn_ratio":    round(syn_ratio, 3),
                },
            )

        # ── Vertical scan (many ports on few hosts) ───────────────────────
        if unique_contacts >= _VERT_THRESHOLD and unique_hosts <= 5:
            sev = Severity.HIGH if unique_contacts >= 100 else Severity.MEDIUM
            return Alert(
                severity=sev,
                title="Port Scan Detected",
                description=(
                    f"{src} probed {unique_contacts} ports on "
                    f"{unique_hosts} host(s) in 60 s"
                ),
                detector="port_scan",
                mitre_key="port_scan",
                src_ip=src,
                evidence={
                    "scan_type":       "vertical_scan",
                    "unique_contacts": unique_contacts,
                    "unique_hosts":    unique_hosts,
                    "syn_count":       syn_count,
                    "syn_ratio":       round(syn_ratio, 3),
                    "stealth":         syn_ratio > 0.85,
                },
            )

        return None

    def _suppress(self, src: str) -> None:
        self._last_alert[src] = time.time()

    def _is_suppressed(self, src: str) -> bool:
        return (time.time() - self._last_alert.get(src, 0.0)) < _SUPPRESSION_S
