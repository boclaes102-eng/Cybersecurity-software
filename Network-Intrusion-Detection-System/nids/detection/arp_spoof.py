"""
ARP cache poisoning (ARP spoofing) detector.

How ARP spoofing works
----------------------
The Address Resolution Protocol has no authentication.  An attacker
can broadcast gratuitous ARP replies claiming ownership of any IP,
overwriting the ARP cache of all hosts on the segment.  This enables
man-in-the-middle attacks, silent traffic interception, and DoS.

Detection strategy
------------------
1. IP → MAC binding table
   We learn the first authoritative binding for each IP.  Any subsequent
   packet where the same IP is claimed by a *different* MAC triggers a
   CRITICAL alert — the binding has been poisoned.

2. Gratuitous ARP flood
   Legitimate hosts rarely broadcast ARP replies.  A source sending
   more than GARP_RATE_THRESHOLD replies in GARP_WINDOW_S seconds is
   running an ARP poisoning campaign.

3. MAC claiming multiple IPs
   One MAC address appearing as sender for many different IPs is
   indicative of an active MITM tool (e.g. arpspoof, bettercap).

MITRE ATT&CK: T1557.002 — ARP Cache Poisoning (Credential Access)
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass

from nids.capture.parser import ParsedPacket
from nids.detection.models import Alert, Severity
from nids.utils.stats import SlidingWindowCounter

_GARP_WINDOW_S: float      = 30.0   # gratuitous ARP rate window
_GARP_THRESHOLD: int       = 10     # replies per window → flood
_MULTI_IP_THRESHOLD: int   = 5      # IPs per MAC → suspicious
_SUPPRESSION_S: float      = 30.0

_BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
_ZERO_MAC      = "00:00:00:00:00:00"


@dataclass
class BindingRecord:
    mac:        str
    first_seen: float
    last_seen:  float
    update_count: int = 0


class ARPSpoofDetector:
    """
    ARP cache poisoning detector with binding table and flood detection.
    """

    def __init__(self) -> None:
        # ip → BindingRecord (first learned MAC wins)
        self._bindings: dict[str, BindingRecord] = {}

        # mac → set of claimed IPs (multi-IP spoofing detection)
        self._mac_to_ips: dict[str, set[str]] = defaultdict(set)

        # mac → ARP reply counter (flood detection)
        self._reply_rates: dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(_GARP_WINDOW_S)
        )

        self._last_alert: dict[str, float] = {}

    # ------------------------------------------------------------------ #

    def process(self, pkt: ParsedPacket) -> list[Alert]:
        if pkt.protocol != "ARP":
            return []

        src_ip  = pkt.arp_psrc
        src_mac = (pkt.arp_hwsrc or "").lower()

        if not src_ip or not src_mac:
            return []

        # Ignore broadcast/null MACs (they are not real senders)
        if src_mac in (_BROADCAST_MAC, _ZERO_MAC):
            return []

        alerts: list[Alert] = []

        # ── Signal 1: IP–MAC binding conflict ────────────────────────────
        if src_ip in self._bindings:
            rec = self._bindings[src_ip]
            if rec.mac != src_mac:
                # Binding changed — poisoning attempt
                rec.update_count += 1
                rec.last_seen = time.time()
                if not self._suppressed(f"conflict:{src_ip}"):
                    self._suppress(f"conflict:{src_ip}")
                    alerts.append(Alert(
                        severity=Severity.CRITICAL,
                        title="ARP Cache Poisoning",
                        description=(
                            f"IP {src_ip} MAC changed: "
                            f"{rec.mac} → {src_mac}  "
                            f"(binding updated {rec.update_count}x)"
                        ),
                        detector="arp_spoof",
                        mitre_key="arp_spoof",
                        src_ip=src_ip,
                        evidence={
                            "target_ip":           src_ip,
                            "original_mac":        rec.mac,
                            "new_mac":             src_mac,
                            "arp_op":              pkt.arp_op,
                            "binding_age_s":       round(time.time() - rec.first_seen, 1),
                            "conflict_count":      rec.update_count,
                        },
                    ))
                # Update binding to track latest claimant
                rec.mac = src_mac
        else:
            self._bindings[src_ip] = BindingRecord(
                mac=src_mac,
                first_seen=time.time(),
                last_seen=time.time(),
            )

        # ── Signal 2: gratuitous ARP reply flood ─────────────────────────
        if pkt.arp_op == 2:   # ARP reply
            self._reply_rates[src_mac].add(pkt.timestamp)
            count = self._reply_rates[src_mac].count()

            if count >= _GARP_THRESHOLD and not self._suppressed(f"garp:{src_mac}"):
                self._suppress(f"garp:{src_mac}")
                alerts.append(Alert(
                    severity=Severity.HIGH,
                    title="Gratuitous ARP Flood",
                    description=(
                        f"MAC {src_mac} sent {count} unsolicited ARP replies "
                        f"in {_GARP_WINDOW_S:.0f} s — active poisoning campaign"
                    ),
                    detector="arp_spoof",
                    mitre_key="arp_spoof",
                    src_ip=src_ip,
                    evidence={
                        "src_mac":           src_mac,
                        "src_ip":            src_ip,
                        "reply_count":       count,
                        "window_seconds":    _GARP_WINDOW_S,
                        "threshold":         _GARP_THRESHOLD,
                    },
                ))

        # ── Signal 3: one MAC claiming many IPs ──────────────────────────
        self._mac_to_ips[src_mac].add(src_ip)
        ip_count = len(self._mac_to_ips[src_mac])

        if ip_count >= _MULTI_IP_THRESHOLD and not self._suppressed(f"multi:{src_mac}"):
            self._suppress(f"multi:{src_mac}")
            alerts.append(Alert(
                severity=Severity.HIGH,
                title="MAC Claiming Multiple IPs",
                description=(
                    f"MAC {src_mac} has claimed {ip_count} distinct IP addresses "
                    "(indicative of ARP spoofing tool)"
                ),
                detector="arp_spoof",
                mitre_key="arp_spoof",
                src_ip=src_ip,
                evidence={
                    "src_mac":     src_mac,
                    "ip_count":    ip_count,
                    "claimed_ips": sorted(self._mac_to_ips[src_mac]),
                    "threshold":   _MULTI_IP_THRESHOLD,
                },
            ))

        return alerts

    # ------------------------------------------------------------------ #

    @property
    def binding_table(self) -> dict[str, BindingRecord]:
        """Snapshot of the current IP → MAC table (for dashboard display)."""
        return dict(self._bindings)

    def _suppressed(self, key: str) -> bool:
        return (time.time() - self._last_alert.get(key, 0.0)) < _SUPPRESSION_S

    def _suppress(self, key: str) -> None:
        self._last_alert[key] = time.time()
