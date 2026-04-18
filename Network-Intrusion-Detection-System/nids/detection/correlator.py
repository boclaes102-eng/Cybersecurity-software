"""
Alert correlator — detects multi-detector attack patterns from the same source.

After each packet is processed by the individual detectors, the engine passes
all resulting alerts through this correlator.  It maintains a short per-source
history and fires a synthetic combined alert when it recognises a known
multi-stage attack pattern within the correlation window.

Firing rules
------------
Each rule fires at most once per source per session (tracked in
_correlated_keys) to avoid alert storms from sustained attacks.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field

from .models import Alert, Severity

WINDOW: float = 60.0  # seconds — detectors must fire within this window

# (frozenset of detector names, severity, title, description)
_PATTERNS: list[tuple[frozenset[str], Severity, str, str]] = [
    (
        frozenset({"port_scan", "syn_flood"}),
        Severity.CRITICAL,
        "Coordinated Network Attack",
        "Simultaneous port scan and SYN flood from the same source — likely an "
        "automated attack tool performing both reconnaissance and disruption.",
    ),
    (
        frozenset({"port_scan", "dns_tunnel"}),
        Severity.HIGH,
        "Reconnaissance + C2 Channel",
        "Port scanning followed by DNS tunnelling from the same host — possible "
        "C2 beaconing after initial network recon.",
    ),
    (
        frozenset({"arp_spoof", "syn_flood"}),
        Severity.CRITICAL,
        "MITM + Flood Attack",
        "ARP cache poisoning combined with SYN flooding — attacker is likely "
        "intercepting traffic while simultaneously disrupting target services.",
    ),
    (
        frozenset({"arp_spoof", "dns_tunnel"}),
        Severity.HIGH,
        "MITM + DNS Exfiltration",
        "ARP spoofing combined with DNS tunnelling — possible man-in-the-middle "
        "position being used to exfiltrate data via DNS.",
    ),
    (
        frozenset({"port_scan", "syn_flood", "dns_tunnel"}),
        Severity.CRITICAL,
        "Full-Spectrum Attack",
        "Port scanning, SYN flooding, and DNS tunnelling all detected from the "
        "same source — highly organised multi-stage intrusion.",
    ),
]

_MULTI_VECTOR_THRESHOLD = 3  # fire if >= this many distinct detectors trigger


@dataclass
class _SourceRecord:
    detectors: dict[str, float] = field(default_factory=dict)  # name → last_seen
    fired_keys: set[str] = field(default_factory=set)          # pattern keys already fired


class CorrelationEngine:
    """
    Stateful cross-detector correlation.  Feed each packet's alert list in;
    get back any new combined alerts that should also be raised.
    """

    def __init__(self) -> None:
        self._records: dict[str, _SourceRecord] = defaultdict(_SourceRecord)

    def check(self, alerts: list[Alert]) -> list[Alert]:
        """
        Given alerts produced for one packet, return additional correlation
        alerts (may be empty).  Call this after the main detector pipeline.
        """
        if not alerts:
            return []

        now = time.time()
        corr_alerts: list[Alert] = []

        # Group by source IP — skip alerts with no source
        by_src: dict[str, list[Alert]] = defaultdict(list)
        for a in alerts:
            if a.src_ip:
                by_src[a.src_ip].append(a)

        for src_ip, src_alerts in by_src.items():
            rec = self._records[src_ip]

            # Expire entries outside the window
            rec.detectors = {
                det: ts for det, ts in rec.detectors.items()
                if now - ts <= WINDOW
            }

            # Record this batch
            for a in src_alerts:
                rec.detectors[a.detector] = now

            active = frozenset(rec.detectors)

            # Check named patterns
            for pattern_set, severity, title, description in _PATTERNS:
                key = "|".join(sorted(pattern_set))
                if pattern_set <= active and key not in rec.fired_keys:
                    rec.fired_keys.add(key)
                    corr_alerts.append(Alert(
                        severity=severity,
                        title=title,
                        description=description,
                        detector="correlator",
                        mitre_key="correlator",
                        src_ip=src_ip,
                        evidence={
                            "triggered_by": sorted(pattern_set),
                            "window_seconds": WINDOW,
                        },
                    ))

            # Generic multi-vector catch-all
            multi_key = f"multi_vector_{len(active)}"
            if len(active) >= _MULTI_VECTOR_THRESHOLD and multi_key not in rec.fired_keys:
                rec.fired_keys.add(multi_key)
                corr_alerts.append(Alert(
                    severity=Severity.CRITICAL,
                    title="Multi-Vector Attack",
                    description=(
                        f"{len(active)} distinct attack types detected from {src_ip} "
                        f"within {WINDOW:.0f}s: {', '.join(sorted(active))}."
                    ),
                    detector="correlator",
                    mitre_key="correlator",
                    src_ip=src_ip,
                    evidence={
                        "triggered_by": sorted(active),
                        "detector_count": len(active),
                        "window_seconds": WINDOW,
                    },
                ))

        return corr_alerts
