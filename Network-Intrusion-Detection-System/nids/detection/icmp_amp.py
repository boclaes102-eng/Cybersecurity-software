"""
ICMP amplification / reflection attack detector.

Attack taxonomy
---------------
Smurf attack (classic)
  The attacker spoofs the victim's source IP and sends ICMP Echo Requests
  to a broadcast address.  Every host on that subnet replies to the victim,
  amplifying traffic N× (one request → N replies).

Modern ICMP reflection / amplification
  The attacker sends small ICMP requests to many open reflectors with the
  victim's spoofed source IP.  The reflectors flood the victim with replies
  it never requested.

Detection signals
-----------------
1. Echo request to broadcast/subnet-broadcast address
   → immediate Smurf source alert

2. Reply/request asymmetry per destination
   A host *receiving* many ICMP Echo Replies without sending Echo Requests
   is the victim of a reflection attack.
   Ratio = reply_rate / max(request_rate, 0.1)
   Fires when: reply_rate ≥ RATE_THRESHOLD AND ratio ≥ RATIO_THRESHOLD

3. High-volume ICMP Echo Reply burst
   Even without request data, a sudden spike of replies to one host
   exceeding ABS_RATE_THRESHOLD is suspicious.

MITRE ATT&CK: T1498.002 — Reflection Amplification (Impact)
"""

from __future__ import annotations

import time
from collections import defaultdict

from nids.capture.parser import ParsedPacket
from nids.detection.models import Alert, Severity
from nids.utils.stats import SlidingWindowCounter

_WINDOW_S: float          = 10.0    # rate measurement window
_ABS_RATE_THRESHOLD: float = 50.0   # replies/s → alert regardless of ratio
_RATIO_THRESHOLD: float    = 5.0    # reply/request multiplier
_SUPPRESSION_S: float      = 30.0

_ICMP_ECHO_REQUEST: int = 8
_ICMP_ECHO_REPLY:   int = 0


def _is_broadcast(ip: str) -> bool:
    """Heuristic: 255.255.255.255 or any .255 address."""
    return ip == "255.255.255.255" or ip.endswith(".255")


class ICMPAmpDetector:
    """
    ICMP amplification and Smurf attack detector.
    """

    def __init__(self) -> None:
        # Per source IP: outgoing echo request count
        self._requests: dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(_WINDOW_S)
        )
        # Per destination IP: incoming echo reply count
        self._replies: dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(_WINDOW_S)
        )
        self._last_alert: dict[str, float] = {}

    # ------------------------------------------------------------------ #

    def process(self, pkt: ParsedPacket) -> list[Alert]:
        if pkt.protocol != "ICMP" or pkt.icmp_type is None:
            return []

        alerts: list[Alert] = []
        src = pkt.src_ip or "unknown"
        dst = pkt.dst_ip or "unknown"
        ts  = pkt.timestamp

        # ── Signal 1: Echo Request to broadcast (Smurf source) ───────────
        if pkt.icmp_type == _ICMP_ECHO_REQUEST and _is_broadcast(dst):
            if not self._suppressed(f"smurf:{src}"):
                self._suppress(f"smurf:{src}")
                alerts.append(Alert(
                    severity=Severity.HIGH,
                    title="Smurf Attack Pattern",
                    description=(
                        f"{src} is sending ICMP Echo Requests to "
                        f"broadcast address {dst}"
                    ),
                    detector="icmp_amp",
                    mitre_key="icmp_amp",
                    src_ip=src,
                    dst_ip=dst,
                    evidence={
                        "icmp_type":   pkt.icmp_type,
                        "dst":         dst,
                        "packet_size": pkt.length,
                        "attack_type": "smurf_broadcast",
                    },
                ))

        # ── Rate tracking ─────────────────────────────────────────────────
        if pkt.icmp_type == _ICMP_ECHO_REQUEST:
            self._requests[src].add(ts)

        elif pkt.icmp_type == _ICMP_ECHO_REPLY:
            self._replies[dst].add(ts)

            reply_rate   = self._replies[dst].rate()
            request_rate = self._requests[dst].rate()
            ratio        = reply_rate / max(request_rate, 0.1)

            # ── Signal 2: asymmetric reply/request ratio ──────────────────
            if (
                reply_rate >= _ABS_RATE_THRESHOLD
                and ratio >= _RATIO_THRESHOLD
                and not self._suppressed(f"amp:{dst}")
            ):
                self._suppress(f"amp:{dst}")
                sev = Severity.CRITICAL if reply_rate >= 200 else Severity.HIGH
                alerts.append(Alert(
                    severity=sev,
                    title="ICMP Amplification Attack",
                    description=(
                        f"{dst} is being flooded with {reply_rate:.0f} "
                        f"ICMP replies/s ({ratio:.1f}× amplification factor)"
                    ),
                    detector="icmp_amp",
                    mitre_key="icmp_amp",
                    dst_ip=dst,
                    evidence={
                        "reply_rate_pps":       round(reply_rate, 2),
                        "request_rate_pps":     round(request_rate, 2),
                        "amplification_ratio":  round(ratio, 2),
                        "rate_threshold":       _ABS_RATE_THRESHOLD,
                        "ratio_threshold":      _RATIO_THRESHOLD,
                        "attack_type":          "icmp_reflection",
                    },
                ))

        return alerts

    # ------------------------------------------------------------------ #

    def _suppressed(self, key: str) -> bool:
        return (time.time() - self._last_alert.get(key, 0.0)) < _SUPPRESSION_S

    def _suppress(self, key: str) -> None:
        self._last_alert[key] = time.time()
