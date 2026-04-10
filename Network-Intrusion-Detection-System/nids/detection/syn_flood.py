"""
SYN flood / TCP state exhaustion detector.

Detection strategy
------------------
A SYN flood exploits the three-way handshake: the attacker sends a
stream of SYN packets but never completes the handshake, exhausting
the server's half-open connection table (SYN backlog).

We track two complementary signals per destination IP:

1. Absolute SYN rate (packets/second over a 10-second window)
   — catches volumetric floods immediately.

2. SYN : SYN-ACK ratio in the same window
   — a healthy server completing handshakes has ratio ≈ 1 : 1.
   — a server under flood sees many SYNs but few SYN-ACKs.
   — detecting via ratio handles distributed floods where no single
     source exceeds rate limits.

Baseline learning
-----------------
After WARMUP_SAMPLES rate samples, we also compute a z-score against
the per-destination historical baseline.  This fires on abnormal but
sub-threshold surges (e.g. an internal service being hit unusually hard).

MITRE ATT&CK: T1498.001 — Direct Network Flood (Impact)
"""

from __future__ import annotations

import time
from collections import defaultdict

from nids.capture.parser import ParsedPacket
from nids.detection.models import Alert, Severity
from nids.utils.stats import EWMA, SlidingWindowCounter, WelfordAccumulator

_WINDOW_S: float            = 10.0    # rate measurement window
_WARMUP_SAMPLES: int        = 20      # before baseline kicks in
_ABS_RATE_HIGH: float       = 100.0   # SYN/s → HIGH
_ABS_RATE_CRITICAL: float   = 500.0   # SYN/s → CRITICAL
_RATIO_THRESHOLD: float     = 0.85    # SYN/(SYN+SYN-ACK)
_Z_THRESHOLD: float         = 4.0     # statistical anomaly z-score
_SAMPLE_INTERVAL_S: float   = 1.0     # rate sampling cadence
_SUPPRESSION_S: float       = 30.0    # per-destination cooldown


class SYNFloodDetector:
    """
    Per-destination SYN flood detector combining absolute rate
    thresholds with statistical baseline comparison.
    """

    def __init__(self) -> None:
        self._syn_counts:    dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(_WINDOW_S)
        )
        self._synack_counts: dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(_WINDOW_S)
        )
        # Smoothed SYN rate for baseline comparisons
        self._ewma:     dict[str, EWMA]               = defaultdict(lambda: EWMA(alpha=0.3))
        self._baseline: dict[str, WelfordAccumulator] = defaultdict(WelfordAccumulator)

        self._last_sample: dict[str, float] = defaultdict(float)
        self._last_alert:  dict[str, float] = {}

    # ------------------------------------------------------------------ #

    def process(self, pkt: ParsedPacket) -> list[Alert]:
        if pkt.protocol != "TCP" or not pkt.dst_ip:
            return []

        dst = pkt.dst_ip
        ts  = pkt.timestamp

        if pkt.is_syn:
            self._syn_counts[dst].add(ts)
        elif pkt.is_syn_ack:
            self._synack_counts[dst].add(ts)
        else:
            return []

        # Rate sampling — avoid noisy per-packet evaluation
        if ts - self._last_sample[dst] < _SAMPLE_INTERVAL_S:
            return []
        self._last_sample[dst] = ts

        syn_rate    = self._syn_counts[dst].rate()
        synack_rate = self._synack_counts[dst].rate()

        # Update EWMA and baseline
        smoothed = self._ewma[dst].update(syn_rate)
        self._baseline[dst].update(smoothed)

        if self._is_suppressed(dst):
            return []

        total = syn_rate + synack_rate
        ratio = syn_rate / total if total > 0.0 else 0.0
        z     = self._baseline[dst].z_score(smoothed)
        warmed = self._baseline[dst].n >= _WARMUP_SAMPLES

        # ── Absolute rate threshold ────────────────────────────────────────
        if syn_rate >= _ABS_RATE_HIGH:
            sev = Severity.CRITICAL if syn_rate >= _ABS_RATE_CRITICAL else Severity.HIGH
            self._suppress(dst)
            return [self._make_alert(dst, sev, syn_rate, synack_rate, ratio, z)]

        # ── Statistical anomaly + high incomplete ratio ────────────────────
        if warmed and z > _Z_THRESHOLD and ratio > _RATIO_THRESHOLD:
            self._suppress(dst)
            return [self._make_alert(dst, Severity.HIGH, syn_rate, synack_rate, ratio, z)]

        return []

    # ------------------------------------------------------------------ #

    def _make_alert(
        self,
        dst: str,
        severity: Severity,
        syn_rate: float,
        synack_rate: float,
        ratio: float,
        z: float,
    ) -> Alert:
        return Alert(
            severity=severity,
            title="SYN Flood Attack",
            description=(
                f"Destination {dst} receiving {syn_rate:.0f} SYN/s "
                f"({ratio:.0%} of TCP handshakes never completed)"
            ),
            detector="syn_flood",
            mitre_key="syn_flood",
            dst_ip=dst,
            evidence={
                "syn_rate_pps":      round(syn_rate, 2),
                "synack_rate_pps":   round(synack_rate, 2),
                "incomplete_ratio":  round(ratio, 3),
                "z_score":           round(z, 2),
                "baseline_mean_pps": round(self._baseline[dst].mean, 2),
                "baseline_std_pps":  round(self._baseline[dst].std_dev, 2),
            },
        )

    def _suppress(self, dst: str) -> None:
        self._last_alert[dst] = time.time()

    def _is_suppressed(self, dst: str) -> bool:
        return (time.time() - self._last_alert.get(dst, 0.0)) < _SUPPRESSION_S
