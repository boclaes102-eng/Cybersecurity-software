"""
Per-host statistical baseline engine.

Each host on the monitored network gets a HostBaseline that tracks packet
rate, byte rate, and protocol distribution using Welford's online algorithm.

Detection logic
---------------
1. Warm-up phase (< WARMUP_PACKETS observations): accumulate statistics,
   suppress all alerts.
2. Detection phase: for every sampled rate, compute the z-score against
   the current baseline distribution.  Fire an alert if |z| > threshold.
3. Continuous learning: the baseline keeps updating even after warm-up, so
   it adapts slowly to legitimate traffic shifts over time.

Alert suppression prevents storms: once an alert fires for a host/category
pair, it is silenced for SUPPRESSION_SECONDS.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from nids.capture.parser import ParsedPacket
from nids.detection.models import Alert, Severity
from nids.utils.stats import EWMA, SlidingWindowCounter, WelfordAccumulator

# Minimum observations before z-score detection activates
WARMUP_PACKETS: int = 200

# Z-score thresholds
Z_CRITICAL: float = 5.0
Z_HIGH: float     = 4.0

# Per-(host, category) alert cooldown
SUPPRESSION_SECONDS: float = 30.0

# Rate sampling interval (seconds)
RATE_SAMPLE_INTERVAL: float = 1.0


@dataclass
class HostBaseline:
    """
    Statistical model for a single observed IP address.

    Packet rate is sampled once per second using a 5-second sliding window
    and fed into both a Welford accumulator (for z-score detection) and an
    EWMA (for the smoothed rate shown in the dashboard).
    """

    ip: str
    first_seen: float = field(default_factory=time.time)
    last_seen:  float = field(default_factory=time.time)

    # Packet-rate model
    pkt_rate_stats: WelfordAccumulator = field(default_factory=WelfordAccumulator)
    pkt_rate_ewma:  EWMA               = field(default_factory=lambda: EWMA(alpha=0.2))
    _pkt_window:    SlidingWindowCounter = field(
        default_factory=lambda: SlidingWindowCounter(5.0)
    )
    _rate_sampled_at: float = field(default_factory=time.monotonic)

    # Aggregate counters (for dashboard display)
    total_packets: int = 0
    total_bytes:   int = 0
    protocol_counts: dict[str, int] = field(default_factory=dict)

    # Alert suppression: category → last alert timestamp
    _last_alert: dict[str, float] = field(default_factory=dict)

    # ------------------------------------------------------------------ #

    def observe(self, pkt: ParsedPacket) -> None:
        """Ingest one packet and update all statistical models."""
        self.last_seen      = pkt.timestamp
        self.total_packets += 1
        self.total_bytes   += pkt.length

        proto = pkt.protocol
        self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1

        # Tick the sliding counter and sample the rate every second
        now = time.monotonic()
        self._pkt_window.add(now)
        if now - self._rate_sampled_at >= RATE_SAMPLE_INTERVAL:
            rate = self._pkt_window.count() / 5.0   # packets/sec over 5 s
            self.pkt_rate_stats.update(rate)
            self.pkt_rate_ewma.update(rate)
            self._rate_sampled_at = now

    # ── Convenience properties ─────────────────────────────────────────

    @property
    def warmed_up(self) -> bool:
        return self.total_packets >= WARMUP_PACKETS

    @property
    def current_rate(self) -> float:
        """Instantaneous packet rate (packets/sec, 5-second window)."""
        return self._pkt_window.count() / 5.0

    @property
    def smoothed_rate(self) -> float:
        return self.pkt_rate_ewma.value

    # ── Alert suppression ──────────────────────────────────────────────

    def is_suppressed(self, category: str) -> bool:
        return (time.time() - self._last_alert.get(category, 0.0)) < SUPPRESSION_SECONDS

    def record_alert(self, category: str) -> None:
        self._last_alert[category] = time.time()

    # ── Detection ─────────────────────────────────────────────────────

    def check_rate_anomaly(self) -> Optional[Alert]:
        """
        Statistical rate anomaly detection.

        Fires when the current packet rate deviates by more than Z_HIGH
        standard deviations from the established baseline mean.
        """
        if not self.warmed_up or self.is_suppressed("rate_anomaly"):
            return None

        rate = self.current_rate
        z    = self.pkt_rate_stats.z_score(rate)

        if z <= Z_HIGH:
            return None

        severity = Severity.CRITICAL if z > Z_CRITICAL else Severity.HIGH
        self.record_alert("rate_anomaly")

        return Alert(
            severity=severity,
            title="Traffic Volume Anomaly",
            description=(
                f"Host {self.ip} rate {rate:.1f} pkt/s is {z:.1f}σ above "
                f"baseline ({self.pkt_rate_stats.mean:.1f} ± "
                f"{self.pkt_rate_stats.std_dev:.1f} pkt/s)"
            ),
            detector="baseline",
            mitre_key="anomaly",
            src_ip=self.ip,
            evidence={
                "current_rate_pps":   round(rate, 2),
                "baseline_mean_pps":  round(self.pkt_rate_stats.mean, 2),
                "baseline_std_pps":   round(self.pkt_rate_stats.std_dev, 2),
                "z_score":            round(z, 2),
                "total_packets_seen": self.total_packets,
            },
        )


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class BaselineManager:
    """Registry of per-host baselines."""

    def __init__(self) -> None:
        self._baselines: dict[str, HostBaseline] = {}

    def get_or_create(self, ip: str) -> HostBaseline:
        if ip not in self._baselines:
            self._baselines[ip] = HostBaseline(ip=ip)
        return self._baselines[ip]

    def get(self, ip: str) -> Optional[HostBaseline]:
        return self._baselines.get(ip)

    @property
    def all_hosts(self) -> dict[str, HostBaseline]:
        return self._baselines
