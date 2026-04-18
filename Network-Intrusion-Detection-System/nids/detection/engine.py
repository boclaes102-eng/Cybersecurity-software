"""
Detection engine — the central processing pipeline.

Architecture
------------
DetectionEngine owns all detector instances and the baseline manager.
Every ParsedPacket flows through:

  1. BaselineManager  — update per-host statistical model + fire rate anomalies
  2. PortScanDetector — sliding-window contact analysis
  3. SYNFloodDetector — half-open connection ratio + absolute rate
  4. DNSTunnelDetector — entropy, label length, beacon rate, payload size
  5. ARPSpoofDetector  — binding table + gratuitous ARP flood
  6. ICMPAmpDetector   — broadcast request + reply asymmetry

Each detector is independent and stateful.  Errors in one detector
never propagate — the exception is caught here and discarded so that
a single malformed packet can never bring down the capture loop.

Global statistics (packets_processed, protocol_counts, etc.) are
maintained here and consumed by the Rich dashboard.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Protocol

from nids.capture.parser import ParsedPacket
from nids.detection.arp_spoof import ARPSpoofDetector
from nids.detection.baseline import BaselineManager
from nids.detection.correlator import CorrelationEngine
from nids.detection.dns_tunnel import DNSTunnelDetector
from nids.detection.icmp_amp import ICMPAmpDetector
from nids.detection.models import Alert
from nids.detection.port_scan import PortScanDetector
from nids.detection.syn_flood import SYNFloodDetector

logger = logging.getLogger(__name__)


class Detector(Protocol):
    """Structural protocol that all detectors satisfy."""
    def process(self, pkt: ParsedPacket) -> list[Alert]: ...


class DetectionEngine:
    """
    Stateful pipeline that routes each ParsedPacket through all detectors
    and collects the resulting alerts.
    """

    def __init__(self) -> None:
        self._baseline_mgr = BaselineManager()
        self._correlator = CorrelationEngine()

        # Ordered pipeline — detectors fire in this sequence
        self._detectors: list[Detector] = [
            PortScanDetector(),
            SYNFloodDetector(),
            DNSTunnelDetector(),
            ARPSpoofDetector(),
            ICMPAmpDetector(),
        ]

        # ── Global stats (read by dashboard) ──────────────────────────────
        self.packets_processed: int = 0
        self.alerts_total:      int = 0
        self.bytes_processed:   int = 0
        self.protocol_counts:   dict[str, int] = defaultdict(int)

    # ------------------------------------------------------------------ #

    def process(self, pkt: ParsedPacket) -> list[Alert]:
        """
        Process one packet through the full detection pipeline.

        Returns a (possibly empty) list of Alert objects.
        This method is synchronous and fast — it must not block the
        asyncio event loop.
        """
        self.packets_processed += 1
        self.bytes_processed   += pkt.length
        self.protocol_counts[pkt.protocol] += 1

        alerts: list[Alert] = []

        # ── Step 1: update host baseline + check for rate anomaly ─────────
        if pkt.src_ip:
            baseline = self._baseline_mgr.get_or_create(pkt.src_ip)
            baseline.observe(pkt)
            rate_alert = baseline.check_rate_anomaly()
            if rate_alert:
                alerts.append(rate_alert)

        # ── Step 2: run each specialist detector ──────────────────────────
        for detector in self._detectors:
            try:
                new_alerts = detector.process(pkt)
                alerts.extend(new_alerts)
            except Exception as exc:
                # Detectors must be resilient; log but never crash
                logger.debug("Detector %s raised: %s", type(detector).__name__, exc)

        # ── Step 3: cross-detector correlation ───────────────────────────
        corr_alerts = self._correlator.check(alerts)
        alerts.extend(corr_alerts)

        self.alerts_total += len(alerts)
        return alerts

    # ------------------------------------------------------------------ #

    @property
    def active_hosts(self) -> dict:
        """Live view of all HostBaseline objects (read by dashboard)."""
        return self._baseline_mgr.all_hosts
