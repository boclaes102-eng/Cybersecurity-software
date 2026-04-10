"""
Alert manager — in-memory alert store for the dashboard and SIEM writer.

Features
--------
  • Fixed-capacity ring buffer (deque with maxlen) avoids unbounded growth
  • Per-severity and per-detector counters for dashboard sparklines
  • Thread-safe via GIL (all operations are O(1) atomic deque operations)
  • recent() snapshot for dashboard rendering
"""

from __future__ import annotations

from collections import defaultdict, deque

from nids.detection.models import Alert, Severity


class AlertManager:
    """
    Central alert store.

    All writers call add(); readers call recent() or by_severity().
    The ring buffer automatically evicts the oldest entry once capacity
    is reached — the dashboard always shows the most recent MAX_ALERTS.
    """

    MAX_ALERTS = 500

    def __init__(self) -> None:
        # New alerts are prepended so index 0 is always the most recent
        self._alerts: deque[Alert] = deque(maxlen=self.MAX_ALERTS)

        # Aggregated counters (never reset during a session)
        self._severity_counts: dict[str, int] = defaultdict(int)
        self._detector_counts: dict[str, int] = defaultdict(int)

    # ------------------------------------------------------------------ #

    def add(self, alert: Alert) -> None:
        self._alerts.appendleft(alert)
        self._severity_counts[alert.severity.value] += 1
        self._detector_counts[alert.detector]       += 1

    def recent(self, n: int = 20) -> list[Alert]:
        """Return the n most recent alerts, newest first."""
        return list(self._alerts)[:n]

    def total(self) -> int:
        return sum(self._severity_counts.values())

    def by_severity(self) -> dict[str, int]:
        """Counts for each severity level (0 if none seen)."""
        return {sev.value: self._severity_counts.get(sev.value, 0) for sev in Severity}

    def by_detector(self) -> dict[str, int]:
        return dict(self._detector_counts)
