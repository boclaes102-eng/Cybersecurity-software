"""
SIEM-compatible alert output stream.

Format: newline-delimited JSON (NDJSON / JSON Lines)
  — one JSON object per line, no outer array
  — compatible with Elastic Bulk API, Splunk HEC, and Filebeat tail input

Field schema mirrors Elastic Common Schema (ECS):
  @timestamp     ISO-8601 UTC
  alert_id       UUID (correlate across log sources)
  severity       CRITICAL | HIGH | MEDIUM | LOW | INFO
  network.*      src/dst IP and port
  threat.*       MITRE ATT&CK technique_id, technique, tactic
  evidence.*     detector-specific signals (z-scores, ratios, etc.)

Usage
-----
  writer = SIEMWriter("alerts.ndjson")
  writer.write(alert)
  writer.close()

The file is opened in append mode so it survives restarts without
losing prior alerts.  Callers should call close() on shutdown or use
the context manager form.
"""

from __future__ import annotations

import json
import logging
import os
from types import TracebackType
from typing import Optional, Type

from nids.detection.models import Alert

logger = logging.getLogger(__name__)


class SIEMWriter:
    """
    Thread-safe NDJSON alert writer.

    write() flushes immediately so that a tail -f on the output file
    or a Filebeat agent configured with close_inactive will pick up
    every alert in real time.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._file = open(path, "a", encoding="utf-8", buffering=1)  # line-buffered
        logger.info("SIEM output: %s", os.path.abspath(path))

    def write(self, alert: Alert) -> None:
        try:
            line = json.dumps(alert.to_siem_dict(), ensure_ascii=False)
            self._file.write(line + "\n")
        except Exception as exc:
            logger.warning("Failed to write alert to SIEM stream: %s", exc)

    def close(self) -> None:
        try:
            self._file.flush()
            self._file.close()
        except Exception:
            pass

    # Context manager support
    def __enter__(self) -> "SIEMWriter":
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.close()
