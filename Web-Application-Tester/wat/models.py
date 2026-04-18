"""Shared data models for WAT findings."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    type: str       # dir_found | header_missing | header_present | header_weak | sqli_hit | xss_hit | error
    severity: str   # CRITICAL | HIGH | MEDIUM | LOW | INFO
    url: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "severity": self.severity,
            "url": self.url,
            "detail": self.detail,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }
