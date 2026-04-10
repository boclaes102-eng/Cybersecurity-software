"""
Alert data model and MITRE ATT&CK taxonomy.

Every detection produces an Alert object that carries:
  - a UUID for correlation across tools
  - structured evidence dict (queryable, serialisable)
  - MITRE ATT&CK technique ID + tactic for SIEM enrichment
  - a to_siem_dict() method compatible with ECS / Splunk HEC / QRadar LEEF
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    @property
    def color(self) -> str:
        return {
            "CRITICAL": "bold red",
            "HIGH":     "red",
            "MEDIUM":   "yellow",
            "LOW":      "cyan",
            "INFO":     "dim",
        }[self.value]

    @property
    def rank(self) -> int:
        """Numeric rank for sorting; higher = more severe."""
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[self.value]


# ---------------------------------------------------------------------------
# MITRE ATT&CK mappings
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MITRETag:
    technique_id: str
    technique: str
    tactic: str


# Curated technique references for this detector set
MITRE_TECHNIQUES: dict[str, MITRETag] = {
    "port_scan": MITRETag(
        "T1046",
        "Network Service Scanning",
        "Discovery",
    ),
    "syn_flood": MITRETag(
        "T1498.001",
        "Direct Network Flood",
        "Impact",
    ),
    "dns_tunnel": MITRETag(
        "T1071.004",
        "Application Layer Protocol: DNS",
        "Command and Control",
    ),
    "arp_spoof": MITRETag(
        "T1557.002",
        "ARP Cache Poisoning",
        "Credential Access",
    ),
    "icmp_amp": MITRETag(
        "T1498.002",
        "Reflection Amplification",
        "Impact",
    ),
    "anomaly": MITRETag(
        "T1571",
        "Non-Standard Port",
        "Command and Control",
    ),
}


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    """
    Immutable-by-convention alert record.

    `evidence` is an open dict so each detector can attach its own signals
    (z-scores, entropy values, ratios …) without schema churn.
    """

    severity:    Severity
    title:       str
    description: str
    detector:    str
    mitre_key:   str

    src_ip:   str | None = None
    dst_ip:   str | None = None
    src_port: int | None = None
    dst_port: int | None = None

    evidence:   dict[str, Any] = field(default_factory=dict)
    timestamp:  float          = field(default_factory=time.time)
    alert_id:   str            = field(default_factory=lambda: str(uuid.uuid4()))

    # ------------------------------------------------------------------ #
    @property
    def mitre(self) -> MITRETag:
        return MITRE_TECHNIQUES.get(
            self.mitre_key,
            MITRE_TECHNIQUES["anomaly"],
        )

    def to_siem_dict(self) -> dict[str, Any]:
        """
        Serialise to a flat dict suitable for NDJSON / Elastic ECS.

        Field names deliberately mirror the ECS network.* and threat.*
        namespaces so the output can be indexed into Elasticsearch without
        a pipeline transform.
        """
        return {
            # --- identity ---------------------------------------------------
            "alert_id":      self.alert_id,
            "timestamp":     self.timestamp,
            "@timestamp":    time.strftime(
                                 "%Y-%m-%dT%H:%M:%S.000Z",
                                 time.gmtime(self.timestamp),
                             ),
            # --- classification ---------------------------------------------
            "severity":      self.severity.value,
            "title":         self.title,
            "description":   self.description,
            "detector":      self.detector,
            # --- network context --------------------------------------------
            "network": {
                "src_ip":   self.src_ip,
                "dst_ip":   self.dst_ip,
                "src_port": self.src_port,
                "dst_port": self.dst_port,
            },
            # --- MITRE ATT&CK -----------------------------------------------
            "threat": {
                "technique_id": self.mitre.technique_id,
                "technique":    self.mitre.technique,
                "tactic":       self.mitre.tactic,
            },
            # --- detector evidence ------------------------------------------
            "evidence": self.evidence,
        }
