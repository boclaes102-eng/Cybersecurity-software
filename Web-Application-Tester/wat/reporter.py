"""JSON report output for WAT findings."""
from __future__ import annotations

import json
import time
from pathlib import Path

from .models import Finding


def save(findings: list[Finding], output_path: str) -> None:
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    report = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_findings": len(findings),
        "by_severity": by_sev,
        "findings": [f.to_dict() for f in findings],
    }
    Path(output_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
