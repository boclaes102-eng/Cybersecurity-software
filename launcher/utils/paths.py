"""
Resolve paths to the three tool directories.

Works both in development (standard repo layout) and inside a PyInstaller
--onefile bundle where all data lives under sys._MEIPASS.
"""
from __future__ import annotations

import sys
from pathlib import Path


def _base() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)          # type: ignore[attr-defined]
    # launcher/utils/paths.py → repo root is three levels up
    return Path(__file__).resolve().parent.parent.parent


BASE_DIR = _base()
NIDS_DIR = BASE_DIR / "Network-Intrusion-Detection-System"
PAS_DIR  = BASE_DIR / "Password-Auditing-Suite"
SMA_DIR  = BASE_DIR / "Static-Malware-Analyzer"
WAT_DIR  = BASE_DIR / "Web-Application-Tester"
PGN_DIR  = BASE_DIR / "Payload-Generator"
CEH_DIR  = BASE_DIR / "CVE-Exploit-Helper"


def add_tools_to_path() -> None:
    """Prepend all tool directories to sys.path (idempotent)."""
    for d in (NIDS_DIR, PAS_DIR, SMA_DIR, WAT_DIR, PGN_DIR, CEH_DIR):
        s = str(d)
        if s not in sys.path:
            sys.path.insert(0, s)
