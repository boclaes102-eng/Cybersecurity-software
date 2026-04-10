"""
Build CyberSuite.exe using PyInstaller.

Usage (from the repo root, inside the venv):
    python build.py

Output:
    dist/CyberSuite.exe   — single portable executable
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).parent
SEP  = ";" if sys.platform == "win32" else ":"


def _data(src: str, dest: str) -> str:
    return f"{ROOT / src}{SEP}{dest}"


def main() -> None:
    try:
        import PyInstaller.__main__ as pyi
    except ImportError:
        print("PyInstaller not found.  Run:  pip install pyinstaller")
        sys.exit(1)

    args = [
        str(ROOT / "launcher" / "main.py"),
        "--name",        "CyberSuite",
        "--onefile",
        "--windowed",                          # no console window on Windows
        "--clean",
        # ── Tool directories bundled as data ──────────────────────────────
        "--add-data", _data("Network-Intrusion-Detection-System",
                            "Network-Intrusion-Detection-System"),
        "--add-data", _data("Password-Auditing-Suite",
                            "Password-Auditing-Suite"),
        "--add-data", _data("Static-Malware-Analyzer",
                            "Static-Malware-Analyzer"),
        # ── customtkinter needs its theme assets ──────────────────────────
        "--collect-all", "customtkinter",
        # ── Hidden imports that auto-analysis may miss ─────────────────────
        "--hidden-import", "scapy.layers.all",
        "--hidden-import", "scapy.arch.windows",
        "--hidden-import", "passlib.handlers.bcrypt",
        "--hidden-import", "passlib.handlers.md5_crypt",
        "--hidden-import", "passlib.handlers.sha2_crypt",
        "--hidden-import", "passlib.handlers.nthash",
        "--hidden-import", "click",
        "--hidden-import", "pefile",
        "--hidden-import", "elftools.elf.elffile",
        "--hidden-import", "requests",
        "--hidden-import", "numpy",
        # ── Multiprocessing support inside frozen bundle ──────────────────
        "--runtime-hook", str(ROOT / "launcher" / "_pyi_hook.py"),
    ]

    print("Building CyberSuite.exe …\n")
    pyi.run(args)
    print(f"\n✓  Done →  dist/CyberSuite.exe")


if __name__ == "__main__":
    main()
