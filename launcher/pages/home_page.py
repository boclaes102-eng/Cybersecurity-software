"""Home / dashboard page — shown at launch."""
from __future__ import annotations

from typing import Callable

import customtkinter as ctk

from ..utils.paths import NIDS_DIR, PAS_DIR, SMA_DIR, WAT_DIR, PGN_DIR, CEH_DIR

_TOOLS = [
    {
        "key": "netmap",
        "short": "NetMap",
        "title": "Network Map",
        "desc": (
            "Discover and visualize the local network:\n"
            "Phase 1 — ARP scan (instant topology)\n"
            "Phase 2 — nmap: OS · open ports · vendor\n\n"
            "Risk rings · drag nodes · click to set target."
        ),
        "deps": ["scapy", "nmap"],
    },
    {
        "key": "nids",
        "short": "NIDS",
        "title": "Network Intrusion Detection",
        "desc": (
            "Real-time packet analysis with 6 attack detectors:\n"
            "Port Scan · SYN Flood · DNS Tunneling\n"
            "ARP Poisoning · ICMP Amplification · Statistical Anomaly\n\n"
            "Live capture or PCAP replay. Rich dashboard + SIEM export."
        ),
        "deps": ["scapy", "rich", "numpy"],
    },
    {
        "key": "pas",
        "short": "PAS",
        "title": "Password Auditing Suite",
        "desc": (
            "Full offline credential analysis:\n"
            "Hash Identification · Dictionary Cracking\n"
            "Entropy Scoring · HIBP Breach Check\n"
            "Wordlist Mutation · Full Audit Pipeline"
        ),
        "deps": ["click", "rich", "requests", "passlib"],
    },
    {
        "key": "sma",
        "short": "SMA",
        "title": "Static Malware Analyzer",
        "desc": (
            "Binary analysis without execution:\n"
            "PE/ELF parsing · Shannon entropy per section\n"
            "18 MITRE ATT&CK behavioral rules · YARA scanning\n"
            "VirusTotal v3 lookup · JSON report export"
        ),
        "deps": ["pefile", "pyelftools", "rich", "requests"],
    },
    {
        "key": "wat",
        "short": "WAT",
        "title": "Web Application Tester",
        "desc": (
            "Active web vulnerability scanning:\n"
            "Directory brute-force · Header security analysis\n"
            "SQL injection detection · Reflected XSS detection\n\n"
            "Multi-threaded. JSON report export."
        ),
        "deps": ["requests"],
    },
    {
        "key": "pgn",
        "short": "PGN",
        "title": "Payload Generator",
        "desc": (
            "Offensive payload generation:\n"
            "Reverse shells · Bind shells · Web shells\n"
            "Encoder (base64 / URL / hex / PowerShell)\n\n"
            "Built-in TCP listener to catch reverse shells."
        ),
        "deps": [],
    },
    {
        "key": "ceh",
        "short": "CEH",
        "title": "CVE & Exploit Helper",
        "desc": (
            "Vulnerability intelligence:\n"
            "NVD API v2 CVE search · CVE detail lookup\n"
            "ExploitDB search (searchsploit or web)\n\n"
            "Results sorted by CVSS score. JSON export."
        ),
        "deps": ["requests", "beautifulsoup4"],
    },
]


def _dep_ok(name: str) -> bool:
    try:
        __import__(name.split("[")[0].replace("-", "_"))
        return True
    except ImportError:
        return False


class HomePage(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkFrame, navigate_cb: Callable[[str], None]) -> None:
        super().__init__(master, fg_color="transparent")
        self._navigate = navigate_cb
        self._build()

    # ------------------------------------------------------------------
    def _build(self) -> None:
        # ── Header ──────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=32, pady=(32, 8))

        ctk.CTkLabel(
            hdr,
            text="CyberSuite Pro",
            font=ctk.CTkFont(size=30, weight="bold"),
        ).pack(anchor="w")
        ctk.CTkLabel(
            hdr,
            text="Six professional security tools — one unified launcher.",
            text_color="gray",
            font=ctk.CTkFont(size=14),
        ).pack(anchor="w", pady=(2, 0))

        ctk.CTkFrame(self, height=1, fg_color="#30363d").pack(fill="x", padx=32, pady=16)

        # ── Tool cards (2 rows × 3 columns) ─────────────────────────────
        cards = ctk.CTkFrame(self, fg_color="transparent")
        cards.pack(fill="both", expand=True, padx=24, pady=0)
        cards.grid_columnconfigure((0, 1, 2), weight=1, uniform="card")
        cards.grid_rowconfigure((0, 1, 2), weight=1)

        for idx, tool in enumerate(_TOOLS):
            row, col = divmod(idx, 3)
            self._make_card(cards, tool, row, col)

        # ── Dependency status bar ────────────────────────────────────────
        bar = ctk.CTkFrame(self, corner_radius=8)
        bar.pack(fill="x", padx=32, pady=(16, 28))

        ctk.CTkLabel(
            bar,
            text="  Dependency status",
            font=ctk.CTkFont(weight="bold"),
            anchor="w",
        ).pack(fill="x", padx=4, pady=(8, 4))

        row = ctk.CTkFrame(bar, fg_color="transparent")
        row.pack(fill="x", padx=8, pady=(0, 8))

        all_deps = sorted({d.split("[")[0] for t in _TOOLS for d in t["deps"] if d})
        for dep in all_deps:
            ok = _dep_ok(dep)
            color = "#3fb950" if ok else "#f85149"
            mark = "OK" if ok else "!!"
            ctk.CTkLabel(
                row,
                text=f"{mark} {dep}",
                text_color=color,
                font=ctk.CTkFont(size=12),
            ).pack(side="left", padx=8)

    # ------------------------------------------------------------------
    def _make_card(self, parent: ctk.CTkFrame, tool: dict, row: int, col: int) -> None:
        card = ctk.CTkFrame(parent, corner_radius=12)
        card.grid(row=row, column=col, padx=8, pady=8, sticky="nsew")
        card.grid_rowconfigure(3, weight=1)
        card.grid_columnconfigure(0, weight=1)

        # Badge
        badge_frame = ctk.CTkFrame(card, fg_color="#1d3557", corner_radius=6)
        badge_frame.grid(row=0, column=0, sticky="w", padx=16, pady=(18, 6))
        ctk.CTkLabel(
            badge_frame,
            text=tool["short"],
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#58a6ff",
        ).pack(padx=10, pady=4)

        ctk.CTkLabel(
            card,
            text=tool["title"],
            font=ctk.CTkFont(size=16, weight="bold"),
            wraplength=230,
            anchor="w",
        ).grid(row=1, column=0, sticky="w", padx=16, pady=(0, 8))

        ctk.CTkLabel(
            card,
            text=tool["desc"],
            text_color="gray",
            font=ctk.CTkFont(size=12),
            wraplength=230,
            justify="left",
            anchor="w",
        ).grid(row=2, column=0, sticky="w", padx=16)

        # Dep status
        ok_count = sum(_dep_ok(d) for d in tool["deps"])
        total = len(tool["deps"])
        dep_color = "#3fb950" if ok_count == total else ("#d29922" if ok_count else "#f85149")
        ctk.CTkLabel(
            card,
            text=f"{ok_count}/{total} dependencies found",
            text_color=dep_color,
            font=ctk.CTkFont(size=11),
        ).grid(row=3, column=0, sticky="sw", padx=16, pady=(12, 6))

        ctk.CTkButton(
            card,
            text=f"Open {tool['short']}",
            fg_color="#238636",
            hover_color="#2ea043",
            command=lambda k=tool["key"]: self._navigate(k),
        ).grid(row=4, column=0, sticky="ew", padx=16, pady=(0, 16))
