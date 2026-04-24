"""Home / dashboard page — shown at launch."""
from __future__ import annotations

from typing import Callable

import customtkinter as ctk

from ..utils.paths import NIDS_DIR, PAS_DIR, SMA_DIR, WAT_DIR, PGN_DIR, CEH_DIR

_TOOLS = [
    {
        "key": "report",
        "short": "RPT",
        "title": "Report Generator",
        "desc": (
            "Professional pentest report builder:\n"
            "Add findings with severity · evidence · remediation\n"
            "Auto-import from NetMap scan results\n\n"
            "Generates styled HTML → print to PDF."
        ),
        "deps": [],
    },
    {
        "key": "msf",
        "short": "MSF",
        "title": "Metasploit Bridge",
        "desc": (
            "CVE → module → exploitation:\n"
            "Search modules or pick from CVE map\n"
            "Pre-fills RHOST/LHOST/payload\n\n"
            "Launches msfconsole in a new window."
        ),
        "deps": [],
    },
    {
        "key": "wifi",
        "short": "WiFi",
        "title": "WiFi Recon & Attack",
        "desc": (
            "Survey nearby networks (netsh)\n"
            "WPA2 handshake capture (airodump-ng)\n"
            "Deauthentication attack (aireplay-ng)\n\n"
            "Export capture to PAS for cracking."
        ),
        "deps": [],
    },
    {
        "key": "ad",
        "short": "AD",
        "title": "AD Enumeration",
        "desc": (
            "Active Directory attack surface:\n"
            "Kerberoastable · AS-REP Roastable\n"
            "Unconstrained delegation · Stale accounts\n\n"
            "Exports findings directly to Report Generator."
        ),
        "deps": ["ldap3"],
    },
    {
        "key": "creds",
        "short": "CRED",
        "title": "Credential Harvester",
        "desc": (
            "Live credential capture during MITM:\n"
            "HTTP form POST · Basic Auth headers\n"
            "NTLM hash extraction (NTLMv2)\n\n"
            "One-click export to hashcat format."
        ),
        "deps": ["scapy"],
    },
    {
        "key": "mitm",
        "short": "MITM",
        "title": "ARP Spoof / MITM",
        "desc": (
            "MAC changer + ARP poisoning:\n"
            "Change interface MAC (random or custom)\n"
            "Bidirectional ARP spoof — target ↔ gateway\n\n"
            "IP forwarding keeps both sides connected."
        ),
        "deps": ["scapy", "psutil"],
    },
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
        hdr.pack(fill="x", padx=28, pady=(28, 6))

        ctk.CTkLabel(hdr, text="CyberSuite Pro",
                     font=ctk.CTkFont(size=28, weight="bold"),
                     text_color="#e6edf3").pack(anchor="w")
        ctk.CTkLabel(hdr,
                     text=f"Unified security operations toolkit  ·  {len(_TOOLS)} modules",
                     text_color="#7d8590",
                     font=ctk.CTkFont(size=13)).pack(anchor="w", pady=(2, 0))

        ctk.CTkFrame(self, height=1, fg_color="#21262d").pack(
            fill="x", padx=28, pady=(14, 12))

        # ── Tool cards ───────────────────────────────────────────────────
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent",
                                        scrollbar_button_color="#30363d")
        scroll.pack(fill="both", expand=True, padx=20, pady=0)
        scroll.grid_columnconfigure((0, 1, 2), weight=1, uniform="card")
        max_row = (len(_TOOLS) - 1) // 3
        scroll.grid_rowconfigure(tuple(range(max_row + 1)), weight=1)

        for idx, tool in enumerate(_TOOLS):
            row, col = divmod(idx, 3)
            self._make_card(scroll, tool, row, col)

        # ── Dependency status bar ────────────────────────────────────────
        bar = ctk.CTkFrame(self, fg_color="#161b22", corner_radius=8,
                           border_width=1, border_color="#21262d")
        bar.pack(fill="x", padx=28, pady=(10, 20))

        ctk.CTkLabel(bar, text="Dependencies",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color="#7d8590"
                     ).pack(anchor="w", padx=16, pady=(10, 4))

        dep_row = ctk.CTkFrame(bar, fg_color="transparent")
        dep_row.pack(fill="x", padx=12, pady=(0, 10))

        all_deps = sorted({d.split("[")[0] for t in _TOOLS for d in t["deps"] if d})
        for dep in all_deps:
            ok = _dep_ok(dep)
            color = "#3fb950" if ok else "#f85149"
            ctk.CTkLabel(dep_row,
                         text=f"{'✓' if ok else '✗'}  {dep}",
                         text_color=color,
                         font=ctk.CTkFont(family="Consolas", size=11),
                         ).pack(side="left", padx=10)

    # ------------------------------------------------------------------
    def _make_card(self, parent: ctk.CTkFrame, tool: dict,
                   row: int, col: int) -> None:
        card = ctk.CTkFrame(parent, fg_color="#161b22",
                            corner_radius=8,
                            border_width=1, border_color="#21262d")
        card.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")
        card.grid_rowconfigure(2, weight=1)
        card.grid_columnconfigure(0, weight=1)

        # Top accent bar
        ctk.CTkFrame(card, height=2, fg_color="#58a6ff",
                     corner_radius=0).grid(
            row=0, column=0, sticky="ew")

        # Content
        content = ctk.CTkFrame(card, fg_color="transparent")
        content.grid(row=1, column=0, sticky="nsew", padx=14, pady=(12, 0))
        content.grid_columnconfigure(0, weight=1)

        # Badge + title row
        top = ctk.CTkFrame(content, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        ctk.CTkLabel(top, text=tool["short"],
                     font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                     text_color="#58a6ff",
                     fg_color="#0d2044",
                     corner_radius=4,
                     width=40
                     ).pack(side="left", padx=(0, 10), ipadx=6, ipady=3)
        ctk.CTkLabel(top, text=tool["title"],
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#e6edf3", anchor="w"
                     ).pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(content,
                     text=tool["desc"],
                     text_color="#7d8590",
                     font=ctk.CTkFont(size=11),
                     wraplength=210,
                     justify="left",
                     anchor="nw",
                     ).grid(row=1, column=0, sticky="nw")

        # Footer
        footer = ctk.CTkFrame(card, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="sew", padx=14, pady=(8, 12))
        footer.grid_columnconfigure(0, weight=1)

        ok_count = sum(_dep_ok(d) for d in tool["deps"])
        total = len(tool["deps"])
        dep_color = ("#3fb950" if ok_count == total
                     else ("#d29922" if ok_count else "#f85149"))
        if total:
            ctk.CTkLabel(footer,
                         text=f"{ok_count}/{total} deps",
                         text_color=dep_color,
                         font=ctk.CTkFont(family="Consolas", size=10),
                         ).grid(row=0, column=0, sticky="w", pady=(0, 6))

        ctk.CTkButton(footer,
                      text="Open →",
                      fg_color="#238636", hover_color="#2ea043",
                      font=ctk.CTkFont(size=12, weight="bold"),
                      height=32,
                      command=lambda k=tool["key"]: self._navigate(k),
                      ).grid(row=1, column=0, sticky="ew")
