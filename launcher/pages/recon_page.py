"""Recon Workspace page — online (backend) + offline (manual) modes."""
from __future__ import annotations

import json
import pathlib
import threading
import urllib.error
import urllib.request
from typing import Callable

import customtkinter as ctk

_CONFIG_PATH = pathlib.Path.home() / ".cybersuite" / "config.json"

_TOOL_LABELS = {
    "ip": "IP Intelligence",   "domain": "Domain Analyzer",
    "subdomains": "Subdomain Enum", "ssl": "SSL Inspector",
    "headers": "HTTP Headers",  "portscan": "Port Scanner",
    "dns": "DNS Resolver",      "reverseip": "Reverse IP",
    "asn": "BGP / ASN",         "whoishistory": "WHOIS History",
    "certs": "Cert Transparency", "traceroute": "Traceroute",
    "url": "URL Scanner",       "email": "Email OSINT",
    "ioc": "IOC Lookup",        "shodan": "Shodan Search",
    "tech": "Tech Fingerprinter", "waf": "WAF Detector",
    "cors": "CORS Checker",
}


def _load_config() -> dict:
    try:
        return json.loads(_CONFIG_PATH.read_text())
    except Exception:
        return {"api_url": "", "api_key": ""}


def _save_config(cfg: dict) -> None:
    _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CONFIG_PATH.write_text(json.dumps(cfg, indent=2))


class ReconPage(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkFrame, runner, output_cb: Callable[[str], None]) -> None:
        super().__init__(master, fg_color="transparent")
        self._out = output_cb
        self._cfg = _load_config()
        self._sessions: list[dict] = []
        self._session_widgets: list[dict] = []
        self._build()

    # ── Layout ─────────────────────────────────────────────────────────────
    def _build(self) -> None:
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(24, 4))
        ctk.CTkLabel(hdr, text="Recon Workspace",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(hdr, text="Load saved dashboard recon sessions  ·  or enter targets manually",
                     text_color="gray", font=ctk.CTkFont(size=12)).pack(anchor="w")

        # Active target banner
        target_bar = ctk.CTkFrame(self, fg_color="#0d1117", corner_radius=6)
        target_bar.pack(fill="x", padx=24, pady=(8, 0))
        ctk.CTkLabel(target_bar, text="Active target:",
                     font=ctk.CTkFont(size=12), text_color="gray").pack(side="left", padx=12, pady=8)
        self._active_target = ctk.StringVar(value="—")
        ctk.CTkLabel(target_bar, textvariable=self._active_target,
                     font=ctk.CTkFont(family="Consolas", size=13),
                     text_color="#58a6ff").pack(side="left", pady=8)
        ctk.CTkButton(target_bar, text="Copy", width=60, height=26,
                      fg_color="#21262d", hover_color="#30363d",
                      command=self._copy_target).pack(side="right", padx=12, pady=6)

        # Tabs
        self._tabs = ctk.CTkTabview(self)
        self._tabs.pack(fill="both", expand=True, padx=24, pady=8)

        self._build_online_tab(self._tabs.add("Workspace (Online)"))
        self._build_offline_tab(self._tabs.add("Manual (Offline)"))
        self._build_settings_tab(self._tabs.add("Settings"))

    # ── Online tab ─────────────────────────────────────────────────────────
    def _build_online_tab(self, tab: ctk.CTkFrame) -> None:
        tab.grid_rowconfigure(1, weight=1)
        tab.grid_columnconfigure(0, weight=1)

        # Controls row
        ctrl = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl.grid(row=0, column=0, sticky="ew", pady=(8, 4))
        ctrl.grid_columnconfigure(1, weight=1)

        self._tool_filter = ctk.StringVar(value="all")
        tool_opts = ["all"] + sorted(_TOOL_LABELS.keys())
        ctk.CTkLabel(ctrl, text="Filter tool:").grid(row=0, column=0, padx=(0, 8))
        ctk.CTkComboBox(ctrl, variable=self._tool_filter, values=tool_opts,
                        state="readonly", width=180).grid(row=0, column=1, sticky="w")
        ctk.CTkButton(ctrl, text="Fetch Sessions", width=130,
                      fg_color="#1f6aa5", hover_color="#1a5a8f",
                      command=self._fetch_sessions).grid(row=0, column=2, padx=(8, 0))
        self._fetch_status = ctk.CTkLabel(ctrl, text="", text_color="gray",
                                           font=ctk.CTkFont(size=11))
        self._fetch_status.grid(row=0, column=3, padx=8)

        # Scrollable session list
        self._session_list = ctk.CTkScrollableFrame(tab, fg_color="#0d1117",
                                                     corner_radius=6, height=400)
        self._session_list.grid(row=1, column=0, sticky="nsew", pady=(4, 0))
        self._session_list.grid_columnconfigure(0, weight=1)

        self._empty_label = ctk.CTkLabel(
            self._session_list,
            text="Click 'Fetch Sessions' to load saved recon data from the backend.",
            text_color="gray", font=ctk.CTkFont(size=12),
        )
        self._empty_label.grid(row=0, column=0, pady=40)

    def _fetch_sessions(self) -> None:
        self._fetch_status.configure(text="Fetching…", text_color="#d29922")
        threading.Thread(target=self._do_fetch, daemon=True).start()

    def _do_fetch(self) -> None:
        cfg = _load_config()
        api_url = cfg.get("api_url", "").rstrip("/")
        api_key = cfg.get("api_key", "")

        if not api_url or not api_key:
            self.after(0, lambda: self._fetch_status.configure(
                text="No API config — go to Settings tab", text_color="#f85149"))
            return

        tool_filter = self._tool_filter.get()
        endpoint = f"{api_url}/api/v1/recon-sessions?limit=50"
        if tool_filter != "all":
            endpoint += f"&tool={tool_filter}"

        try:
            req = urllib.request.Request(endpoint, headers={"X-API-Key": api_key})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            sessions = data.get("data", [])
            self.after(0, lambda: self._render_sessions(sessions))
        except urllib.error.URLError as e:
            msg = f"Connection failed: {e.reason}"
            self.after(0, lambda: self._fetch_status.configure(text=msg, text_color="#f85149"))
        except Exception as e:
            self.after(0, lambda: self._fetch_status.configure(
                text=f"Error: {e}", text_color="#f85149"))

    def _render_sessions(self, sessions: list[dict]) -> None:
        # Clear existing rows
        for child in self._session_list.winfo_children():
            child.destroy()

        self._sessions = sessions

        if not sessions:
            lbl = ctk.CTkLabel(self._session_list, text="No sessions found.",
                               text_color="gray", font=ctk.CTkFont(size=12))
            lbl.grid(row=0, column=0, pady=40)
            self._fetch_status.configure(text="No sessions found", text_color="gray")
            return

        self._fetch_status.configure(
            text=f"{len(sessions)} session(s) loaded", text_color="#3fb950")

        for i, s in enumerate(sessions):
            self._make_session_row(i, s)

    def _make_session_row(self, row: int, s: dict) -> None:
        tool  = s.get("tool", "?")
        label = _TOOL_LABELS.get(tool, tool)
        target = s.get("target", "")
        created = s.get("createdAt", "")[:10]
        summary = s.get("summary", {})

        frame = ctk.CTkFrame(self._session_list, fg_color="#161b22",
                             corner_radius=6, border_width=1, border_color="#30363d")
        frame.grid(row=row, column=0, sticky="ew", pady=3, padx=4)
        frame.grid_columnconfigure(1, weight=1)

        # Tool badge
        ctk.CTkLabel(frame, text=label,
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="#58a6ff", width=140, anchor="w").grid(
            row=0, column=0, padx=10, pady=(8, 2))

        # Target
        ctk.CTkLabel(frame, text=target,
                     font=ctk.CTkFont(family="Consolas", size=12),
                     text_color="#c9d1d9", anchor="w").grid(
            row=0, column=1, sticky="w", padx=4, pady=(8, 2))

        # Date
        ctk.CTkLabel(frame, text=created,
                     font=ctk.CTkFont(size=10), text_color="gray").grid(
            row=0, column=2, padx=10, pady=(8, 2))

        # Load button
        ctk.CTkButton(frame, text="Load", width=60, height=26,
                      fg_color="#238636", hover_color="#2ea043",
                      command=lambda t=target: self._load_target(t)).grid(
            row=0, column=3, padx=10, pady=(6, 2))

        # Summary (collapsed)
        if summary:
            summary_text = "  ·  ".join(
                f"{k}: {v}" for k, v in list(summary.items())[:5] if v is not None
            )
            ctk.CTkLabel(frame, text=summary_text,
                         font=ctk.CTkFont(family="Consolas", size=10),
                         text_color="gray", anchor="w").grid(
                row=1, column=0, columnspan=4, sticky="w", padx=10, pady=(0, 8))

    # ── Offline tab ────────────────────────────────────────────────────────
    def _build_offline_tab(self, tab: ctk.CTkFrame) -> None:
        tab.grid_columnconfigure(1, weight=1)
        row = 0

        ctk.CTkLabel(tab, text="Target (IP / domain / URL)", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._manual_target = ctk.StringVar()
        ctk.CTkEntry(tab, textvariable=self._manual_target,
                     placeholder_text="e.g. 192.168.1.1 or example.com").grid(
            row=row, column=1, sticky="ew", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="Tool context", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._manual_tool = ctk.StringVar(value="ip")
        ctk.CTkComboBox(tab, variable=self._manual_tool,
                        values=sorted(_TOOL_LABELS.keys()),
                        state="readonly", width=180).grid(
            row=row, column=1, sticky="w", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="Notes", anchor="e").grid(
            row=row, column=0, sticky="ne", padx=(0, 12), pady=10)
        self._manual_notes = ctk.CTkTextbox(tab, height=80,
                                             font=ctk.CTkFont(family="Consolas", size=12))
        self._manual_notes.grid(row=row, column=1, sticky="ew", pady=10)
        row += 1

        ctk.CTkButton(tab, text="Set as Active Target",
                      fg_color="#238636", hover_color="#2ea043",
                      command=self._set_manual_target).grid(
            row=row, column=1, sticky="w", pady=8)

    def _set_manual_target(self) -> None:
        target = self._manual_target.get().strip()
        if target:
            self._load_target(target)

    # ── Settings tab ───────────────────────────────────────────────────────
    def _build_settings_tab(self, tab: ctk.CTkFrame) -> None:
        tab.grid_columnconfigure(1, weight=1)
        row = 0

        ctk.CTkLabel(tab, text="Backend API URL", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._cfg_url = ctk.StringVar(value=self._cfg.get("api_url", ""))
        ctk.CTkEntry(tab, textvariable=self._cfg_url,
                     placeholder_text="https://your-backend.railway.app").grid(
            row=row, column=1, sticky="ew", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="API Key", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._cfg_key = ctk.StringVar(value=self._cfg.get("api_key", ""))
        ctk.CTkEntry(tab, textvariable=self._cfg_key, show="*",
                     placeholder_text="your-api-key").grid(
            row=row, column=1, sticky="ew", pady=10)
        row += 1

        self._save_status = ctk.CTkLabel(tab, text="", text_color="gray",
                                          font=ctk.CTkFont(size=11))
        self._save_status.grid(row=row, column=1, sticky="w")
        row += 1

        ctk.CTkButton(tab, text="Save Settings",
                      fg_color="#1f6aa5", hover_color="#1a5a8f",
                      command=self._save_settings).grid(
            row=row, column=1, sticky="w", pady=8)
        row += 1

        ctk.CTkLabel(tab,
                     text="Config stored at: " + str(_CONFIG_PATH),
                     text_color="gray", font=ctk.CTkFont(size=10), anchor="w").grid(
            row=row, column=0, columnspan=2, sticky="w", padx=4, pady=(16, 0))

    def _save_settings(self) -> None:
        cfg = {"api_url": self._cfg_url.get().strip(), "api_key": self._cfg_key.get().strip()}
        _save_config(cfg)
        self._cfg = cfg
        self._save_status.configure(text="Saved!", text_color="#3fb950")
        self.after(2000, lambda: self._save_status.configure(text=""))

    # ── Helpers ────────────────────────────────────────────────────────────
    def _load_target(self, target: str) -> None:
        self._active_target.set(target)
        self._out(f"[Workspace] Active target set → {target}\n")

    def _copy_target(self) -> None:
        target = self._active_target.get()
        if target and target != "—":
            self.clipboard_clear()
            self.clipboard_append(target)
            self._out(f"[Workspace] Copied to clipboard: {target}\n")
