"""
CyberSuite Pro — main application window.

Layout
──────
┌────────────┬──────────────────────────────────────────────────┐
│  Sidebar   │  Page frame                                      │
│  236 px    ├──────────────────────────────────────────────────┤
│            │  Output console  (260 px)                        │
└────────────┴──────────────────────────────────────────────────┘

Keyboard shortcuts:  Ctrl+L = clear console   Escape = stop tool
"""
from __future__ import annotations

import customtkinter as ctk

from .pages.home_page   import HomePage
from .pages.nids_page   import NIDSPage
from .pages.pas_page    import PASPage
from .pages.sma_page    import SMAPage
from .pages.wat_page    import WATPage
from .pages.pgn_page    import PGNPage
from .pages.ceh_page    import CEHPage
from .pages.recon_page  import ReconPage
from .pages.netmap_page import NetMapPage
from .pages.mitm_page   import MITMPage
from .pages.report_page import ReportPage
from .pages.creds_page  import CredsPage
from .pages.msf_page    import MSFPage
from .pages.wifi_page   import WiFiPage
from .pages.ad_page     import ADPage
from .utils.runner      import ToolRunner

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── Navigation structure ──────────────────────────────────────────────────────
_NAV: list[tuple[str | None, list[tuple[str, str]]]] = [
    (None, [
        ("Home", "home"),
    ]),
    ("RECON", [
        ("Recon Workspace", "recon"),
        ("Network Map",     "netmap"),
        ("WiFi Recon",      "wifi"),
    ]),
    ("ATTACK", [
        ("MITM / ARP Spoof", "mitm"),
        ("Cred Harvester",   "creds"),
        ("Metasploit",       "msf"),
        ("AD Enumeration",   "ad"),
    ]),
    ("ANALYSIS", [
        ("NIDS",             "nids"),
        ("Password Audit",   "pas"),
        ("Malware Analyzer", "sma"),
        ("Web App Tester",   "wat"),
        ("Payload Gen",      "pgn"),
        ("CVE / Exploits",   "ceh"),
    ]),
    ("REPORTING", [
        ("Report Builder", "report"),
    ]),
]

# Flat ordered list for navigation logic
_NAV_FLAT = [(label, key)
             for _, items in _NAV
             for label, key in items]

# Console tag rules
_TAG_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("error",   ("[error]", "error:", "traceback", "exception:", "[stopped")),
    ("warning", ("[warning]", "warning:", "warn:", "[!")),
    ("success", ("[finished", "analysis complete", "[+]", "complete", "sent")),
    ("info",    ("=" * 10, "starting", "[*]")),
]


class App(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("CyberSuite Pro")
        self.geometry("1360x860")
        self.minsize(1024, 680)
        self.after(0, lambda: self.state("zoomed"))
        self.configure(fg_color="#0d1117")

        self._runner     = ToolRunner()
        self._pages:     dict[str, ctk.CTkFrame]   = {}
        self._nav_btns:  dict[str, ctk.CTkFrame]   = {}   # key → row frame
        self._accents:   dict[str, ctk.CTkFrame]   = {}   # key → accent strip
        self._nav_labels: dict[str, ctk.CTkLabel]  = {}   # key → label
        self._active_page = ""

        self._build_layout()
        self._bind_shortcuts()
        self._navigate("home")
        self._poll_status()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build_layout(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_content()

    def _build_sidebar(self) -> None:
        sidebar = ctk.CTkFrame(self, width=236, corner_radius=0,
                               fg_color="#161b22",
                               border_width=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        sidebar.grid_columnconfigure(0, weight=1)
        sidebar.grid_rowconfigure(2, weight=1)

        # ── Logo ─────────────────────────────────────────────────────────────
        logo = ctk.CTkFrame(sidebar, fg_color="transparent")
        logo.grid(row=0, column=0, padx=20, pady=(24, 16), sticky="ew")

        logo_inner = ctk.CTkFrame(logo, fg_color="transparent")
        logo_inner.pack(anchor="w")
        ctk.CTkLabel(logo_inner, text="CyberSuite",
                     font=ctk.CTkFont(size=18, weight="bold"),
                     text_color="#e6edf3").pack(side="left")
        ctk.CTkLabel(logo_inner, text=" Pro",
                     font=ctk.CTkFont(size=18),
                     text_color="#58a6ff").pack(side="left")
        ctk.CTkLabel(logo, text="Security Operations Toolkit",
                     font=ctk.CTkFont(size=10),
                     text_color="#7d8590").pack(anchor="w", pady=(2, 0))

        ctk.CTkFrame(sidebar, height=1, fg_color="#21262d").grid(
            row=1, column=0, sticky="ew", padx=0)

        # ── Navigation ────────────────────────────────────────────────────────
        nav_scroll = ctk.CTkScrollableFrame(
            sidebar, fg_color="transparent",
            scrollbar_button_color="#30363d",
            scrollbar_button_hover_color="#484f58")
        nav_scroll.grid(row=2, column=0, sticky="nsew", padx=0, pady=(8, 0))
        nav_scroll.grid_columnconfigure(0, weight=1)

        for section, items in _NAV:
            if section:
                ctk.CTkLabel(nav_scroll, text=section,
                             font=ctk.CTkFont(size=9, weight="bold"),
                             text_color="#484f58"
                             ).pack(anchor="w", padx=20, pady=(14, 3))

            for label, key in items:
                self._make_nav_item(nav_scroll, label, key)

        # ── Status bar ────────────────────────────────────────────────────────
        ctk.CTkFrame(sidebar, height=1, fg_color="#21262d").grid(
            row=3, column=0, sticky="ew")

        status = ctk.CTkFrame(sidebar, fg_color="transparent")
        status.grid(row=4, column=0, padx=20, pady=12, sticky="ew")

        self._status_dot = ctk.CTkLabel(status, text="●",
                                         font=ctk.CTkFont(size=9),
                                         text_color="#3fb950")
        self._status_dot.pack(side="left")
        self._status_text = ctk.CTkLabel(status, text="Ready",
                                          font=ctk.CTkFont(size=11),
                                          text_color="#7d8590",
                                          anchor="w")
        self._status_text.pack(side="left", padx=(6, 0))

        ctk.CTkLabel(sidebar, text="boclaes102-eng",
                     font=ctk.CTkFont(size=9),
                     text_color="#484f58"
                     ).grid(row=5, column=0, padx=20, pady=(0, 14), sticky="sw")

    def _make_nav_item(self, parent: ctk.CTkFrame,
                       label: str, key: str) -> None:
        """Create a nav row: 3px accent strip + label button."""
        row = ctk.CTkFrame(parent, fg_color="transparent", height=34)
        row.pack(fill="x", pady=1)
        row.pack_propagate(False)

        accent = ctk.CTkFrame(row, width=3, fg_color="transparent",
                              corner_radius=0)
        accent.pack(side="left", fill="y")

        btn = ctk.CTkButton(
            row,
            text=label,
            anchor="w",
            fg_color="transparent",
            hover_color="#1c2128",
            text_color="#7d8590",
            font=ctk.CTkFont(size=12),
            height=34,
            corner_radius=4,
            command=lambda k=key: self._navigate(k),
        )
        btn.pack(side="left", fill="x", expand=True, padx=(4, 8))

        self._nav_btns[key]   = row
        self._accents[key]    = accent
        self._nav_labels[key] = btn

    # ── Content area ──────────────────────────────────────────────────────────

    def _build_content(self) -> None:
        content = ctk.CTkFrame(self, fg_color="#0d1117", corner_radius=0)
        content.grid(row=0, column=1, sticky="nsew")
        content.grid_rowconfigure(0, weight=1)
        content.grid_columnconfigure(0, weight=1)

        # Page container
        self._page_container = ctk.CTkFrame(content, fg_color="transparent")
        self._page_container.grid(row=0, column=0, sticky="nsew")

        # Console
        console_outer = ctk.CTkFrame(content, corner_radius=0,
                                     fg_color="#0d1117", height=240)
        console_outer.grid(row=1, column=0, sticky="ew")
        console_outer.grid_propagate(False)
        console_outer.grid_rowconfigure(1, weight=1)
        console_outer.grid_columnconfigure(0, weight=1)

        ctk.CTkFrame(console_outer, height=1, fg_color="#21262d").grid(
            row=0, column=0, sticky="ew")

        # Console toolbar
        con_tb = ctk.CTkFrame(console_outer, fg_color="#161b22",
                              height=34, corner_radius=0)
        con_tb.grid(row=1, column=0, sticky="ew")
        con_tb.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(con_tb, text="  Output Console",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="#58a6ff"
                     ).grid(row=0, column=0, sticky="w", padx=4)

        btn_row = ctk.CTkFrame(con_tb, fg_color="transparent")
        btn_row.grid(row=0, column=1, sticky="e", padx=6)

        ctk.CTkLabel(btn_row, text="Ctrl+L  ·  Esc",
                     text_color="#484f58",
                     font=ctk.CTkFont(size=10)
                     ).pack(side="left", padx=(0, 10), pady=6)

        for text, cmd, color in [
            ("Copy",  self._copy_console, "#21262d"),
            ("Clear", self.clear_console, "#21262d"),
            ("Stop",  self._stop_tool,    "#da3633"),
        ]:
            ctk.CTkButton(btn_row, text=text, width=66, height=24,
                          fg_color=color, hover_color="#30363d",
                          font=ctk.CTkFont(size=10),
                          command=cmd
                          ).pack(side="left", padx=3, pady=5)

        # Console text widget
        self._console = ctk.CTkTextbox(
            console_outer,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color="#010409",
            text_color="#e6edf3",
            corner_radius=0,
            wrap="word",
            state="disabled",
        )
        self._console.grid(row=2, column=0, sticky="nsew")

        self._tw = self._console._textbox
        self._tw.tag_configure("error",   foreground="#f85149")
        self._tw.tag_configure("warning", foreground="#d29922")
        self._tw.tag_configure("success", foreground="#3fb950")
        self._tw.tag_configure("info",    foreground="#58a6ff")
        self._tw.tag_configure("dim",     foreground="#484f58")

        # ── Pages ─────────────────────────────────────────────────────────────
        out = self.append_output
        self._pages["home"]   = HomePage  (self._page_container, navigate_cb=self._navigate)
        self._pages["recon"]  = ReconPage (self._page_container, self._runner, out)
        self._pages["netmap"] = NetMapPage(self._page_container, self._runner, out)
        self._pages["mitm"]   = MITMPage  (self._page_container, self._runner, out)
        self._pages["creds"]  = CredsPage (self._page_container, self._runner, out)
        self._pages["msf"]    = MSFPage   (self._page_container, self._runner, out)
        self._pages["wifi"]   = WiFiPage  (self._page_container, self._runner, out)
        self._pages["ad"]     = ADPage    (self._page_container, self._runner, out)
        self._pages["nids"]   = NIDSPage  (self._page_container, self._runner, out)
        self._pages["pas"]    = PASPage   (self._page_container, self._runner, out)
        self._pages["sma"]    = SMAPage   (self._page_container, self._runner, out)
        self._pages["wat"]    = WATPage   (self._page_container, self._runner, out)
        self._pages["pgn"]    = PGNPage   (self._page_container, self._runner, out)
        self._pages["ceh"]    = CEHPage   (self._page_container, self._runner, out)
        self._pages["report"] = ReportPage(self._page_container, self._runner, out)

    # ── Navigation ────────────────────────────────────────────────────────────

    def _navigate(self, key: str) -> None:
        if key == self._active_page:
            return
        if self._active_page and self._active_page in self._pages:
            self._pages[self._active_page].pack_forget()

        self._pages[key].pack(fill="both", expand=True)
        self._active_page = key

        for k in self._accents:
            if k == key:
                self._accents[k].configure(fg_color="#58a6ff")
                self._nav_labels[k].configure(
                    text_color="#e6edf3", fg_color="#1c2128")
            else:
                self._accents[k].configure(fg_color="transparent")
                self._nav_labels[k].configure(
                    text_color="#7d8590", fg_color="transparent")

    # ── Console ───────────────────────────────────────────────────────────────

    def append_output(self, text: str) -> None:
        tag = self._classify_tag(text)
        def _do() -> None:
            at_bottom = self._tw.yview()[1] >= 0.98
            self._tw.configure(state="normal")
            if tag:
                self._tw.insert("end", text, tag)
            else:
                self._tw.insert("end", text)
            if at_bottom:
                self._tw.see("end")
            self._tw.configure(state="disabled")
        self.after(0, _do)

    @staticmethod
    def _classify_tag(text: str) -> str:
        lower = text.lower()
        for tag, keywords in _TAG_RULES:
            if any(k in lower for k in keywords):
                return tag
        return ""

    def _copy_console(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self._tw.get("1.0", "end"))

    def clear_console(self) -> None:
        self._tw.configure(state="normal")
        self._tw.delete("1.0", "end")
        self._tw.configure(state="disabled")

    def _stop_tool(self) -> None:
        if self._runner.is_running:
            self._runner.stop()

    # ── Status polling ────────────────────────────────────────────────────────

    def _poll_status(self) -> None:
        if self._runner.is_running:
            tool = self._runner.active_tool or "tool"
            self._status_dot.configure(text_color="#d29922")
            self._status_text.configure(text=f"Running  {tool}")
        else:
            self._status_dot.configure(text_color="#3fb950")
            self._status_text.configure(text="Ready")
        self.after(400, self._poll_status)

    # ── Shortcuts ─────────────────────────────────────────────────────────────

    def _bind_shortcuts(self) -> None:
        self.bind_all("<Control-l>", lambda _e: self.clear_console())
        self.bind_all("<Control-L>", lambda _e: self.clear_console())
        self.bind_all("<Escape>",    lambda _e: self._stop_tool())
