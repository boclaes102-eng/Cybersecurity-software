"""
CyberSuite Pro — main application window.

Layout
──────
┌────────────┬───────────────────────────────────────────────┐
│  Sidebar   │  Page frame (Home / NIDS / PAS / SMA)         │
│  220 px    │                                               │
│            ├───────────────────────────────────────────────┤
│  Status    │  Output console  (260 px tall)                │
└────────────┴───────────────────────────────────────────────┘

Keyboard shortcuts
──────────────────
  Ctrl+L   — clear output console
  Escape   — stop running tool
"""
from __future__ import annotations

import customtkinter as ctk

from .pages.home_page import HomePage
from .pages.nids_page import NIDSPage
from .pages.pas_page  import PASPage
from .pages.sma_page  import SMAPage
from .pages.wat_page  import WATPage
from .pages.pgn_page  import PGNPage
from .pages.ceh_page   import CEHPage
from .pages.recon_page import ReconPage
from .utils.runner import ToolRunner

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

_NAV = [
    ("Home",  "home"),
    ("Recon", "recon"),
    ("NIDS",  "nids"),
    ("PAS",   "pas"),
    ("SMA",   "sma"),
    ("WAT",   "wat"),
    ("PGN",   "pgn"),
    ("CEH",   "ceh"),
]

# Output-line colour classification
_TAG_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("error",   ("[error]", "error:", "traceback", "exception:", "[stopped")),
    ("warning", ("[warning]", "warning:", "warn:")),
    ("success", ("[finished", "analysis complete", "done]", "clean")),
    ("info",    ("=" * 10, "starting")),
]


class App(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("CyberSuite Pro — Security Toolkit")
        self.geometry("1280x820")
        self.minsize(960, 640)
        self.after(0, lambda: self.state("zoomed"))

        self._runner = ToolRunner()
        self._pages: dict[str, ctk.CTkFrame] = {}
        self._nav_btns: dict[str, ctk.CTkButton] = {}
        self._active_page = ""

        self._build_layout()
        self._bind_shortcuts()
        self._navigate("home")
        self._poll_status()          # start periodic status refresh

    # ──────────────────────────────────────────────────────────────────────
    def _build_layout(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ── Sidebar ───────────────────────────────────────────────────────
        sidebar = ctk.CTkFrame(self, width=224, corner_radius=0, fg_color="#161b22")
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        sidebar.grid_columnconfigure(0, weight=1)
        sidebar.grid_rowconfigure(3, weight=1)   # spacer row

        # Logo
        logo = ctk.CTkFrame(sidebar, fg_color="transparent")
        logo.grid(row=0, column=0, padx=16, pady=(24, 8), sticky="ew")
        ctk.CTkLabel(logo, text="CyberSuite",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(logo, text="Pro Edition",
                     text_color="gray", font=ctk.CTkFont(size=11)).pack(anchor="w")

        ctk.CTkFrame(sidebar, height=1, fg_color="#30363d").grid(
            row=1, column=0, padx=12, pady=(0, 8), sticky="ew")

        # Nav buttons
        nav_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        nav_frame.grid(row=2, column=0, sticky="ew", padx=8)

        for label, key in _NAV:
            btn = ctk.CTkButton(
                nav_frame,
                text=label,
                anchor="w",
                fg_color="transparent",
                hover_color="#21262d",
                text_color="gray70",
                font=ctk.CTkFont(size=14),
                height=42,
                command=lambda k=key: self._navigate(k),
            )
            btn.pack(fill="x", pady=2)
            self._nav_btns[key] = btn

        # Spacer
        ctk.CTkFrame(sidebar, fg_color="transparent").grid(
            row=3, column=0, sticky="nsew")

        # Status indicator
        status_frame = ctk.CTkFrame(sidebar, fg_color="#0d1117", corner_radius=8)
        status_frame.grid(row=4, column=0, padx=12, pady=8, sticky="ew")
        self._status_dot  = ctk.CTkLabel(status_frame, text="●",
                                          font=ctk.CTkFont(size=10))
        self._status_dot.pack(side="left", padx=(10, 4), pady=8)
        self._status_text = ctk.CTkLabel(status_frame, text="Ready",
                                          font=ctk.CTkFont(size=12), anchor="w")
        self._status_text.pack(side="left", pady=8, fill="x", expand=True)

        # Version footer
        ctk.CTkLabel(sidebar, text="github.com/boclaes",
                     text_color="#484f58", font=ctk.CTkFont(size=10)).grid(
            row=5, column=0, padx=12, pady=(0, 12), sticky="sw")

        # ── Main content area ─────────────────────────────────────────────
        content = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        content.grid(row=0, column=1, sticky="nsew")
        content.grid_rowconfigure(0, weight=1)
        content.grid_columnconfigure(0, weight=1)

        # Page container
        self._page_container = ctk.CTkFrame(content, fg_color="transparent")
        self._page_container.grid(row=0, column=0, sticky="nsew")

        # ── Output console ────────────────────────────────────────────────
        console_outer = ctk.CTkFrame(content, corner_radius=0, fg_color="#0d1117", height=270)
        console_outer.grid(row=1, column=0, sticky="ew")
        console_outer.grid_propagate(False)
        console_outer.grid_rowconfigure(1, weight=1)
        console_outer.grid_columnconfigure(0, weight=1)

        # Toolbar
        toolbar = ctk.CTkFrame(console_outer, fg_color="#161b22", height=36, corner_radius=0)
        toolbar.grid(row=0, column=0, sticky="ew")
        toolbar.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(toolbar, text="  Output Console",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#58a6ff").grid(row=0, column=0, sticky="w", padx=4)

        btn_row = ctk.CTkFrame(toolbar, fg_color="transparent")
        btn_row.grid(row=0, column=1, sticky="e", padx=6)

        ctk.CTkLabel(btn_row, text="Ctrl+L = clear  |  Esc = stop",
                     text_color="#484f58", font=ctk.CTkFont(size=10)).pack(
            side="left", padx=(0, 12), pady=8)

        ctk.CTkButton(btn_row, text="Copy", width=70, height=26,
                      fg_color="#21262d", hover_color="#30363d",
                      command=self._copy_console).pack(side="left", padx=4, pady=5)
        ctk.CTkButton(btn_row, text="Clear", width=70, height=26,
                      fg_color="#21262d", hover_color="#30363d",
                      command=self.clear_console).pack(side="left", padx=4, pady=5)
        ctk.CTkButton(btn_row, text="Stop", width=80, height=26,
                      fg_color="#da3633", hover_color="#b91c1c",
                      command=self._stop_tool).pack(side="left", padx=(0, 4), pady=5)

        # Text widget — we use the inner tk.Text for tag-based colour
        self._console = ctk.CTkTextbox(
            console_outer,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color="#010409",
            text_color="#c9d1d9",
            corner_radius=0,
            wrap="word",
            state="disabled",
        )
        self._console.grid(row=1, column=0, sticky="nsew")

        # Configure colour tags on the underlying tk.Text widget
        self._tw = self._console._textbox
        self._tw.tag_configure("error",   foreground="#f85149")
        self._tw.tag_configure("warning", foreground="#d29922")
        self._tw.tag_configure("success", foreground="#3fb950")
        self._tw.tag_configure("info",    foreground="#58a6ff")
        self._tw.tag_configure("dim",     foreground="#484f58")
        self._tw.tag_configure("header",  foreground="#58a6ff", font="Consolas 12 bold")

        # ── Build pages ───────────────────────────────────────────────────
        out = self.append_output
        self._pages["home"]  = HomePage(self._page_container, navigate_cb=self._navigate)
        self._pages["recon"] = ReconPage(self._page_container, self._runner, out)
        self._pages["nids"]  = NIDSPage(self._page_container, self._runner, out)
        self._pages["pas"]  = PASPage (self._page_container, self._runner, out)
        self._pages["sma"]  = SMAPage (self._page_container, self._runner, out)
        self._pages["wat"]  = WATPage (self._page_container, self._runner, out)
        self._pages["pgn"]  = PGNPage (self._page_container, self._runner, out)
        self._pages["ceh"]  = CEHPage (self._page_container, self._runner, out)

    # ──────────────────────────────────────────────────────────────────────
    def _navigate(self, key: str) -> None:
        if key == self._active_page:
            return
        if self._active_page and self._active_page in self._pages:
            self._pages[self._active_page].pack_forget()
        self._pages[key].pack(fill="both", expand=True)
        self._active_page = key

        for k, btn in self._nav_btns.items():
            if k == key:
                btn.configure(fg_color="#1f6aa5", text_color="white")
            else:
                btn.configure(fg_color="transparent", text_color="gray70")

    # ──────────────────────────────────────────────────────────────────────
    def append_output(self, text: str) -> None:
        """Thread-safe, colour-tagged append to the output console."""
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

    # ──────────────────────────────────────────────────────────────────────
    def _copy_console(self) -> None:
        text = self._tw.get("1.0", "end")
        self.clipboard_clear()
        self.clipboard_append(text)

    def clear_console(self) -> None:
        self._tw.configure(state="normal")
        self._tw.delete("1.0", "end")
        self._tw.configure(state="disabled")

    def _stop_tool(self) -> None:
        if self._runner.is_running:
            self._runner.stop()

    # ──────────────────────────────────────────────────────────────────────
    def _poll_status(self) -> None:
        """Update sidebar status every 400 ms."""
        if self._runner.is_running:
            tool = self._runner.active_tool or "tool"
            self._status_dot.configure(text_color="#d29922")
            self._status_text.configure(text=f"Running {tool}…")
        else:
            self._status_dot.configure(text_color="#3fb950")
            self._status_text.configure(text="Ready")
        self.after(400, self._poll_status)

    # ──────────────────────────────────────────────────────────────────────
    def _bind_shortcuts(self) -> None:
        self.bind_all("<Control-l>", lambda _e: self.clear_console())
        self.bind_all("<Control-L>", lambda _e: self.clear_console())
        self.bind_all("<Escape>",    lambda _e: self._stop_tool())
