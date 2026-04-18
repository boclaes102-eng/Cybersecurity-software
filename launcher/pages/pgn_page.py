"""Payload Generator launcher page."""
from __future__ import annotations

import sys
import threading
from typing import Callable

import customtkinter as ctk

from ..utils.paths import PGN_DIR
from ..utils.runner import ToolRunner


class PGNPage(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkFrame, runner: ToolRunner,
                 output_cb: Callable[[str], None]) -> None:
        super().__init__(master, fg_color="transparent")
        self._runner = runner
        self._out    = output_cb
        self._build()

    # ------------------------------------------------------------------
    def _build(self) -> None:
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(24, 4))
        ctk.CTkLabel(hdr, text="Payload Generator",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(hdr,
                     text="Reverse shells  ·  Bind shells  ·  Web shells  ·  Encoder  ·  TCP listener",
                     text_color="gray", font=ctk.CTkFont(size=12)).pack(anchor="w")

        self._tabs = ctk.CTkTabview(self)
        self._tabs.pack(fill="both", expand=True, padx=24, pady=(8, 0))

        self._build_reverse_tab(self._tabs.add("Reverse Shell"))
        self._build_bind_tab(self._tabs.add("Bind Shell"))
        self._build_webshell_tab(self._tabs.add("Web Shell"))
        self._build_encoder_tab(self._tabs.add("Encoder"))
        self._build_listener_tab(self._tabs.add("Listener"))

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=24, pady=12)
        self._run_btn = ctk.CTkButton(
            btn_row, text="Generate / Start",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#238636", hover_color="#2ea043",
            height=42, command=self._run,
        )
        self._run_btn.pack(side="right")

    # ── Tab builders ───────────────────────────────────────────────────

    def _build_reverse_tab(self, tab: ctk.CTkFrame) -> None:
        tab.grid_columnconfigure(1, weight=1)
        row = 0

        ctk.CTkLabel(tab, text="LHOST (your IP)", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._rev_lhost = ctk.StringVar(value="10.10.10.10")
        ctk.CTkEntry(tab, textvariable=self._rev_lhost,
                     placeholder_text="Attacker IP address").grid(
            row=row, column=1, sticky="w", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="LPORT", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._rev_lport = ctk.StringVar(value="4444")
        ctk.CTkEntry(tab, textvariable=self._rev_lport, width=100).grid(
            row=row, column=1, sticky="w", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="Language", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._rev_lang = ctk.StringVar(value="bash")
        ctk.CTkComboBox(tab, variable=self._rev_lang,
                        values=["bash", "bash_196", "python", "python_windows",
                                "netcat", "netcat_mkfifo", "powershell",
                                "php", "ruby", "perl", "java"],
                        state="readonly").grid(row=row, column=1, sticky="w", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="All variants", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=6)
        self._rev_all = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(tab, text="Print all reverse shell languages at once",
                        variable=self._rev_all).grid(
            row=row, column=1, sticky="w", pady=6)

    def _build_bind_tab(self, tab: ctk.CTkFrame) -> None:
        tab.grid_columnconfigure(1, weight=1)
        row = 0

        ctk.CTkLabel(tab, text="LPORT (target)", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._bind_lport = ctk.StringVar(value="4444")
        ctk.CTkEntry(tab, textvariable=self._bind_lport, width=100).grid(
            row=row, column=1, sticky="w", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="Language", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._bind_lang = ctk.StringVar(value="netcat")
        ctk.CTkComboBox(tab, variable=self._bind_lang,
                        values=["python", "netcat", "bash", "powershell"],
                        state="readonly").grid(row=row, column=1, sticky="w", pady=10)
        row += 1

        note = ctk.CTkFrame(tab, fg_color="#1c2128", corner_radius=6)
        note.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(8, 4))
        ctk.CTkLabel(note,
                     text="  Run on the target — then connect with:  nc <target-ip> <port>",
                     text_color="#8b949e", font=ctk.CTkFont(size=11), anchor="w").pack(
            padx=12, pady=6, anchor="w")

    def _build_webshell_tab(self, tab: ctk.CTkFrame) -> None:
        tab.grid_columnconfigure(1, weight=1)
        row = 0

        ctk.CTkLabel(tab, text="Shell type", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._web_type = ctk.StringVar(value="php_simple")
        ctk.CTkComboBox(tab, variable=self._web_type,
                        values=["php_simple", "php_passthru", "php_eval",
                                "php_full", "asp", "aspx", "jsp"],
                        state="readonly").grid(row=row, column=1, sticky="w", pady=10)
        row += 1

        note = ctk.CTkFrame(tab, fg_color="#1c2128", corner_radius=6)
        note.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(8, 4))
        ctk.CTkLabel(note,
                     text="  Upload the generated snippet and call it with ?cmd=<command>",
                     text_color="#8b949e", font=ctk.CTkFont(size=11), anchor="w").pack(
            padx=12, pady=6, anchor="w")

    def _build_encoder_tab(self, tab: ctk.CTkFrame) -> None:
        tab.grid_columnconfigure(1, weight=1)
        row = 0

        ctk.CTkLabel(tab, text="Payload", anchor="e").grid(
            row=row, column=0, sticky="ne", padx=(0, 12), pady=10)
        self._enc_input = ctk.CTkTextbox(tab, height=80,
                                          font=ctk.CTkFont(family="Consolas", size=12))
        self._enc_input.grid(row=row, column=1, sticky="ew", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="Format", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._enc_fmt = ctk.StringVar(value="base64")
        ctk.CTkComboBox(tab, variable=self._enc_fmt,
                        values=["base64", "url", "hex", "powershell"],
                        state="readonly").grid(row=row, column=1, sticky="w", pady=10)

    def _build_listener_tab(self, tab: ctk.CTkFrame) -> None:
        tab.grid_columnconfigure(1, weight=1)
        row = 0

        ctk.CTkLabel(tab, text="Port", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._lst_port = ctk.StringVar(value="4444")
        ctk.CTkEntry(tab, textvariable=self._lst_port, width=100).grid(
            row=row, column=1, sticky="w", pady=10)
        row += 1

        note = ctk.CTkFrame(tab, fg_color="#1c2128", corner_radius=6)
        note.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(8, 4))
        ctk.CTkLabel(note,
                     text="  Opens a TCP socket and waits for an incoming reverse shell connection.",
                     text_color="#8b949e", font=ctk.CTkFont(size=11), anchor="w").pack(
            padx=12, pady=6, anchor="w")

    # ── Run ────────────────────────────────────────────────────────────

    def _ensure_path(self) -> None:
        pgn_str = str(PGN_DIR)
        if pgn_str not in sys.path:
            sys.path.insert(0, pgn_str)

    def _run(self) -> None:
        if self._runner.is_running:
            self._runner.stop()
            self._run_btn.configure(text="Generate / Start",
                                    fg_color="#238636", hover_color="#2ea043")
            return

        tab = self._tabs.get()
        self._ensure_path()

        if tab == "Reverse Shell":
            self._gen_reverse()
        elif tab == "Bind Shell":
            self._gen_bind()
        elif tab == "Web Shell":
            self._gen_webshell()
        elif tab == "Encoder":
            self._encode()
        elif tab == "Listener":
            self._start_listener()

    def _gen_reverse(self) -> None:
        from pgn.shells import generate_reverse, generate_reverse as _rev, REVERSE_LANGUAGES
        lhost = self._rev_lhost.get().strip()
        lport_str = self._rev_lport.get().strip()
        lang  = self._rev_lang.get()
        all_v = self._rev_all.get()

        if not lhost:
            self._out("[ERROR] Enter your LHOST.\n")
            return
        try:
            lport = int(lport_str)
        except ValueError:
            self._out("[ERROR] LPORT must be a number.\n")
            return

        self._out(f"\n{'='*60}\n")
        if all_v:
            self._out(f"  All Reverse Shells — {lhost}:{lport}\n{'='*60}\n\n")
            for l in REVERSE_LANGUAGES:
                try:
                    p = generate_reverse(l, lhost, lport)
                    self._out(f"--- {l.upper()} ---\n{p.content}\n\n")
                except Exception as exc:
                    self._out(f"[!] {l}: {exc}\n")
        else:
            p = generate_reverse(lang, lhost, lport)
            self._out(f"  Reverse Shell — {lang.upper()}  |  {lhost}:{lport}\n{'='*60}\n\n")
            self._out(f"{p.content}\n\n")

    def _gen_bind(self) -> None:
        from pgn.shells import generate_bind
        lang = self._bind_lang.get()
        try:
            lport = int(self._bind_lport.get().strip())
        except ValueError:
            self._out("[ERROR] LPORT must be a number.\n")
            return
        p = generate_bind(lang, lport)
        self._out(f"\n{'='*60}\n  Bind Shell — {lang.upper()}  |  port {lport}\n{'='*60}\n\n")
        self._out(f"{p.content}\n\n")
        self._out(f"[*] Connect with:  nc <target-ip> {lport}\n")

    def _gen_webshell(self) -> None:
        from pgn.shells import generate_webshell
        shell_type = self._web_type.get()
        p = generate_webshell(shell_type)
        self._out(f"\n{'='*60}\n  Web Shell — {shell_type.upper()}\n{'='*60}\n\n")
        self._out(f"{p.content}\n\n")
        self._out("[*] Upload and call with ?cmd=<command>\n")

    def _encode(self) -> None:
        from pgn.encoder import encode
        payload = self._enc_input.get("1.0", "end").strip()
        fmt = self._enc_fmt.get()
        if not payload:
            self._out("[ERROR] Enter a payload to encode.\n")
            return
        result = encode(payload, fmt)
        self._out(f"\n{'='*60}\n  {fmt.upper()} Encoded\n{'='*60}\n\n")
        self._out(f"{result}\n\n")
        if fmt == "powershell":
            self._out(f"[*] Run with:  powershell -EncodedCommand {result}\n")

    def _start_listener(self) -> None:
        try:
            port = int(self._lst_port.get().strip())
        except ValueError:
            self._out("[ERROR] Port must be a number.\n")
            return

        self._run_btn.configure(text="Stop Listener",
                                fg_color="#da3633", hover_color="#b91c1c")
        self._out(f"\n{'='*60}\nPGN  [TCP Listener]  port {port}\n{'='*60}\n")

        def task() -> int:
            from pgn.listener import listen
            listen(port, self._runner.stop_event, self._out)
            return 0

        def on_done(code: int) -> None:
            self.after(0, lambda: self._run_btn.configure(
                text="Generate / Start", fg_color="#238636", hover_color="#2ea043"))
            self._out(f"\n[Finished Listener — exit code {code}]\n")

        self._runner.run(task, done_cb=on_done,
                         output_cb=self._out, tool_name="PGN/Listener")
