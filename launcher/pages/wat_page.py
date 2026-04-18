"""Web Application Tester launcher page."""
from __future__ import annotations

import sys
import threading
from tkinter import filedialog
from typing import Callable

import customtkinter as ctk

from ..utils.paths import WAT_DIR
from ..utils.runner import ToolRunner


class WATPage(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkFrame, runner: ToolRunner,
                 output_cb: Callable[[str], None]) -> None:
        super().__init__(master, fg_color="transparent")
        self._runner   = runner
        self._out      = output_cb
        self._build()

    # ------------------------------------------------------------------
    def _build(self) -> None:
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(24, 4))
        ctk.CTkLabel(hdr, text="Web Application Tester",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(hdr,
                     text="Dir brute-force  ·  Header analysis  ·  SQLi fuzzing  ·  XSS detection",
                     text_color="gray", font=ctk.CTkFont(size=12)).pack(anchor="w")

        self._tabs = ctk.CTkTabview(self)
        self._tabs.pack(fill="both", expand=True, padx=24, pady=(8, 0))

        self._build_dirscan_tab(self._tabs.add("Dir Scan"))
        self._build_headers_tab(self._tabs.add("Headers"))
        self._build_sqli_tab(self._tabs.add("SQLi"))
        self._build_xss_tab(self._tabs.add("XSS"))

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=24, pady=12)
        self._run_btn = ctk.CTkButton(
            btn_row, text="Run",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#238636", hover_color="#2ea043",
            height=42, command=self._run,
        )
        self._run_btn.pack(side="right")

        self._progress = ctk.CTkProgressBar(self, mode="indeterminate",
                                             progress_color="#1f6aa5")
        self._progress.pack(fill="x", padx=24, pady=(0, 6))
        self._progress.pack_forget()

    # ── Tab builders ───────────────────────────────────────────────────

    def _build_dirscan_tab(self, tab: ctk.CTkFrame) -> None:
        tab.grid_columnconfigure(1, weight=1)
        row = 0

        ctk.CTkLabel(tab, text="Target URL", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._ds_url = ctk.StringVar(value="http://")
        ctk.CTkEntry(tab, textvariable=self._ds_url,
                     placeholder_text="http://target.com").grid(
            row=row, column=1, sticky="ew", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="Wordlist", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        wl_row = ctk.CTkFrame(tab, fg_color="transparent")
        wl_row.grid(row=row, column=1, sticky="ew", pady=10)
        wl_row.grid_columnconfigure(0, weight=1)
        self._ds_wordlist = ctk.StringVar(value="")
        ctk.CTkEntry(wl_row, textvariable=self._ds_wordlist,
                     placeholder_text="Leave blank to use built-in list").grid(
            row=0, column=0, sticky="ew")
        ctk.CTkButton(wl_row, text="Browse…", width=90,
                      command=lambda: self._browse(self._ds_wordlist,
                                                   [("Text", "*.txt"), ("All", "*.*")])).grid(
            row=0, column=1, padx=(8, 0))
        row += 1

        ctk.CTkLabel(tab, text="Extensions", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._ds_ext = ctk.StringVar(value=".php .html .txt .bak")
        ctk.CTkEntry(tab, textvariable=self._ds_ext,
                     placeholder_text="Space-separated: .php .html .txt").grid(
            row=row, column=1, sticky="ew", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="Threads", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._ds_threads = ctk.StringVar(value="10")
        ctk.CTkEntry(tab, textvariable=self._ds_threads, width=80).grid(
            row=row, column=1, sticky="w", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="Timeout (s)", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._ds_timeout = ctk.StringVar(value="5")
        ctk.CTkEntry(tab, textvariable=self._ds_timeout, width=80).grid(
            row=row, column=1, sticky="w", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="Output JSON", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        out_row = ctk.CTkFrame(tab, fg_color="transparent")
        out_row.grid(row=row, column=1, sticky="ew", pady=10)
        out_row.grid_columnconfigure(0, weight=1)
        self._ds_output = ctk.StringVar(value="")
        ctk.CTkEntry(out_row, textvariable=self._ds_output,
                     placeholder_text="Optional — save report as JSON").grid(
            row=0, column=0, sticky="ew")
        ctk.CTkButton(out_row, text="Browse…", width=90,
                      command=lambda: self._save(self._ds_output,
                                                 [("JSON", "*.json"), ("All", "*.*")])).grid(
            row=0, column=1, padx=(8, 0))

    def _build_headers_tab(self, tab: ctk.CTkFrame) -> None:
        tab.grid_columnconfigure(1, weight=1)
        row = 0

        ctk.CTkLabel(tab, text="Target URL", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._hdr_url = ctk.StringVar(value="http://")
        ctk.CTkEntry(tab, textvariable=self._hdr_url,
                     placeholder_text="http://target.com").grid(
            row=row, column=1, sticky="ew", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="Timeout (s)", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._hdr_timeout = ctk.StringVar(value="10")
        ctk.CTkEntry(tab, textvariable=self._hdr_timeout, width=80).grid(
            row=row, column=1, sticky="w", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="Output JSON", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        out_row = ctk.CTkFrame(tab, fg_color="transparent")
        out_row.grid(row=row, column=1, sticky="ew", pady=10)
        out_row.grid_columnconfigure(0, weight=1)
        self._hdr_output = ctk.StringVar(value="")
        ctk.CTkEntry(out_row, textvariable=self._hdr_output,
                     placeholder_text="Optional").grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(out_row, text="Browse…", width=90,
                      command=lambda: self._save(self._hdr_output,
                                                 [("JSON", "*.json"), ("All", "*.*")])).grid(
            row=0, column=1, padx=(8, 0))
        row += 1

        note = ctk.CTkFrame(tab, fg_color="#1c2128", corner_radius=6)
        note.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(8, 4))
        ctk.CTkLabel(note,
                     text="  Checks: HSTS · CSP · X-Frame-Options · X-Content-Type-Options · "
                          "Referrer-Policy · Permissions-Policy · Info-leak headers",
                     text_color="#8b949e", font=ctk.CTkFont(size=11), anchor="w").pack(
            padx=12, pady=6, anchor="w")

    def _build_sqli_tab(self, tab: ctk.CTkFrame) -> None:
        tab.grid_columnconfigure(1, weight=1)
        row = 0

        ctk.CTkLabel(tab, text="Target URL", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._sqli_url = ctk.StringVar(value="http://")
        ctk.CTkEntry(tab, textvariable=self._sqli_url,
                     placeholder_text="http://target.com/page?param=value").grid(
            row=row, column=1, sticky="ew", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="Timeout (s)", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._sqli_timeout = ctk.StringVar(value="10")
        ctk.CTkEntry(tab, textvariable=self._sqli_timeout, width=80).grid(
            row=row, column=1, sticky="w", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="Output JSON", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        out_row = ctk.CTkFrame(tab, fg_color="transparent")
        out_row.grid(row=row, column=1, sticky="ew", pady=10)
        out_row.grid_columnconfigure(0, weight=1)
        self._sqli_output = ctk.StringVar(value="")
        ctk.CTkEntry(out_row, textvariable=self._sqli_output, placeholder_text="Optional").grid(
            row=0, column=0, sticky="ew")
        ctk.CTkButton(out_row, text="Browse…", width=90,
                      command=lambda: self._save(self._sqli_output,
                                                 [("JSON", "*.json"), ("All", "*.*")])).grid(
            row=0, column=1, padx=(8, 0))
        row += 1

        note = ctk.CTkFrame(tab, fg_color="#1c2128", corner_radius=6)
        note.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(8, 4))
        ctk.CTkLabel(note,
                     text="  URL must include GET params (e.g. ?q=test). "
                          "Detects SQL error signatures in responses.",
                     text_color="#8b949e", font=ctk.CTkFont(size=11), anchor="w").pack(
            padx=12, pady=6, anchor="w")

    def _build_xss_tab(self, tab: ctk.CTkFrame) -> None:
        tab.grid_columnconfigure(1, weight=1)
        row = 0

        ctk.CTkLabel(tab, text="Target URL", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._xss_url = ctk.StringVar(value="http://")
        ctk.CTkEntry(tab, textvariable=self._xss_url,
                     placeholder_text="http://target.com/page?name=value").grid(
            row=row, column=1, sticky="ew", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="Timeout (s)", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._xss_timeout = ctk.StringVar(value="10")
        ctk.CTkEntry(tab, textvariable=self._xss_timeout, width=80).grid(
            row=row, column=1, sticky="w", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="Output JSON", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        out_row = ctk.CTkFrame(tab, fg_color="transparent")
        out_row.grid(row=row, column=1, sticky="ew", pady=10)
        out_row.grid_columnconfigure(0, weight=1)
        self._xss_output = ctk.StringVar(value="")
        ctk.CTkEntry(out_row, textvariable=self._xss_output, placeholder_text="Optional").grid(
            row=0, column=0, sticky="ew")
        ctk.CTkButton(out_row, text="Browse…", width=90,
                      command=lambda: self._save(self._xss_output,
                                                 [("JSON", "*.json"), ("All", "*.*")])).grid(
            row=0, column=1, padx=(8, 0))
        row += 1

        note = ctk.CTkFrame(tab, fg_color="#1c2128", corner_radius=6)
        note.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(8, 4))
        ctk.CTkLabel(note,
                     text="  URL must include GET params. "
                          "Checks whether each payload is reflected verbatim in the response.",
                     text_color="#8b949e", font=ctk.CTkFont(size=11), anchor="w").pack(
            padx=12, pady=6, anchor="w")

    # ── Helpers ────────────────────────────────────────────────────────

    def _browse(self, var: ctk.StringVar, ftypes: list) -> None:
        path = filedialog.askopenfilename(filetypes=ftypes)
        if path:
            var.set(path)

    def _save(self, var: ctk.StringVar, ftypes: list) -> None:
        path = filedialog.asksaveasfilename(filetypes=ftypes)
        if path:
            var.set(path)

    # ── Run ────────────────────────────────────────────────────────────

    def _run(self) -> None:
        if self._runner.is_running:
            self._runner.stop()
            return

        tab = self._tabs.get()

        wat_str = str(WAT_DIR)
        if wat_str not in sys.path:
            sys.path.insert(0, wat_str)

        stop = self._runner.stop_event

        if tab == "Dir Scan":
            self._run_dirscan(stop)
        elif tab == "Headers":
            self._run_headers(stop)
        elif tab == "SQLi":
            self._run_sqli(stop)
        elif tab == "XSS":
            self._run_xss(stop)

    def _start_ui(self, label: str) -> None:
        self._run_btn.configure(text=f"Stop {label}", fg_color="#da3633",
                                hover_color="#b91c1c")
        self._progress.pack(fill="x", padx=24, pady=(0, 6))
        self._progress.start()

    def _stop_ui(self, code: int, label: str) -> None:
        self.after(0, lambda: (
            self._run_btn.configure(text="Run", fg_color="#238636",
                                    hover_color="#2ea043"),
            self._progress.stop(),
            self._progress.pack_forget(),
        ))
        self._out(f"\n[Finished {label} — exit code {code}]\n")

    def _run_dirscan(self, stop: threading.Event) -> None:
        url     = self._ds_url.get().strip()
        wl      = self._ds_wordlist.get().strip() or None
        ext     = [e.strip() for e in self._ds_ext.get().split() if e.strip()]
        threads = int(self._ds_threads.get() or "10")
        timeout = float(self._ds_timeout.get() or "5")
        output  = self._ds_output.get().strip() or None

        if not url or url == "http://":
            self._out("[ERROR] Enter a target URL.\n")
            return

        self._out(f"\n{'='*60}\nWAT  [Dir Scan]  {url}\n{'='*60}\n")
        self._start_ui("WAT")

        def task() -> int:
            from wat.dir_scanner import scan
            from wat import reporter as rep
            from wat.models import Finding

            def on_finding(f: Finding) -> None:
                    self._out(f"[{f.severity}] {f.url}  — {f.detail}\n")

            findings = scan(url, wl, ext, threads, timeout, stop,
                            on_finding, self._out)
            self._out(f"\n[+] Found {len(findings)} interesting paths\n")
            if output and findings:
                rep.save(findings, output)
                self._out(f"[+] Report saved → {output}\n")
            return 0

        self._runner.run(task, done_cb=lambda c: self._stop_ui(c, "Dir Scan"),
                         output_cb=self._out, tool_name="WAT/DirScan")

    def _run_headers(self, stop: threading.Event) -> None:
        url     = self._hdr_url.get().strip()
        timeout = float(self._hdr_timeout.get() or "10")
        output  = self._hdr_output.get().strip() or None

        if not url or url == "http://":
            self._out("[ERROR] Enter a target URL.\n")
            return

        self._out(f"\n{'='*60}\nWAT  [Header Analysis]  {url}\n{'='*60}\n")
        self._start_ui("WAT")

        def task() -> int:
            from wat.header_analyzer import analyze
            from wat import reporter as rep
            from wat.models import Finding

            def on_finding(f: Finding) -> None:
                if f.type == "header_present":
                    self._out(f"  [OK]  {f.detail}\n")
                elif f.type == "header_missing":
                    self._out(f"[{f.severity}] MISSING  {f.detail}\n")
                elif f.type == "header_weak":
                    self._out(f"[LOW] INFO LEAK  {f.detail}\n")
                else:
                    self._out(f"  {f.detail}\n")

            findings = analyze(url, timeout, on_finding)
            if output:
                rep.save(findings, output)
                self._out(f"\n[+] Report saved → {output}\n")
            return 0

        self._runner.run(task, done_cb=lambda c: self._stop_ui(c, "Headers"),
                         output_cb=self._out, tool_name="WAT/Headers")

    def _run_sqli(self, stop: threading.Event) -> None:
        url     = self._sqli_url.get().strip()
        timeout = float(self._sqli_timeout.get() or "10")
        output  = self._sqli_output.get().strip() or None

        if not url or url == "http://":
            self._out("[ERROR] Enter a target URL with GET parameters.\n")
            return

        self._out(f"\n{'='*60}\nWAT  [SQLi Fuzzer]  {url}\n{'='*60}\n")
        self._start_ui("WAT")

        def task() -> int:
            from wat.sqli_fuzzer import fuzz
            from wat import reporter as rep
            from wat.models import Finding

            def on_finding(f: Finding) -> None:
                self._out(f"[CRITICAL] SQLi HIT — {f.url}\n   {f.detail}\n\n")

            findings = fuzz(url, timeout, stop, on_finding, self._out)
            self._out(f"\n[+] {len(findings)} SQLi hit(s) found\n")
            if output and findings:
                rep.save(findings, output)
                self._out(f"[+] Report saved → {output}\n")
            return 0

        self._runner.run(task, done_cb=lambda c: self._stop_ui(c, "SQLi"),
                         output_cb=self._out, tool_name="WAT/SQLi")

    def _run_xss(self, stop: threading.Event) -> None:
        url     = self._xss_url.get().strip()
        timeout = float(self._xss_timeout.get() or "10")
        output  = self._xss_output.get().strip() or None

        if not url or url == "http://":
            self._out("[ERROR] Enter a target URL with GET parameters.\n")
            return

        self._out(f"\n{'='*60}\nWAT  [XSS Fuzzer]  {url}\n{'='*60}\n")
        self._start_ui("WAT")

        def task() -> int:
            from wat.xss_fuzzer import fuzz
            from wat import reporter as rep
            from wat.models import Finding

            def on_finding(f: Finding) -> None:
                self._out(f"[HIGH] XSS HIT — {f.url}\n   {f.detail}\n\n")

            findings = fuzz(url, timeout, stop, on_finding, self._out)
            self._out(f"\n[+] {len(findings)} XSS hit(s) found\n")
            if output and findings:
                rep.save(findings, output)
                self._out(f"[+] Report saved → {output}\n")
            return 0

        self._runner.run(task, done_cb=lambda c: self._stop_ui(c, "XSS"),
                         output_cb=self._out, tool_name="WAT/XSS")
