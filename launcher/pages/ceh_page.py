"""CVE & Exploit Helper launcher page."""
from __future__ import annotations

import sys
from typing import Callable

import customtkinter as ctk

from ..utils.paths import CEH_DIR
from ..utils.runner import ToolRunner


class CEHPage(ctk.CTkFrame):
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
        ctk.CTkLabel(hdr, text="CVE & Exploit Helper",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(hdr,
                     text="NVD CVE search  ·  CVE lookup  ·  ExploitDB search",
                     text_color="gray", font=ctk.CTkFont(size=12)).pack(anchor="w")

        self._tabs = ctk.CTkTabview(self)
        self._tabs.pack(fill="both", expand=True, padx=24, pady=(8, 0))

        self._build_search_tab(self._tabs.add("CVE Search"))
        self._build_lookup_tab(self._tabs.add("CVE Lookup"))
        self._build_exploits_tab(self._tabs.add("Exploits"))

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=24, pady=12)
        self._run_btn = ctk.CTkButton(
            btn_row, text="Search",
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

    def _build_search_tab(self, tab: ctk.CTkFrame) -> None:
        tab.grid_columnconfigure(1, weight=1)
        row = 0

        ctk.CTkLabel(tab, text="Keyword", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._srch_kw = ctk.StringVar(value="")
        ctk.CTkEntry(tab, textvariable=self._srch_kw,
                     placeholder_text="e.g.  log4j  or  apache  or  OpenSSL 3.0").grid(
            row=row, column=1, sticky="ew", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="Max results", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._srch_limit = ctk.StringVar(value="20")
        ctk.CTkEntry(tab, textvariable=self._srch_limit, width=80).grid(
            row=row, column=1, sticky="w", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="NVD API Key", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._srch_apikey = ctk.StringVar(value="")
        ctk.CTkEntry(tab, textvariable=self._srch_apikey, show="*",
                     placeholder_text="Optional — raises rate limit (env: NVD_API_KEY)").grid(
            row=row, column=1, sticky="ew", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="Output JSON", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._srch_output = ctk.StringVar(value="")
        ctk.CTkEntry(tab, textvariable=self._srch_output,
                     placeholder_text="Optional — save JSON report").grid(
            row=row, column=1, sticky="ew", pady=10)
        row += 1

        note = ctk.CTkFrame(tab, fg_color="#1c2128", corner_radius=6)
        note.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(8, 4))
        ctk.CTkLabel(note,
                     text="  Queries the NVD API v2. Results sorted by CVSS score (highest first).",
                     text_color="#8b949e", font=ctk.CTkFont(size=11), anchor="w").pack(
            padx=12, pady=6, anchor="w")

    def _build_lookup_tab(self, tab: ctk.CTkFrame) -> None:
        tab.grid_columnconfigure(1, weight=1)
        row = 0

        ctk.CTkLabel(tab, text="CVE ID", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._lkp_id = ctk.StringVar(value="")
        ctk.CTkEntry(tab, textvariable=self._lkp_id,
                     placeholder_text="e.g.  CVE-2021-44228").grid(
            row=row, column=1, sticky="ew", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="NVD API Key", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._lkp_apikey = ctk.StringVar(value="")
        ctk.CTkEntry(tab, textvariable=self._lkp_apikey, show="*",
                     placeholder_text="Optional").grid(
            row=row, column=1, sticky="ew", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="Output JSON", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._lkp_output = ctk.StringVar(value="")
        ctk.CTkEntry(tab, textvariable=self._lkp_output,
                     placeholder_text="Optional").grid(
            row=row, column=1, sticky="ew", pady=10)

    def _build_exploits_tab(self, tab: ctk.CTkFrame) -> None:
        tab.grid_columnconfigure(1, weight=1)
        row = 0

        ctk.CTkLabel(tab, text="Query", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._exp_query = ctk.StringVar(value="")
        ctk.CTkEntry(tab, textvariable=self._exp_query,
                     placeholder_text="e.g.  Apache 2.4  or  CVE-2021-44228").grid(
            row=row, column=1, sticky="ew", pady=10)
        row += 1

        ctk.CTkLabel(tab, text="Output JSON", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._exp_output = ctk.StringVar(value="")
        ctk.CTkEntry(tab, textvariable=self._exp_output,
                     placeholder_text="Optional").grid(
            row=row, column=1, sticky="ew", pady=10)
        row += 1

        note = ctk.CTkFrame(tab, fg_color="#1c2128", corner_radius=6)
        note.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(8, 4))
        ctk.CTkLabel(note,
                     text="  Uses searchsploit if installed, otherwise scrapes exploit-db.com.",
                     text_color="#8b949e", font=ctk.CTkFont(size=11), anchor="w").pack(
            padx=12, pady=6, anchor="w")

    # ── Run ────────────────────────────────────────────────────────────

    def _ensure_path(self) -> None:
        ceh_str = str(CEH_DIR)
        if ceh_str not in sys.path:
            sys.path.insert(0, ceh_str)

    def _start_ui(self) -> None:
        self._run_btn.configure(text="Stop", fg_color="#da3633", hover_color="#b91c1c")
        self._progress.pack(fill="x", padx=24, pady=(0, 6))
        self._progress.start()

    def _stop_ui(self, code: int, label: str) -> None:
        self.after(0, lambda: (
            self._run_btn.configure(text="Search", fg_color="#238636",
                                    hover_color="#2ea043"),
            self._progress.stop(),
            self._progress.pack_forget(),
        ))
        self._out(f"\n[Finished {label} — exit code {code}]\n")

    def _run(self) -> None:
        if self._runner.is_running:
            self._runner.stop()
            return

        tab = self._tabs.get()
        self._ensure_path()

        if tab == "CVE Search":
            self._run_search()
        elif tab == "CVE Lookup":
            self._run_lookup()
        elif tab == "Exploits":
            self._run_exploits()

    def _run_search(self) -> None:
        keyword = self._srch_kw.get().strip()
        if not keyword:
            self._out("[ERROR] Enter a keyword to search.\n")
            return
        try:
            limit = int(self._srch_limit.get() or "20")
        except ValueError:
            limit = 20
        api_key = self._srch_apikey.get().strip() or None
        output  = self._srch_output.get().strip() or None

        self._out(f"\n{'='*60}\nCEH  [CVE Search]  '{keyword}'\n{'='*60}\n")
        self._start_ui()

        def task() -> int:
            from cve import nvd_client, reporter
            from cve.models import CVERecord

            try:
                records = nvd_client.search(keyword, max_results=limit, api_key=api_key)
            except Exception as exc:
                self._out(f"[error] NVD API error: {exc}\n")
                return 1

            if not records:
                self._out("[!] No CVEs found.\n")
                return 0

            for c in records:
                score = f"{c.cvss_score:.1f}" if c.cvss_score else "N/A"
                self._out(f"[{c.severity}]  {c.cve_id}  CVSS {score}\n")
                short = c.description[:130] + "…" if len(c.description) > 130 else c.description
                self._out(f"   {short}\n")
                self._out(f"   Published: {c.published[:10]}\n")
                if c.references:
                    self._out(f"   {c.references[0]}\n")
                self._out("\n")

            self._out(f"[+] {len(records)} CVEs found\n")
            if output:
                reporter.save_cves(records, output)
                self._out(f"[+] Report saved → {output}\n")
            return 0

        self._runner.run(task, done_cb=lambda c: self._stop_ui(c, "CVE Search"),
                         output_cb=self._out, tool_name="CEH/CVESearch")

    def _run_lookup(self) -> None:
        cve_id = self._lkp_id.get().strip().upper()
        if not cve_id:
            self._out("[ERROR] Enter a CVE ID (e.g. CVE-2021-44228).\n")
            return
        api_key = self._lkp_apikey.get().strip() or None
        output  = self._lkp_output.get().strip() or None

        self._out(f"\n{'='*60}\nCEH  [CVE Lookup]  {cve_id}\n{'='*60}\n")
        self._start_ui()

        def task() -> int:
            from cve import nvd_client, reporter

            try:
                record = nvd_client.lookup(cve_id, api_key=api_key)
            except Exception as exc:
                self._out(f"[error] NVD API error: {exc}\n")
                return 1

            if not record:
                self._out(f"[!] {cve_id} not found.\n")
                return 0

            score = f"{record.cvss_score:.1f}" if record.cvss_score else "N/A"
            self._out(f"[{record.severity}]  {record.cve_id}  CVSS {score}\n\n")
            self._out(f"{record.description}\n\n")
            self._out(f"Published: {record.published[:10]}  |  Modified: {record.modified[:10]}\n\n")
            if record.references:
                self._out("References:\n")
                for ref in record.references[:8]:
                    self._out(f"  {ref}\n")

            if output:
                reporter.save_cves([record], output)
                self._out(f"\n[+] Report saved → {output}\n")
            return 0

        self._runner.run(task, done_cb=lambda c: self._stop_ui(c, "CVE Lookup"),
                         output_cb=self._out, tool_name="CEH/CVELookup")

    def _run_exploits(self) -> None:
        query  = self._exp_query.get().strip()
        output = self._exp_output.get().strip() or None
        if not query:
            self._out("[ERROR] Enter a search query.\n")
            return

        self._out(f"\n{'='*60}\nCEH  [Exploits]  '{query}'\n{'='*60}\n")
        self._start_ui()

        def task() -> int:
            from cve import exploitdb, reporter

            records = exploitdb.search(query, self._out)
            if not records:
                self._out("[!] No exploits found.\n")
                return 0

            self._out(f"\n{'='*60}\n")
            for e in records:
                eid = f"EDB-{e.exploit_id}" if e.exploit_id else "EDB-?"
                self._out(f"  [{eid:>10}]  {e.title}\n")
                self._out(f"               {e.platform or 'N/A'}  |  {e.type or 'N/A'}  |  {e.date}\n")
                if e.url:
                    self._out(f"               {e.url}\n")
                self._out("\n")
            self._out(f"[+] {len(records)} exploits found\n")
            if output:
                reporter.save_exploits(records, output)
                self._out(f"[+] Report saved → {output}\n")
            return 0

        self._runner.run(task, done_cb=lambda c: self._stop_ui(c, "Exploits"),
                         output_cb=self._out, tool_name="CEH/Exploits")
