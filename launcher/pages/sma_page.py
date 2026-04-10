"""Static Malware Analyzer page."""
from __future__ import annotations

import importlib.util
import os
import sys
import types
from pathlib import Path
from tkinter import filedialog
from typing import Callable, Optional

import customtkinter as ctk

from ..utils.paths import SMA_DIR
from ..utils.runner import ToolRunner

_sma_module: Optional[types.ModuleType] = None


def _load_sma() -> Optional[types.ModuleType]:
    global _sma_module
    if _sma_module is not None:
        return _sma_module
    main_path = SMA_DIR / "main.py"
    if not main_path.exists():
        return None
    sma_str = str(SMA_DIR)
    if sma_str not in sys.path:
        sys.path.insert(0, sma_str)
    spec = importlib.util.spec_from_file_location("sma_main", str(main_path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["sma_main"] = mod
    try:
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        _sma_module = mod
    except Exception:
        pass
    return _sma_module


def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f} TB"


class SMAPage(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkFrame, runner: ToolRunner,
                 output_cb: Callable[[str], None]) -> None:
        super().__init__(master, fg_color="transparent")
        self._runner = runner
        self._output_cb = output_cb
        self._build()

    # ------------------------------------------------------------------
    def _build(self) -> None:
        # ── Header ──────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(24, 4))
        ctk.CTkLabel(hdr, text="🦠  Static Malware Analyzer",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(hdr,
                     text="PE / ELF analysis without execution  ·  Entropy  ·  18 MITRE ATT&CK rules  ·  YARA  ·  VirusTotal",
                     text_color="gray", font=ctk.CTkFont(size=12)).pack(anchor="w")

        # ── Scrollable options ───────────────────────────────────────────
        opts = ctk.CTkScrollableFrame(self)
        opts.pack(fill="both", expand=True, padx=24, pady=(8, 0))
        opts.grid_columnconfigure(1, weight=1)
        row = 0

        # Binary file drop-zone style picker
        drop_frame = ctk.CTkFrame(opts, fg_color="#1c2128", corner_radius=8)
        drop_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(8, 4))
        drop_frame.grid_columnconfigure(0, weight=1)
        row += 1

        ctk.CTkLabel(drop_frame, text="Binary File to Analyze",
                     font=ctk.CTkFont(size=13, weight="bold"), anchor="w").grid(
            row=0, column=0, sticky="w", padx=14, pady=(12, 4))

        file_inner = ctk.CTkFrame(drop_frame, fg_color="transparent")
        file_inner.grid(row=1, column=0, columnspan=2, sticky="ew", padx=14, pady=(0, 4))
        file_inner.grid_columnconfigure(0, weight=1)
        self._binary_var = ctk.StringVar()
        self._binary_var.trace_add("write", self._on_file_change)
        ctk.CTkEntry(file_inner, textvariable=self._binary_var,
                     placeholder_text="Select or paste a path to a .exe / .dll / .so / ELF binary").grid(
            row=0, column=0, sticky="ew")
        ctk.CTkButton(file_inner, text="Browse…", width=90,
                      command=self._browse_binary).grid(row=0, column=1, padx=(8, 0))

        self._file_info = ctk.CTkLabel(drop_frame, text="",
                                        text_color="#8b949e", font=ctk.CTkFont(size=11),
                                        anchor="w")
        self._file_info.grid(row=2, column=0, sticky="w", padx=14, pady=(2, 10))

        ctk.CTkFrame(opts, height=1, fg_color="#30363d").grid(
            row=row, column=0, columnspan=2, sticky="ew", pady=8)
        row += 1

        # VT API Key
        ctk.CTkLabel(opts, text="VirusTotal API Key", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        key_row = ctk.CTkFrame(opts, fg_color="transparent")
        key_row.grid(row=row, column=1, sticky="ew", pady=10)
        key_row.grid_columnconfigure(0, weight=1)
        self._vt_key_var = ctk.StringVar(value=os.environ.get("VT_API_KEY", ""))
        self._vt_entry = ctk.CTkEntry(key_row, textvariable=self._vt_key_var, show="●",
                                      placeholder_text="Optional — or set VT_API_KEY env var")
        self._vt_entry.grid(row=0, column=0, sticky="ew")
        self._show_key = False
        self._show_btn = ctk.CTkButton(key_row, text="Show", width=60,
                                        command=self._toggle_key)
        self._show_btn.grid(row=0, column=1, padx=(8, 0))
        row += 1

        # YARA rules
        ctk.CTkLabel(opts, text="YARA Rules", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        yara_row = ctk.CTkFrame(opts, fg_color="transparent")
        yara_row.grid(row=row, column=1, sticky="ew", pady=10)
        yara_row.grid_columnconfigure(0, weight=1)
        self._yara_var = ctk.StringVar()
        ctk.CTkEntry(yara_row, textvariable=self._yara_var,
                     placeholder_text="Leave blank to use the 18 built-in rules").grid(
            row=0, column=0, sticky="ew")
        ctk.CTkButton(yara_row, text="Browse…", width=90,
                      command=lambda: self._browse(self._yara_var,
                                                   [("YARA", "*.yar *.yara"), ("All", "*.*")])).grid(
            row=0, column=1, padx=(8, 0))
        row += 1

        # JSON report
        ctk.CTkLabel(opts, text="JSON Report", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        json_row = ctk.CTkFrame(opts, fg_color="transparent")
        json_row.grid(row=row, column=1, sticky="ew", pady=10)
        json_row.grid_columnconfigure(0, weight=1)
        self._json_var = ctk.StringVar()
        ctk.CTkEntry(json_row, textvariable=self._json_var,
                     placeholder_text="Optional — e.g.  report.json").grid(
            row=0, column=0, sticky="ew")
        ctk.CTkButton(json_row, text="Browse…", width=90,
                      command=lambda: self._save(self._json_var,
                                                 [("JSON", "*.json")])).grid(
            row=0, column=1, padx=(8, 0))
        row += 1

        # Min string length
        ctk.CTkLabel(opts, text="Min String Length", anchor="e").grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        spin_row = ctk.CTkFrame(opts, fg_color="transparent")
        spin_row.grid(row=row, column=1, sticky="w", pady=10)
        self._min_str_var = ctk.StringVar(value="4")
        ctk.CTkEntry(spin_row, textvariable=self._min_str_var, width=70).pack(side="left")
        ctk.CTkLabel(spin_row, text="  characters minimum",
                     text_color="gray", font=ctk.CTkFont(size=11)).pack(side="left")
        row += 1

        ctk.CTkFrame(opts, height=1, fg_color="#30363d").grid(
            row=row, column=0, columnspan=2, sticky="ew", pady=8)
        row += 1

        # Skip flags
        flags = ctk.CTkFrame(opts, fg_color="transparent")
        flags.grid(row=row, column=0, columnspan=2, sticky="w", pady=6)
        self._no_yara_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(flags, text="Skip YARA scanning",
                        variable=self._no_yara_var).pack(side="left", padx=(0, 28))
        self._no_vt_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(flags, text="Skip VirusTotal lookup (offline mode)",
                        variable=self._no_vt_var).pack(side="left")

        # ── Run button ───────────────────────────────────────────────────
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=24, pady=12)
        self._run_btn = ctk.CTkButton(
            btn_frame, text="▶  Analyze Binary",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#238636", hover_color="#2ea043",
            height=42, command=self._run,
        )
        self._run_btn.pack(side="right")

    # ------------------------------------------------------------------
    def _on_file_change(self, *_) -> None:
        """Update file-info label when binary path changes."""
        path = Path(self._binary_var.get().strip().strip('"'))
        if path.is_file():
            size = _fmt_size(path.stat().st_size)
            suffix = path.suffix.lower()
            fmt = "PE (Windows)" if suffix in (".exe", ".dll", ".sys") else \
                  "ELF (Linux)"  if suffix in (".so", ".elf", "")       else suffix
            self._file_info.configure(
                text=f"📄  {path.name}   •   {size}   •   {fmt}",
                text_color="#3fb950",
            )
        elif self._binary_var.get().strip():
            self._file_info.configure(text="⚠  File not found", text_color="#f85149")
        else:
            self._file_info.configure(text="")

    def _browse_binary(self) -> None:
        path = filedialog.askopenfilename(
            title="Select a binary to analyze",
            filetypes=[("Executables", "*.exe *.dll *.sys *.so *.elf"),
                       ("All files", "*.*")])
        if path:
            self._binary_var.set(path)

    def _browse(self, var: ctk.StringVar, ftypes: list) -> None:
        path = filedialog.askopenfilename(filetypes=ftypes)
        if path:
            var.set(path)

    def _save(self, var: ctk.StringVar, ftypes: list) -> None:
        path = filedialog.asksaveasfilename(filetypes=ftypes)
        if path:
            var.set(path)

    def _toggle_key(self) -> None:
        self._show_key = not self._show_key
        self._vt_entry.configure(show="" if self._show_key else "●")
        self._show_btn.configure(text="Hide" if self._show_key else "Show")

    # ------------------------------------------------------------------
    def _run(self) -> None:
        if self._runner.is_running:
            self._runner.stop()
            return

        binary = self._binary_var.get().strip().strip('"')
        if not binary:
            self._output_cb("[ERROR] Select a binary file to analyze.\n")
            return
        if not Path(binary).is_file():
            self._output_cb(f"[ERROR] File not found: {binary}\n")
            return

        mod = _load_sma()
        if mod is None:
            self._output_cb("[ERROR] Could not load SMA — directory missing or dependencies uninstalled.\n")
            return

        argv = self._build_argv(binary)
        old_argv = sys.argv

        def run_sma() -> int:
            sys.argv = argv
            try:
                return mod.main()  # type: ignore[return-value]
            finally:
                sys.argv = old_argv

        self._run_btn.configure(text="⏹  Stop", fg_color="#da3633", hover_color="#b91c1c")
        self._output_cb(
            f"\n{'='*60}\n▶ Analyzing: {Path(binary).name}\n{'='*60}\n")

        def on_done(code: int) -> None:
            self.after(0, lambda: self._run_btn.configure(
                text="▶  Analyze Binary", fg_color="#238636", hover_color="#2ea043"))
            label = {0: "Clean / Low risk", 1: "Suspicious / Malicious",
                     2: "Error during analysis"}.get(code, f"exit {code}")
            self._output_cb(f"\n[Analysis complete — {label}]\n")

        self._runner.run(run_sma, done_cb=on_done,
                         output_cb=self._output_cb, tool_name="SMA")

    def _build_argv(self, binary: str) -> list[str]:
        argv = ["sma", binary]
        vt_key = self._vt_key_var.get().strip()
        if vt_key:
            argv += ["--vt-key", vt_key]
        yara = self._yara_var.get().strip()
        if yara:
            argv += ["--rules", yara]
        json_out = self._json_var.get().strip()
        if json_out:
            argv += ["--json", json_out]
        min_s = self._min_str_var.get().strip()
        if min_s and min_s != "4":
            argv += ["--min-strings", min_s]
        if self._no_yara_var.get():
            argv.append("--no-yara")
        if self._no_vt_var.get():
            argv.append("--no-vt")
        return argv
