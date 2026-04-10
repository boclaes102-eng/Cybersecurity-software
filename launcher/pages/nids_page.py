"""Network Intrusion Detection System page."""
from __future__ import annotations

import importlib.util
import sys
import types
from tkinter import filedialog
from typing import TYPE_CHECKING, Callable, Optional

import customtkinter as ctk

from ..utils.paths import NIDS_DIR
from ..utils.runner import ToolRunner

_MODES = [
    "Interactive Menu",
    "Live Capture",
    "PCAP Replay",
    "List Interfaces",
    "Generate Test PCAP",
]

_MODE_HINTS = {
    "Interactive Menu":   "Launch NIDS's own numbered menu (runs in console).",
    "Live Capture":       "Capture packets on a live network interface in real-time.",
    "PCAP Replay":        "Analyse a pre-recorded .pcap / .pcapng file offline.",
    "List Interfaces":    "Print all available network interfaces and exit.",
    "Generate Test PCAP": "Create a synthetic attack-traffic PCAP for testing.",
}

_nids_module: Optional[types.ModuleType] = None


def _load_nids() -> Optional[types.ModuleType]:
    global _nids_module
    if _nids_module is not None:
        return _nids_module
    main_path = NIDS_DIR / "main.py"
    if not main_path.exists():
        return None
    nids_str = str(NIDS_DIR)
    if nids_str not in sys.path:
        sys.path.insert(0, nids_str)
    spec = importlib.util.spec_from_file_location("nids_main", str(main_path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["nids_main"] = mod
    try:
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        _nids_module = mod
    except Exception:
        pass
    return _nids_module


def _get_interfaces() -> list[str]:
    """Return available network interface names via Scapy."""
    try:
        from scapy.interfaces import get_if_list  # type: ignore
        ifaces = [i for i in get_if_list() if i]
        return ifaces or ["eth0"]
    except Exception:
        return ["(scapy not installed — install dependencies first)"]


class NIDSPage(ctk.CTkFrame):
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
        ctk.CTkLabel(hdr, text="🌐  Network Intrusion Detection System",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(hdr,
                     text="Real-time packet capture  ·  PCAP replay  ·  6 attack detectors  ·  SIEM export",
                     text_color="gray", font=ctk.CTkFont(size=12)).pack(anchor="w")

        # ── Scrollable options ───────────────────────────────────────────
        opts = ctk.CTkScrollableFrame(self)
        opts.pack(fill="both", expand=True, padx=24, pady=(8, 0))
        opts.grid_columnconfigure(1, weight=1)

        row = 0

        # Mode selector
        ctk.CTkLabel(opts, text="Mode", anchor="e", font=ctk.CTkFont(weight="bold")).grid(
            row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._mode_var = ctk.StringVar(value="Interactive Menu")
        mode_cb = ctk.CTkComboBox(opts, variable=self._mode_var, values=_MODES,
                                  command=self._on_mode_change, state="readonly",
                                  font=ctk.CTkFont(size=13))
        mode_cb.grid(row=row, column=1, sticky="w", pady=10)
        row += 1

        # Mode hint
        ctk.CTkLabel(opts, text="", anchor="e").grid(row=row, column=0)
        self._hint_label = ctk.CTkLabel(opts, text=_MODE_HINTS["Interactive Menu"],
                                         text_color="#8b949e", font=ctk.CTkFont(size=11),
                                         anchor="w", wraplength=500)
        self._hint_label.grid(row=row, column=1, sticky="w", pady=(0, 6))
        row += 1

        ctk.CTkFrame(opts, height=1, fg_color="#30363d").grid(
            row=row, column=0, columnspan=2, sticky="ew", pady=8)
        row += 1

        # Interface (Live only)
        self._iface_label = ctk.CTkLabel(opts, text="Interface", anchor="e")
        self._iface_label.grid(row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._iface_row = ctk.CTkFrame(opts, fg_color="transparent")
        self._iface_row.grid(row=row, column=1, sticky="ew", pady=10)
        self._iface_row.grid_columnconfigure(0, weight=1)
        self._iface_var = ctk.StringVar()
        self._iface_cb = ctk.CTkComboBox(self._iface_row, variable=self._iface_var, values=[""])
        self._iface_cb.grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(self._iface_row, text="↺ Refresh", width=90,
                      command=self._refresh_ifaces).grid(row=0, column=1, padx=(8, 0))
        row += 1

        # BPF Filter (Live only)
        self._filter_label = ctk.CTkLabel(opts, text="BPF Filter", anchor="e")
        self._filter_label.grid(row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._filter_var = ctk.StringVar(value="tcp or udp")
        self._filter_entry = ctk.CTkEntry(opts, textvariable=self._filter_var,
                                          placeholder_text="e.g.  tcp or udp port 80  or  icmp")
        self._filter_entry.grid(row=row, column=1, sticky="ew", pady=10)
        row += 1

        # PCAP file (Replay only)
        self._pcap_label = ctk.CTkLabel(opts, text="PCAP File", anchor="e")
        self._pcap_label.grid(row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._pcap_row = ctk.CTkFrame(opts, fg_color="transparent")
        self._pcap_row.grid(row=row, column=1, sticky="ew", pady=10)
        self._pcap_row.grid_columnconfigure(0, weight=1)
        self._pcap_var = ctk.StringVar()
        ctk.CTkEntry(self._pcap_row, textvariable=self._pcap_var,
                     placeholder_text="path/to/capture.pcap").grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(self._pcap_row, text="Browse…", width=90,
                      command=lambda: self._browse(self._pcap_var,
                                                   [("PCAP", "*.pcap *.pcapng"), ("All", "*.*")])).grid(
            row=0, column=1, padx=(8, 0))
        row += 1

        # SIEM output (Live + Replay)
        self._siem_label = ctk.CTkLabel(opts, text="SIEM Output", anchor="e")
        self._siem_label.grid(row=row, column=0, sticky="e", padx=(0, 12), pady=10)
        self._siem_row = ctk.CTkFrame(opts, fg_color="transparent")
        self._siem_row.grid(row=row, column=1, sticky="ew", pady=10)
        self._siem_row.grid_columnconfigure(0, weight=1)
        self._siem_var = ctk.StringVar(value="alerts.ndjson")
        ctk.CTkEntry(self._siem_row, textvariable=self._siem_var).grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(self._siem_row, text="Browse…", width=90,
                      command=lambda: self._save(self._siem_var,
                                                 [("NDJSON", "*.ndjson"), ("All", "*.*")])).grid(
            row=0, column=1, padx=(8, 0))
        row += 1

        ctk.CTkFrame(opts, height=1, fg_color="#30363d").grid(
            row=row, column=0, columnspan=2, sticky="ew", pady=8)
        row += 1

        # Flags
        flags = ctk.CTkFrame(opts, fg_color="transparent")
        flags.grid(row=row, column=0, columnspan=2, sticky="w", pady=6)
        self._headless_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(flags, text="Headless — suppress Rich dashboard",
                        variable=self._headless_var).pack(side="left", padx=(0, 24))
        self._verbose_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(flags, text="Verbose / debug logging",
                        variable=self._verbose_var).pack(side="left")
        row += 1

        # Admin note (always visible, informational)
        note = ctk.CTkFrame(opts, fg_color="#1c2128", corner_radius=6)
        note.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(4, 8))
        ctk.CTkLabel(note,
                     text="⚠  Live capture requires Npcap (Windows) or root / cap_net_raw+ep (Linux).",
                     text_color="#d29922", font=ctk.CTkFont(size=11), anchor="w").pack(
            padx=12, pady=6, anchor="w")

        # ── Run button ───────────────────────────────────────────────────
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=24, pady=12)
        self._run_btn = ctk.CTkButton(
            btn_frame, text="▶  Run NIDS",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#238636", hover_color="#2ea043",
            height=42, command=self._run,
        )
        self._run_btn.pack(side="right")

        # Apply initial visibility
        self._on_mode_change("Interactive Menu")
        self._refresh_ifaces()

    # ------------------------------------------------------------------
    def _on_mode_change(self, value: str) -> None:
        self._hint_label.configure(text=_MODE_HINTS.get(value, ""))
        live   = value == "Live Capture"
        replay = value == "PCAP Replay"
        siem   = live or replay

        def _show(widget, visible: bool) -> None:
            if visible:
                widget.grid()
            else:
                widget.grid_remove()

        _show(self._iface_label,  live)
        _show(self._iface_row,    live)
        _show(self._filter_label, live)
        _show(self._filter_entry, live)
        _show(self._pcap_label,   replay)
        _show(self._pcap_row,     replay)
        _show(self._siem_label,   siem)
        _show(self._siem_row,     siem)

    def _refresh_ifaces(self) -> None:
        ifaces = _get_interfaces()
        self._iface_cb.configure(values=ifaces)
        if ifaces:
            self._iface_var.set(ifaces[0])

    # ------------------------------------------------------------------
    def _browse(self, var: ctk.StringVar, ftypes: list) -> None:
        path = filedialog.askopenfilename(filetypes=ftypes)
        if path:
            var.set(path)

    def _save(self, var: ctk.StringVar, ftypes: list) -> None:
        path = filedialog.asksaveasfilename(filetypes=ftypes)
        if path:
            var.set(path)

    # ------------------------------------------------------------------
    def _run(self) -> None:
        if self._runner.is_running:
            self._runner.stop()
            return

        mod = _load_nids()
        if mod is None:
            self._output_cb("[ERROR] Could not load NIDS — directory missing or dependencies uninstalled.\n")
            return

        argv = self._build_argv()
        old_argv = sys.argv

        def run_nids() -> int:
            sys.argv = argv
            try:
                return mod.main()  # type: ignore[return-value]
            finally:
                sys.argv = old_argv

        self._run_btn.configure(text="⏹  Stop NIDS", fg_color="#da3633", hover_color="#b91c1c")
        self._output_cb(
            f"\n{'='*60}\n▶ NIDS  [{' '.join(argv[1:])}]\n{'='*60}\n")

        def on_done(code: int) -> None:
            self.after(0, lambda: self._run_btn.configure(
                text="▶  Run NIDS", fg_color="#238636", hover_color="#2ea043"))
            self._output_cb(f"\n[Finished — exit code {code}]\n")

        self._runner.run(run_nids, done_cb=on_done,
                         output_cb=self._output_cb, tool_name="NIDS")

    def _build_argv(self) -> list[str]:
        mode = self._mode_var.get()
        argv = ["nids"]

        if mode == "Interactive Menu":
            return argv
        if mode == "List Interfaces":
            return argv + ["--list-interfaces"]
        if mode == "Generate Test PCAP":
            return argv  # NIDS interactive menu option 4 handles this

        if mode == "Live Capture":
            iface = self._iface_var.get().strip()
            if iface and not iface.startswith("("):
                argv += ["-i", iface]
            filt = self._filter_var.get().strip()
            if filt:
                argv += ["--filter", filt]
            siem = self._siem_var.get().strip()
            if siem:
                argv += ["--siem", siem]
            if self._headless_var.get():
                argv.append("--no-ui")
            if self._verbose_var.get():
                argv.append("--verbose")

        elif mode == "PCAP Replay":
            pcap = self._pcap_var.get().strip()
            if not pcap:
                self._output_cb("[ERROR] Select a PCAP file for replay.\n")
                return ["nids"]
            argv += ["--pcap", pcap]
            siem = self._siem_var.get().strip()
            if siem:
                argv += ["--siem", siem]
            if self._verbose_var.get():
                argv.append("--verbose")

        return argv
