"""Password Auditing Suite page — 6 tabs (identify, crack, score, breach, mutate, audit)."""
from __future__ import annotations

import importlib.util
import sys
import types
from tkinter import filedialog
from typing import Callable, Optional

import customtkinter as ctk

from ..utils.paths import PAS_DIR
from ..utils.runner import ToolRunner

_pas_cli_module: Optional[types.ModuleType] = None


def _load_pas_cli() -> Optional[types.ModuleType]:
    global _pas_cli_module
    if _pas_cli_module is not None:
        return _pas_cli_module
    cli_path = PAS_DIR / "cli.py"
    if not cli_path.exists():
        return None
    pas_str = str(PAS_DIR)
    if pas_str not in sys.path:
        sys.path.insert(0, pas_str)
    spec = importlib.util.spec_from_file_location("pas_cli", str(cli_path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["pas_cli"] = mod
    try:
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        _pas_cli_module = mod
    except Exception:
        pass
    return _pas_cli_module


# ── Shared widget helpers ─────────────────────────────────────────────────────

class _FileRow(ctk.CTkFrame):
    """Label + Entry + Browse button in a single row."""
    def __init__(self, master, placeholder: str = "", ftypes=None, save: bool = False):
        super().__init__(master, fg_color="transparent")
        self.grid_columnconfigure(0, weight=1)
        self.var = ctk.StringVar()
        ctk.CTkEntry(self, textvariable=self.var,
                     placeholder_text=placeholder).grid(row=0, column=0, sticky="ew")
        action = self._save if save else self._browse
        self._ftypes = ftypes or [("All files", "*.*")]
        ctk.CTkButton(self, text="Browse…", width=90,
                      command=action).grid(row=0, column=1, padx=(8, 0))

    def _browse(self) -> None:
        p = filedialog.askopenfilename(filetypes=self._ftypes)
        if p:
            self.var.set(p)

    def _save(self) -> None:
        p = filedialog.asksaveasfilename(filetypes=self._ftypes)
        if p:
            self.var.set(p)


class _FormatRow(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self.var = ctk.StringVar(value="hash")
        ctk.CTkRadioButton(self, text="hash",      variable=self.var, value="hash").pack(side="left", padx=(0, 20))
        ctk.CTkRadioButton(self, text="user:hash", variable=self.var, value="user:hash").pack(side="left")


_ALGOS = ["auto-detect", "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
          "sha3_256", "sha3_512", "bcrypt", "argon2", "scrypt", "ntlm"]

_RULE_NAMES = ["leet", "case", "date", "keyboard", "prefix", "suffix", "reverse", "double"]


# ── Main page ─────────────────────────────────────────────────────────────────

class PASPage(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkFrame, runner: ToolRunner,
                 output_cb: Callable[[str], None]) -> None:
        super().__init__(master, fg_color="transparent")
        self._runner = runner
        self._output_cb = output_cb
        self._run_btns: list[ctk.CTkButton] = []
        self._tab_labels: list[str] = []
        self._build()

    # ------------------------------------------------------------------
    def _build(self) -> None:
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(24, 4))
        ctk.CTkLabel(hdr, text="Password Auditing Suite",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(hdr,
                     text="Hash identification  ·  Cracking  ·  Entropy scoring  ·  HIBP breach  ·  Wordlist mutation",
                     text_color="gray", font=ctk.CTkFont(size=12)).pack(anchor="w")

        tabs = ctk.CTkTabview(self)
        tabs.pack(fill="both", expand=True, padx=24, pady=(8, 4))

        for name, builder in [
            ("Identify", self._build_identify),
            ("Crack",    self._build_crack),
            ("Score",    self._build_score),
            ("Breach",   self._build_breach),
            ("Mutate",   self._build_mutate),
            ("Audit",    self._build_audit),
        ]:
            frame = tabs.add(name)
            frame.grid_columnconfigure(1, weight=1)
            builder(frame)

        self._progress = ctk.CTkProgressBar(self, mode="indeterminate",
                                             progress_color="#1f6aa5")
        self._progress.pack(fill="x", padx=24, pady=(0, 6))
        self._progress.pack_forget()

    # ── Identify ──────────────────────────────────────────────────────────
    def _build_identify(self, f: ctk.CTkFrame) -> None:
        r = 0
        ctk.CTkLabel(f, text="Hash(es)", anchor="ne",
                     font=ctk.CTkFont(weight="bold")).grid(
            row=r, column=0, sticky="ne", padx=(0, 12), pady=10)
        info = ctk.CTkFrame(f, fg_color="transparent")
        info.grid(row=r, column=1, sticky="ew", pady=(10, 2))
        info.grid_columnconfigure(0, weight=1)
        self._id_hashes = ctk.CTkTextbox(info, height=110,
                                          font=ctk.CTkFont(family="Consolas", size=12))
        self._id_hashes.grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(info, text="Paste", width=60,
                      command=lambda: self._paste(self._id_hashes)).grid(
            row=0, column=1, padx=(8, 0), sticky="n")
        r += 1

        ctk.CTkLabel(f, text="", anchor="e").grid(row=r, column=0)
        ctk.CTkLabel(f, text="Enter one hash per line — MD5, SHA*, bcrypt, NTLM, Argon2, etc.",
                     text_color="#8b949e", font=ctk.CTkFont(size=11), anchor="w").grid(
            row=r, column=1, sticky="w", pady=(0, 8))
        r += 1

        ctk.CTkLabel(f, text="Top N candidates", anchor="e").grid(
            row=r, column=0, sticky="e", padx=(0, 12), pady=10)
        spin_row = ctk.CTkFrame(f, fg_color="transparent")
        spin_row.grid(row=r, column=1, sticky="w", pady=10)
        self._id_top = ctk.StringVar(value="3")
        ctk.CTkEntry(spin_row, textvariable=self._id_top, width=70).pack(side="left")
        ctk.CTkLabel(spin_row, text="  per hash", text_color="gray",
                     font=ctk.CTkFont(size=11)).pack(side="left")
        r += 1

        btn = self._run_button(f, "Identify Hashes", r, self._run_identify)
        self._run_btns.append(btn)

    # ── Crack ─────────────────────────────────────────────────────────────
    def _build_crack(self, f: ctk.CTkFrame) -> None:
        r = 0
        ctk.CTkLabel(f, text="Hash File", anchor="e").grid(
            row=r, column=0, sticky="e", padx=(0, 12), pady=10)
        self._crack_hashfile = _FileRow(f, "hashes.txt  (one hash or user:hash per line)")
        self._crack_hashfile.grid(row=r, column=1, sticky="ew", pady=10); r += 1

        ctk.CTkLabel(f, text="Wordlist", anchor="e").grid(
            row=r, column=0, sticky="e", padx=(0, 12), pady=10)
        self._crack_wordlist = _FileRow(f, "rockyou.txt  ← required")
        self._crack_wordlist.grid(row=r, column=1, sticky="ew", pady=10); r += 1

        ctk.CTkLabel(f, text="Algorithm", anchor="e").grid(
            row=r, column=0, sticky="e", padx=(0, 12), pady=10)
        self._crack_algo = ctk.StringVar(value="auto-detect")
        ctk.CTkComboBox(f, variable=self._crack_algo, values=_ALGOS,
                        state="readonly", width=180).grid(row=r, column=1, sticky="w", pady=10); r += 1

        ctk.CTkLabel(f, text="Input Format", anchor="e").grid(
            row=r, column=0, sticky="e", padx=(0, 12), pady=10)
        self._crack_fmt = _FormatRow(f)
        self._crack_fmt.grid(row=r, column=1, sticky="w", pady=10); r += 1

        ctk.CTkLabel(f, text="Workers", anchor="e").grid(
            row=r, column=0, sticky="e", padx=(0, 12), pady=8)
        self._crack_workers = ctk.StringVar(value="4")
        ctk.CTkEntry(f, textvariable=self._crack_workers, width=80).grid(
            row=r, column=1, sticky="w", pady=8); r += 1

        ctk.CTkLabel(f, text="Timeout (s)", anchor="e").grid(
            row=r, column=0, sticky="e", padx=(0, 12), pady=8)
        self._crack_timeout = ctk.StringVar(value="3600")
        ctk.CTkEntry(f, textvariable=self._crack_timeout, width=100).grid(
            row=r, column=1, sticky="w", pady=8); r += 1

        self._crack_mutate = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(f, text="Apply mutation rules (leet, case, dates, keyboard walks…)",
                        variable=self._crack_mutate).grid(
            row=r, column=0, columnspan=2, sticky="w", pady=8); r += 1

        btn = self._run_button(f, "Start Cracking", r, self._run_crack)
        self._run_btns.append(btn)

    # ── Score ─────────────────────────────────────────────────────────────
    def _build_score(self, f: ctk.CTkFrame) -> None:
        r = 0
        ctk.CTkLabel(f, text="Password(s)", anchor="ne",
                     font=ctk.CTkFont(weight="bold")).grid(
            row=r, column=0, sticky="ne", padx=(0, 12), pady=10)
        pw_row = ctk.CTkFrame(f, fg_color="transparent")
        pw_row.grid(row=r, column=1, sticky="ew", pady=10)
        pw_row.grid_columnconfigure(0, weight=1)
        self._score_pws = ctk.CTkTextbox(pw_row, height=100,
                                          font=ctk.CTkFont(family="Consolas", size=12))
        self._score_pws.grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(pw_row, text="Paste", width=60,
                      command=lambda: self._paste(self._score_pws)).grid(
            row=0, column=1, padx=(8, 0), sticky="n"); r += 1

        ctk.CTkLabel(f, text="", anchor="e").grid(row=r, column=0)
        ctk.CTkLabel(f, text="One password per line — scores entropy, character pools, and policy compliance.",
                     text_color="#8b949e", font=ctk.CTkFont(size=11), anchor="w").grid(
            row=r, column=1, sticky="w", pady=(0, 8)); r += 1

        for label, attr, default in [
            ("Min Length",              "_score_minlen",     "8"),
            ("Min Char Classes",        "_score_minclasses", "1"),
            ("Max Consecutive Repeats", "_score_maxrepeat",  "3"),
        ]:
            ctk.CTkLabel(f, text=label, anchor="e").grid(
                row=r, column=0, sticky="e", padx=(0, 12), pady=8)
            var = ctk.StringVar(value=default)
            setattr(self, attr, var)
            ctk.CTkEntry(f, textvariable=var, width=80).grid(row=r, column=1, sticky="w", pady=8)
            r += 1

        self._score_block = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(f, text="Block passwords from the common-password list",
                        variable=self._score_block).grid(
            row=r, column=0, columnspan=2, sticky="w", pady=8); r += 1

        btn = self._run_button(f, "Score Passwords", r, self._run_score)
        self._run_btns.append(btn)

    # ── Breach ────────────────────────────────────────────────────────────
    def _build_breach(self, f: ctk.CTkFrame) -> None:
        r = 0
        ctk.CTkLabel(f, text="Password(s)", anchor="ne",
                     font=ctk.CTkFont(weight="bold")).grid(
            row=r, column=0, sticky="ne", padx=(0, 12), pady=10)
        pw_row = ctk.CTkFrame(f, fg_color="transparent")
        pw_row.grid(row=r, column=1, sticky="ew", pady=10)
        pw_row.grid_columnconfigure(0, weight=1)
        self._breach_pws = ctk.CTkTextbox(pw_row, height=110,
                                           font=ctk.CTkFont(family="Consolas", size=12))
        self._breach_pws.grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(pw_row, text="Paste", width=60,
                      command=lambda: self._paste(self._breach_pws)).grid(
            row=0, column=1, padx=(8, 0), sticky="n"); r += 1

        # Privacy note
        note = ctk.CTkFrame(f, fg_color="#1c2128", corner_radius=6)
        note.grid(row=r, column=0, columnspan=2, sticky="ew", pady=(4, 12))
        ctk.CTkLabel(note,
                     text="k-Anonymity: only the first 5 hex chars of each hash are sent to HIBP.\n"
                          "    Your full password or hash never leaves your machine.",
                     text_color="#58a6ff", font=ctk.CTkFont(size=11),
                     justify="left", anchor="w").pack(padx=12, pady=8, anchor="w"); r += 1

        btn = self._run_button(f, "Check HIBP Breaches", r, self._run_breach)
        self._run_btns.append(btn)

    # ── Mutate ────────────────────────────────────────────────────────────
    def _build_mutate(self, f: ctk.CTkFrame) -> None:
        r = 0
        ctk.CTkLabel(f, text="Wordlist", anchor="e").grid(
            row=r, column=0, sticky="e", padx=(0, 12), pady=10)
        self._mut_wordlist = _FileRow(f, "wordlist.txt  ← required")
        self._mut_wordlist.grid(row=r, column=1, sticky="ew", pady=10); r += 1

        ctk.CTkLabel(f, text="Output File", anchor="e").grid(
            row=r, column=0, sticky="e", padx=(0, 12), pady=10)
        self._mut_output = _FileRow(f, "Optional — prints to console if blank", save=True)
        self._mut_output.grid(row=r, column=1, sticky="ew", pady=10); r += 1

        ctk.CTkLabel(f, text="Rules", anchor="ne").grid(
            row=r, column=0, sticky="ne", padx=(0, 12), pady=10)
        rules_frame = ctk.CTkFrame(f, fg_color="transparent")
        rules_frame.grid(row=r, column=1, sticky="ew", pady=10)
        self._mut_rules: dict[str, ctk.BooleanVar] = {}
        for i, name in enumerate(_RULE_NAMES):
            v = ctk.BooleanVar(value=True)
            self._mut_rules[name] = v
            ctk.CTkCheckBox(rules_frame, text=name, variable=v).grid(
                row=i // 4, column=i % 4, sticky="w", padx=8, pady=2)
        r += 1

        for label, attr, default in [
            ("Max Leet Combos / word", "_mut_maxleet",  "64"),
            ("Max Date Tokens / word", "_mut_maxdates", "200"),
        ]:
            ctk.CTkLabel(f, text=label, anchor="e").grid(
                row=r, column=0, sticky="e", padx=(0, 12), pady=8)
            var = ctk.StringVar(value=default)
            setattr(self, attr, var)
            ctk.CTkEntry(f, textvariable=var, width=90).grid(row=r, column=1, sticky="w", pady=8)
            r += 1

        btn = self._run_button(f, "Generate Mutations", r, self._run_mutate)
        self._run_btns.append(btn)

    # ── Audit ─────────────────────────────────────────────────────────────
    def _build_audit(self, f: ctk.CTkFrame) -> None:
        r = 0
        ctk.CTkLabel(f, text="Hash File", anchor="e").grid(
            row=r, column=0, sticky="e", padx=(0, 12), pady=10)
        self._audit_hashfile = _FileRow(f, "hashes.txt")
        self._audit_hashfile.grid(row=r, column=1, sticky="ew", pady=10); r += 1

        ctk.CTkLabel(f, text="Wordlist", anchor="e").grid(
            row=r, column=0, sticky="e", padx=(0, 12), pady=10)
        self._audit_wordlist = _FileRow(f, "rockyou.txt  ← required")
        self._audit_wordlist.grid(row=r, column=1, sticky="ew", pady=10); r += 1

        ctk.CTkLabel(f, text="Input Format", anchor="e").grid(
            row=r, column=0, sticky="e", padx=(0, 12), pady=10)
        self._audit_fmt = _FormatRow(f)
        self._audit_fmt.grid(row=r, column=1, sticky="w", pady=10); r += 1

        for label, attr, default in [
            ("Workers",    "_audit_workers", "4"),
            ("Timeout (s)", "_audit_timeout", "3600"),
        ]:
            ctk.CTkLabel(f, text=label, anchor="e").grid(
                row=r, column=0, sticky="e", padx=(0, 12), pady=8)
            var = ctk.StringVar(value=default)
            setattr(self, attr, var)
            ctk.CTkEntry(f, textvariable=var, width=100).grid(row=r, column=1, sticky="w", pady=8)
            r += 1

        flags = ctk.CTkFrame(f, fg_color="transparent")
        flags.grid(row=r, column=0, columnspan=2, sticky="w", pady=8)
        self._audit_breach = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(flags, text="Include HIBP breach check",
                        variable=self._audit_breach).pack(side="left", padx=(0, 24))
        self._audit_mutate = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(flags, text="Apply mutations",
                        variable=self._audit_mutate).pack(side="left")
        r += 1

        btn = self._run_button(f, "Run Full Audit", r, self._run_audit)
        self._run_btns.append(btn)

    # ── Shared helpers ────────────────────────────────────────────────────
    def _run_button(self, parent, text: str, row: int,
                    cmd: Callable) -> ctk.CTkButton:
        btn = ctk.CTkButton(parent, text=text,
                            font=ctk.CTkFont(size=13, weight="bold"),
                            fg_color="#238636", hover_color="#2ea043",
                            height=40, command=cmd)
        btn.grid(row=row, column=0, columnspan=2, pady=16)
        return btn

    def _paste(self, box: ctk.CTkTextbox) -> None:
        try:
            text = self.clipboard_get()
            box.insert("end", text)
        except Exception:
            pass

    def _lines(self, box: ctk.CTkTextbox) -> list[str]:
        return [l.strip() for l in box.get("1.0", "end").splitlines() if l.strip()]

    def _reset_btns(self) -> None:
        labels = ["Identify Hashes", "Start Cracking", "Score Passwords",
                  "Check HIBP Breaches", "Generate Mutations", "Run Full Audit"]
        for btn, label in zip(self._run_btns, labels):
            btn.configure(text=label, fg_color="#238636", hover_color="#2ea043")

    # ── Invocation ────────────────────────────────────────────────────────
    def _invoke(self, args: list[str], sub: str) -> None:
        if self._runner.is_running:
            self._runner.stop()
            return

        mod = _load_pas_cli()
        if mod is None:
            self._output_cb("[ERROR] Could not load PAS cli — directory missing or dependencies uninstalled.\n")
            return

        def run_pas() -> int:
            try:
                result = mod.cli.main(args, standalone_mode=False)
                return result if isinstance(result, int) else 0
            except SystemExit as e:
                return e.code if isinstance(e.code, int) else 0

        for btn in self._run_btns:
            btn.configure(text="Stop", fg_color="#da3633", hover_color="#b91c1c")

        self._progress.pack(fill="x", padx=24, pady=(0, 6))
        self._progress.start()
        self._output_cb(f"\n{'='*60}\nPAS  {' '.join(args)}\n{'='*60}\n")

        def on_done(code: int) -> None:
            self.after(0, self._reset_btns)
            self.after(0, lambda: (self._progress.stop(), self._progress.pack_forget()))
            self._output_cb(f"\n[Done — exit code {code}]\n")

        self._runner.run(run_pas, done_cb=on_done,
                         output_cb=self._output_cb, tool_name=f"PAS/{sub}")

    # ── Individual command runners ─────────────────────────────────────────
    def _run_identify(self) -> None:
        hashes = self._lines(self._id_hashes)
        if not hashes:
            self._output_cb("[ERROR] Enter at least one hash.\n"); return
        self._invoke(["identify"] + hashes + ["--top", self._id_top.get()], "identify")

    def _run_crack(self) -> None:
        hashfile = self._crack_hashfile.var.get().strip()
        wordlist = self._crack_wordlist.var.get().strip()
        if not hashfile or not wordlist:
            self._output_cb("[ERROR] Hash file and wordlist are both required.\n"); return
        args = ["crack", hashfile, "--wordlist", wordlist,
                "--workers", self._crack_workers.get(),
                "--timeout", self._crack_timeout.get(),
                "--format", self._crack_fmt.var.get()]
        algo = self._crack_algo.get()
        if algo != "auto-detect":
            args += ["--algorithm", algo]
        if not self._crack_mutate.get():
            args.append("--no-mutate")
        self._invoke(args, "crack")

    def _run_score(self) -> None:
        pws = self._lines(self._score_pws)
        if not pws:
            self._output_cb("[ERROR] Enter at least one password.\n"); return
        args = (["score"] + pws
                + ["--min-length",  self._score_minlen.get(),
                   "--min-classes", self._score_minclasses.get(),
                   "--max-repeat",  self._score_maxrepeat.get()])
        if not self._score_block.get():
            args.append("--no-block-common")
        self._invoke(args, "score")

    def _run_breach(self) -> None:
        pws = self._lines(self._breach_pws)
        if not pws:
            self._output_cb("[ERROR] Enter at least one password.\n"); return
        self._invoke(["breach"] + pws, "breach")

    def _run_mutate(self) -> None:
        wordlist = self._mut_wordlist.var.get().strip()
        if not wordlist:
            self._output_cb("[ERROR] Wordlist file is required.\n"); return
        args = ["mutate", wordlist]
        out = self._mut_output.var.get().strip()
        if out:
            args += ["--output", out]
        for r, v in self._mut_rules.items():
            if v.get():
                args += ["--rules", r]
        args += ["--max-leet", self._mut_maxleet.get(),
                 "--max-dates", self._mut_maxdates.get()]
        self._invoke(args, "mutate")

    def _run_audit(self) -> None:
        hashfile = self._audit_hashfile.var.get().strip()
        wordlist = self._audit_wordlist.var.get().strip()
        if not hashfile or not wordlist:
            self._output_cb("[ERROR] Hash file and wordlist are both required.\n"); return
        args = ["audit", hashfile, "--wordlist", wordlist,
                "--workers", self._audit_workers.get(),
                "--timeout", self._audit_timeout.get(),
                "--format",  self._audit_fmt.var.get()]
        if not self._audit_breach.get():
            args.append("--no-breach-check")
        if not self._audit_mutate.get():
            args.append("--no-mutate")
        self._invoke(args, "audit")
