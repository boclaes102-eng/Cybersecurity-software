"""
Pentest Report Generator — collect findings during an engagement and
generate a professional HTML report that opens in the browser
(print to PDF from there).

Findings are persisted to ~/.cybersuite/findings.json between sessions.
Auto-imports from NetMap scan data when available.
"""
from __future__ import annotations

import json
import pathlib
import tempfile
import uuid
import webbrowser
from datetime import date
from typing import Callable, Optional

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox

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

_SEV_COLORS = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#d97706",
    "low":      "#2563eb",
    "info":     "#6b7280",
}
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]

_DATA_DIR  = pathlib.Path.home() / ".cybersuite"
_FIND_FILE = _DATA_DIR / "findings.json"
_ENG_FILE  = _DATA_DIR / "engagement.json"

# ── Persistence ───────────────────────────────────────────────────────────────

def _load_findings() -> list[dict]:
    try:
        return json.loads(_FIND_FILE.read_text())
    except Exception:
        return []

def _save_findings(findings: list[dict]) -> None:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _FIND_FILE.write_text(json.dumps(findings, indent=2))

def _load_engagement() -> dict:
    try:
        return json.loads(_ENG_FILE.read_text())
    except Exception:
        return {
            "client":   "",
            "assessor": "Bo Claes",
            "date":     date.today().isoformat(),
            "scope":    "",
            "type":     "Internal Network Penetration Test",
        }

def _save_engagement(eng: dict) -> None:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _ENG_FILE.write_text(json.dumps(eng, indent=2))

# ── Auto-import from NetMap ───────────────────────────────────────────────────

def _import_from_netmap() -> list[dict]:
    """Convert NetMap high-risk hosts into pre-filled findings."""
    cfg_path = _DATA_DIR / "config.json"
    try:
        cfg = json.loads(cfg_path.read_text())
    except Exception:
        return []

    hosts = cfg.get("last_scan_hosts", [])
    findings = []
    for host in hosts:
        risk = host.get("risk", "")
        if risk not in ("high", "med"):
            continue
        ports = [p for p in host.get("ports", []) if p["state"] == "open"]
        port_list = ", ".join(f"{p['port']}/{p['proto']} ({p['service']})" for p in ports)
        sev = "high" if risk == "high" else "medium"
        findings.append({
            "id":           str(uuid.uuid4())[:8].upper(),
            "title":        f"Exposed services on {host['ip']} ({host.get('type','Host')})",
            "severity":     sev,
            "category":     "Network",
            "host":         host["ip"],
            "description":  f"Host {host['ip']} ({host.get('os','unknown OS')}) has "
                            f"{len(ports)} open port(s) including potentially risky services.",
            "evidence":     f"Open ports: {port_list}\nOS: {host.get('os','—')}\n"
                            f"MAC: {host.get('mac','—')}  Vendor: {host.get('vendor','—')}",
            "remediation":  "Review necessity of each open service. "
                            "Close or firewall ports not required for business operations. "
                            "Apply latest patches to running services.",
            "cvss":         "7.5" if sev == "high" else "5.0",
        })
    return findings

# ── HTML Report Template ──────────────────────────────────────────────────────

def _generate_html(eng: dict, findings: list[dict]) -> str:
    today = date.today().strftime("%B %d, %Y")
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in _SEV_ORDER}
    total  = len(findings)

    sev_badge = {
        "critical": '<span style="background:#dc2626;color:#fff;padding:2px 10px;border-radius:3px;font-size:11px;font-weight:bold;letter-spacing:1px">CRITICAL</span>',
        "high":     '<span style="background:#ea580c;color:#fff;padding:2px 10px;border-radius:3px;font-size:11px;font-weight:bold;letter-spacing:1px">HIGH</span>',
        "medium":   '<span style="background:#d97706;color:#fff;padding:2px 10px;border-radius:3px;font-size:11px;font-weight:bold;letter-spacing:1px">MEDIUM</span>',
        "low":      '<span style="background:#2563eb;color:#fff;padding:2px 10px;border-radius:3px;font-size:11px;font-weight:bold;letter-spacing:1px">LOW</span>',
        "info":     '<span style="background:#6b7280;color:#fff;padding:2px 10px;border-radius:3px;font-size:11px;font-weight:bold;letter-spacing:1px">INFO</span>',
    }

    # Risk bar widths
    bar_pct = {}
    for s in _SEV_ORDER:
        bar_pct[s] = f"{(counts[s]/max(total,1))*100:.0f}%"

    # Findings rows for summary table
    table_rows = ""
    for i, f in enumerate(sorted(findings,
                                  key=lambda x: _SEV_ORDER.index(x["severity"])), 1):
        table_rows += f"""
        <tr style="border-bottom:1px solid #e5e7eb">
          <td style="padding:10px 12px;font-weight:600;color:#111">{i}</td>
          <td style="padding:10px 12px">{sev_badge[f['severity']]}</td>
          <td style="padding:10px 12px;font-weight:500">{f['title']}</td>
          <td style="padding:10px 12px;color:#6b7280;font-family:monospace">{f.get('host','—')}</td>
          <td style="padding:10px 12px;color:#6b7280">{f.get('category','—')}</td>
          <td style="padding:10px 12px;color:#6b7280;font-family:monospace">{f.get('cvss','—')}</td>
        </tr>"""

    # Detailed findings
    detailed = ""
    for i, f in enumerate(sorted(findings,
                                   key=lambda x: _SEV_ORDER.index(x["severity"])), 1):
        col = _SEV_COLORS.get(f["severity"], "#6b7280")
        evidence_html = f['evidence'].replace('\n', '<br>') if f.get('evidence') else '—'
        detailed += f"""
        <div style="margin-bottom:32px;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;page-break-inside:avoid">
          <div style="background:{col};padding:14px 20px;display:flex;align-items:center;gap:16px">
            <span style="color:#fff;font-size:13px;font-weight:700;opacity:.7">FIND-{i:03d}</span>
            <span style="color:#fff;font-size:16px;font-weight:700">{f['title']}</span>
            <span style="margin-left:auto">{sev_badge[f['severity']]}</span>
          </div>
          <div style="padding:20px;background:#fff">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:16px">
              <div><span style="font-size:11px;color:#6b7280;letter-spacing:1px;text-transform:uppercase">Affected Host</span>
                   <p style="margin:4px 0;font-family:monospace;font-weight:600">{f.get('host','—')}</p></div>
              <div><span style="font-size:11px;color:#6b7280;letter-spacing:1px;text-transform:uppercase">Category</span>
                   <p style="margin:4px 0;font-weight:600">{f.get('category','—')}</p></div>
              <div><span style="font-size:11px;color:#6b7280;letter-spacing:1px;text-transform:uppercase">CVSS Score</span>
                   <p style="margin:4px 0;font-weight:700;color:{col}">{f.get('cvss','—')}</p></div>
            </div>
            <div style="margin-bottom:14px">
              <p style="font-size:11px;color:#6b7280;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Description</p>
              <p style="color:#374151;line-height:1.7">{f['description']}</p>
            </div>
            <div style="margin-bottom:14px;background:#f8fafc;border-radius:6px;padding:14px">
              <p style="font-size:11px;color:#6b7280;letter-spacing:1px;text-transform:uppercase;margin-bottom:6px">Evidence</p>
              <pre style="font-family:monospace;font-size:12px;color:#1e293b;white-space:pre-wrap;margin:0">{evidence_html}</pre>
            </div>
            <div style="background:#f0fdf4;border-left:4px solid #16a34a;padding:14px;border-radius:0 6px 6px 0">
              <p style="font-size:11px;color:#15803d;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px">Remediation</p>
              <p style="color:#374151;line-height:1.7;margin:0">{f.get('remediation','—')}</p>
            </div>
          </div>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Penetration Test Report — {eng.get('client','[Client]')}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
       font-size:14px;color:#374151;background:#f9fafb;line-height:1.6}}
  .page{{max-width:900px;margin:0 auto;background:#fff;box-shadow:0 0 40px rgba(0,0,0,.08)}}
  .cover{{background:#0f172a;color:#fff;padding:80px 60px;min-height:280px}}
  .cover h1{{font-size:32px;font-weight:800;letter-spacing:-1px;margin-bottom:8px}}
  .cover .sub{{color:#94a3b8;font-size:16px;margin-bottom:40px}}
  .cover-grid{{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:40px}}
  .cover-item span{{display:block;font-size:11px;color:#64748b;letter-spacing:1px;text-transform:uppercase}}
  .cover-item strong{{color:#f1f5f9;font-size:15px}}
  .section{{padding:40px 60px;border-bottom:1px solid #f1f5f9}}
  .section h2{{font-size:20px;font-weight:700;color:#0f172a;margin-bottom:20px;
               padding-bottom:10px;border-bottom:2px solid #e2e8f0}}
  .risk-bar{{display:flex;height:8px;border-radius:4px;overflow:hidden;margin:16px 0}}
  .stat-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:20px 0}}
  .stat-card{{text-align:center;padding:16px;border-radius:8px;border:1px solid #e5e7eb}}
  .stat-card .num{{font-size:28px;font-weight:800}}
  .stat-card .lbl{{font-size:11px;letter-spacing:1px;text-transform:uppercase;color:#6b7280;margin-top:2px}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  th{{background:#f8fafc;padding:10px 12px;text-align:left;font-size:11px;
      letter-spacing:1px;text-transform:uppercase;color:#6b7280;border-bottom:2px solid #e5e7eb}}
  @media print{{body{{background:#fff}}.page{{box-shadow:none}}}}
  .classification{{display:inline-block;background:#dc2626;color:#fff;font-size:10px;
                   letter-spacing:2px;padding:3px 10px;border-radius:2px;margin-bottom:16px}}
</style>
</head>
<body>
<div class="page">

  <!-- Cover -->
  <div class="cover">
    <div class="classification">CONFIDENTIAL</div>
    <h1>Penetration Test Report</h1>
    <div class="sub">{eng.get('type','Internal Network Penetration Test')}</div>
    <div class="cover-grid">
      <div class="cover-item"><span>Client</span><strong>{eng.get('client','—')}</strong></div>
      <div class="cover-item"><span>Assessor</span><strong>{eng.get('assessor','—')}</strong></div>
      <div class="cover-item"><span>Report Date</span><strong>{today}</strong></div>
      <div class="cover-item"><span>Scope</span><strong>{eng.get('scope','—')}</strong></div>
    </div>
  </div>

  <!-- Executive Summary -->
  <div class="section">
    <h2>Executive Summary</h2>
    <p style="color:#6b7280;margin-bottom:20px">
      This report presents the findings of a {eng.get('type','penetration test')} conducted
      against <strong>{eng.get('client','the target environment')}</strong>.
      A total of <strong>{total}</strong> finding(s) were identified across all tested systems.
    </p>
    <div class="stat-grid">
      <div class="stat-card" style="border-color:#dc2626">
        <div class="num" style="color:#dc2626">{counts['critical']}</div>
        <div class="lbl">Critical</div>
      </div>
      <div class="stat-card" style="border-color:#ea580c">
        <div class="num" style="color:#ea580c">{counts['high']}</div>
        <div class="lbl">High</div>
      </div>
      <div class="stat-card" style="border-color:#d97706">
        <div class="num" style="color:#d97706">{counts['medium']}</div>
        <div class="lbl">Medium</div>
      </div>
      <div class="stat-card" style="border-color:#2563eb">
        <div class="num" style="color:#2563eb">{counts['low']}</div>
        <div class="lbl">Low</div>
      </div>
      <div class="stat-card" style="border-color:#6b7280">
        <div class="num" style="color:#6b7280">{counts['info']}</div>
        <div class="lbl">Info</div>
      </div>
    </div>
    <div class="risk-bar">
      <div style="width:{bar_pct['critical']};background:#dc2626"></div>
      <div style="width:{bar_pct['high']};background:#ea580c"></div>
      <div style="width:{bar_pct['medium']};background:#d97706"></div>
      <div style="width:{bar_pct['low']};background:#2563eb"></div>
      <div style="width:{bar_pct['info']};background:#e5e7eb"></div>
    </div>
  </div>

  <!-- Findings Table -->
  <div class="section">
    <h2>Findings Summary</h2>
    <table>
      <thead>
        <tr>
          <th>#</th><th>Severity</th><th>Title</th>
          <th>Host</th><th>Category</th><th>CVSS</th>
        </tr>
      </thead>
      <tbody>{table_rows}</tbody>
    </table>
  </div>

  <!-- Detailed Findings -->
  <div class="section">
    <h2>Detailed Findings</h2>
    {detailed if detailed else '<p style="color:#6b7280">No findings recorded.</p>'}
  </div>

  <!-- Footer -->
  <div style="padding:24px 60px;background:#f8fafc;text-align:center;
              color:#9ca3af;font-size:12px;letter-spacing:.5px">
    CONFIDENTIAL — {eng.get('client','Client')} — {today} — Generated by CyberSuite Pro
  </div>

</div>
</body>
</html>"""

# ── Page ──────────────────────────────────────────────────────────────────────

class ReportPage(ctk.CTkFrame):

    def __init__(self, master: ctk.CTkFrame, runner,
                 output_cb: Callable[[str], None]) -> None:
        super().__init__(master, fg_color="transparent")
        self._runner   = runner
        self._out      = output_cb
        self._findings: list[dict] = _load_findings()
        self._eng:      dict       = _load_engagement()
        self._selected: Optional[int] = None
        self._build()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        # Header
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(20, 10))
        ctk.CTkLabel(hdr, text="Report Generator",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")
        ctk.CTkLabel(hdr, text="  —  collect findings · generate professional pentest report",
                     text_color=_LO, font=ctk.CTkFont(size=12)).pack(side="left")

        # Engagement bar
        self._build_engagement_bar()

        # Body: findings list | finding editor
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=24, pady=(0, 0))
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        self._build_findings_list(body)
        self._build_editor(body)

        # Generate button
        self._build_bottom_bar()

    def _build_engagement_bar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color=_SURFACE, corner_radius=8,
                           border_width=1, border_color=_BORDER)
        bar.pack(fill="x", padx=24, pady=(0, 8))

        fields = [
            ("Client",   "client",   200),
            ("Assessor", "assessor", 150),
            ("Date",     "date",     110),
            ("Scope",    "scope",    220),
            ("Type",     "type",     240),
        ]
        self._eng_vars: dict[str, ctk.StringVar] = {}
        for label, key, w in fields:
            ctk.CTkLabel(bar, text=f"{label}:", text_color=_LO,
                         font=ctk.CTkFont(family="Consolas", size=11)
                         ).pack(side="left", padx=(12, 3), pady=8)
            var = ctk.StringVar(value=self._eng.get(key, ""))
            ctk.CTkEntry(bar, textvariable=var, width=w,
                         font=ctk.CTkFont(family="Consolas", size=11)
                         ).pack(side="left", padx=(0, 6), pady=8)
            var.trace_add("write", lambda *_, k=key, v=var: self._on_eng_change(k, v))
            self._eng_vars[key] = var

    def _on_eng_change(self, key: str, var: ctk.StringVar) -> None:
        self._eng[key] = var.get()
        _save_engagement(self._eng)

    def _build_findings_list(self, parent: ctk.CTkFrame) -> None:
        card = ctk.CTkFrame(parent, fg_color=_SURFACE, corner_radius=8,
                            border_width=1, border_color=_BORDER)
        card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        card.grid_rowconfigure(1, weight=1)
        card.grid_columnconfigure(0, weight=1)

        # Toolbar
        tb = ctk.CTkFrame(card, fg_color="transparent")
        tb.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))
        ctk.CTkLabel(tb, text="FINDINGS",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=_LO).pack(side="left")

        ctk.CTkButton(tb, text="+ Add", width=60,
                      fg_color=_GREEN, hover_color="#2ea043",
                      font=ctk.CTkFont(size=11, weight="bold"),
                      command=self._add_finding
                      ).pack(side="right", padx=(4, 0))
        ctk.CTkButton(tb, text="Import NetMap", width=110,
                      fg_color=_SURFACE, hover_color=_BORDER,
                      border_width=1, border_color=_BORDER,
                      text_color=_LO, font=ctk.CTkFont(size=10),
                      command=self._import_netmap
                      ).pack(side="right", padx=4)

        # Scrollable list
        self._list_frame = ctk.CTkScrollableFrame(card, fg_color="transparent")
        self._list_frame.grid(row=1, column=0, sticky="nsew", padx=4, pady=(0, 8))
        self._refresh_list()

    def _refresh_list(self) -> None:
        for w in self._list_frame.winfo_children():
            w.destroy()
        if not self._findings:
            ctk.CTkLabel(self._list_frame,
                         text="No findings yet.\nClick  + Add  to start.",
                         text_color=_LO,
                         font=ctk.CTkFont(family="Consolas", size=11)
                         ).pack(pady=20)
            return
        sorted_f = sorted(self._findings,
                          key=lambda x: _SEV_ORDER.index(x["severity"]))
        for i, f in enumerate(sorted_f):
            self._make_finding_row(i, f)

    def _make_finding_row(self, idx: int, f: dict) -> None:
        col = _SEV_COLORS.get(f["severity"], "#6b7280")
        is_sel = self._selected == idx
        bg = "#21262d" if is_sel else "transparent"

        row = ctk.CTkFrame(self._list_frame, fg_color=bg, corner_radius=6)
        row.pack(fill="x", padx=4, pady=2)
        row.grid_columnconfigure(1, weight=1)

        # Severity dot
        dot = tk.Canvas(row, width=10, height=10,
                        bg=bg if bg != "transparent" else _SURFACE,
                        highlightthickness=0)
        dot.create_oval(1, 1, 9, 9, fill=col, outline="")
        dot.grid(row=0, column=0, padx=(8, 6), pady=10)

        title = f["title"][:42] + "…" if len(f["title"]) > 42 else f["title"]
        ctk.CTkLabel(row, text=title,
                     font=ctk.CTkFont(family="Consolas", size=11),
                     text_color=_HI, anchor="w"
                     ).grid(row=0, column=1, sticky="w")

        ctk.CTkButton(row, text="✕", width=24, height=24,
                      fg_color="transparent", hover_color=_RED,
                      text_color=_LO, font=ctk.CTkFont(size=10),
                      command=lambda fi=f: self._delete_finding(fi)
                      ).grid(row=0, column=2, padx=6)

        for w in [row, dot]:
            w.bind("<Button-1>", lambda _e, i=idx: self._select(i))
        for child in row.winfo_children():
            child.bind("<Button-1>", lambda _e, i=idx: self._select(i))

    def _select(self, idx: int) -> None:
        self._selected = idx
        sorted_f = sorted(self._findings,
                          key=lambda x: _SEV_ORDER.index(x["severity"]))
        if idx < len(sorted_f):
            self._load_into_editor(sorted_f[idx])
        self._refresh_list()

    def _build_editor(self, parent: ctk.CTkFrame) -> None:
        card = ctk.CTkFrame(parent, fg_color=_SURFACE, corner_radius=8,
                            border_width=1, border_color=_BORDER)
        card.grid(row=0, column=1, sticky="nsew")
        card.grid_rowconfigure(99, weight=1)
        card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(card, text="FINDING EDITOR",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=_LO).grid(
            row=0, column=0, columnspan=2, sticky="w", padx=16, pady=(14, 0))
        ctk.CTkFrame(card, height=1, fg_color=_BORDER).grid(
            row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(6, 10))

        self._ed: dict[str, tk.Variable] = {}
        row = 2

        def lbl(text, r):
            ctk.CTkLabel(card, text=text, text_color=_LO,
                         font=ctk.CTkFont(family="Consolas", size=11),
                         anchor="e", width=90
                         ).grid(row=r, column=0, sticky="e", padx=(16, 8), pady=4)

        # Title
        lbl("Title", row)
        self._ed["title"] = ctk.StringVar()
        ctk.CTkEntry(card, textvariable=self._ed["title"],
                     font=ctk.CTkFont(family="Consolas", size=12)
                     ).grid(row=row, column=1, sticky="ew", padx=(0, 16), pady=4)
        row += 1

        # Severity + Category + Host in one row
        lbl("Severity", row)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.grid(row=row, column=1, sticky="ew", padx=(0, 16), pady=4)
        self._ed["severity"] = ctk.StringVar(value="high")
        ctk.CTkComboBox(inner, variable=self._ed["severity"],
                        values=_SEV_ORDER, state="readonly", width=110,
                        font=ctk.CTkFont(family="Consolas", size=12)
                        ).pack(side="left", padx=(0, 12))
        ctk.CTkLabel(inner, text="Category:", text_color=_LO,
                     font=ctk.CTkFont(family="Consolas", size=11)
                     ).pack(side="left", padx=(0, 6))
        self._ed["category"] = ctk.StringVar(value="Network")
        ctk.CTkComboBox(inner, variable=self._ed["category"],
                        values=["Network", "Web", "Authentication",
                                "Configuration", "Privilege Escalation",
                                "Social Engineering", "Physical", "Misc"],
                        state="readonly", width=160,
                        font=ctk.CTkFont(family="Consolas", size=12)
                        ).pack(side="left")
        row += 1

        # Host + CVSS
        lbl("Host", row)
        inner2 = ctk.CTkFrame(card, fg_color="transparent")
        inner2.grid(row=row, column=1, sticky="ew", padx=(0, 16), pady=4)
        self._ed["host"] = ctk.StringVar()
        ctk.CTkEntry(inner2, textvariable=self._ed["host"], width=160,
                     font=ctk.CTkFont(family="Consolas", size=12)
                     ).pack(side="left", padx=(0, 12))
        ctk.CTkLabel(inner2, text="CVSS:", text_color=_LO,
                     font=ctk.CTkFont(family="Consolas", size=11)
                     ).pack(side="left", padx=(0, 6))
        self._ed["cvss"] = ctk.StringVar()
        ctk.CTkEntry(inner2, textvariable=self._ed["cvss"], width=70,
                     font=ctk.CTkFont(family="Consolas", size=12)
                     ).pack(side="left")
        row += 1

        # Multiline fields
        for field, label, h in [
            ("description", "Description", 70),
            ("evidence",    "Evidence",    70),
            ("remediation", "Remediation", 55),
        ]:
            lbl(label, row)
            tb = ctk.CTkTextbox(card,
                                font=ctk.CTkFont(family="Consolas", size=11),
                                fg_color="#0d1117", text_color=_HI,
                                height=h, corner_radius=6)
            tb.grid(row=row, column=1, sticky="ew", padx=(0, 16), pady=4)
            self._ed[field] = tb
            row += 1

        # Save button
        ctk.CTkButton(card, text="💾  Save Finding",
                      fg_color=_GREEN, hover_color="#2ea043",
                      font=ctk.CTkFont(size=13, weight="bold"),
                      command=self._save_current
                      ).grid(row=row, column=0, columnspan=2,
                             sticky="ew", padx=16, pady=(8, 16))

    def _load_into_editor(self, f: dict) -> None:
        self._ed["title"].set(f.get("title", ""))
        self._ed["severity"].set(f.get("severity", "high"))
        self._ed["category"].set(f.get("category", "Network"))
        self._ed["host"].set(f.get("host", ""))
        self._ed["cvss"].set(f.get("cvss", ""))
        for field in ("description", "evidence", "remediation"):
            tb = self._ed[field]
            tb.delete("0.0", "end")
            tb.insert("0.0", f.get(field, ""))

    def _get_from_editor(self) -> dict:
        result = {}
        for key in ("title", "severity", "category", "host", "cvss"):
            result[key] = self._ed[key].get()
        for key in ("description", "evidence", "remediation"):
            result[key] = self._ed[key].get("0.0", "end").strip()
        return result

    def _add_finding(self) -> None:
        new_f = {
            "id":           str(uuid.uuid4())[:8].upper(),
            "title":        "New finding",
            "severity":     "high",
            "category":     "Network",
            "host":         "",
            "description":  "",
            "evidence":     "",
            "remediation":  "",
            "cvss":         "",
        }
        self._findings.append(new_f)
        _save_findings(self._findings)
        self._selected = 0
        self._load_into_editor(new_f)
        self._refresh_list()

    def _save_current(self) -> None:
        if self._selected is None:
            return
        data = self._get_from_editor()
        sorted_f = sorted(self._findings,
                          key=lambda x: _SEV_ORDER.index(x["severity"]))
        if self._selected >= len(sorted_f):
            return
        orig = sorted_f[self._selected]
        idx  = self._findings.index(orig)
        self._findings[idx].update(data)
        _save_findings(self._findings)
        self._refresh_list()
        self._out(f"[+] Finding saved: {data['title']}\n")

    def _delete_finding(self, f: dict) -> None:
        if not messagebox.askyesno("Delete", f"Delete finding:\n{f['title']}?"):
            return
        self._findings = [x for x in self._findings if x.get("id") != f.get("id")]
        self._selected = None
        _save_findings(self._findings)
        self._refresh_list()

    def _import_netmap(self) -> None:
        new = _import_from_netmap()
        if not new:
            self._out("[!] No NetMap scan data found. Run a Deep scan first.\n")
            return
        existing_titles = {f["title"] for f in self._findings}
        added = [f for f in new if f["title"] not in existing_titles]
        self._findings.extend(added)
        _save_findings(self._findings)
        self._refresh_list()
        self._out(f"[+] Imported {len(added)} finding(s) from last NetMap scan.\n")

    def _build_bottom_bar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.pack(fill="x", padx=24, pady=(8, 16))

        self._count_lbl = ctk.CTkLabel(
            bar, text=self._count_text(),
            text_color=_LO, font=ctk.CTkFont(family="Consolas", size=11))
        self._count_lbl.pack(side="left")

        ctk.CTkButton(bar, text="🗑  Clear All", width=110,
                      fg_color=_SURFACE, hover_color=_BORDER,
                      border_width=1, border_color=_BORDER,
                      text_color=_LO, font=ctk.CTkFont(size=11),
                      command=self._clear_all
                      ).pack(side="right", padx=(8, 0))

        ctk.CTkButton(bar, text="📄  Generate Report",
                      fg_color=_GREEN, hover_color="#2ea043",
                      font=ctk.CTkFont(size=14, weight="bold"),
                      height=40,
                      command=self._generate
                      ).pack(side="right")

    def _count_text(self) -> str:
        c = {s: sum(1 for f in self._findings if f["severity"] == s)
             for s in _SEV_ORDER}
        parts = [f"{c[s]} {s}" for s in _SEV_ORDER if c[s]]
        return f"{len(self._findings)} finding(s): {', '.join(parts)}" if parts else "No findings"

    def _clear_all(self) -> None:
        if not messagebox.askyesno("Clear", "Delete ALL findings?"):
            return
        self._findings = []
        _save_findings(self._findings)
        self._selected = None
        self._refresh_list()

    def _generate(self) -> None:
        eng = {k: v.get() for k, v in self._eng_vars.items()}
        html = _generate_html(eng, self._findings)
        tmp = pathlib.Path(tempfile.mktemp(suffix=".html"))
        tmp.write_text(html, encoding="utf-8")
        webbrowser.open(tmp.as_uri())
        self._out(f"[+] Report generated → {tmp}\n")
        self._out("[*] Use Ctrl+P in the browser to save as PDF.\n")
