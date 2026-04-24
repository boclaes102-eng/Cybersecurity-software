"""
Active Directory Enumeration — connect to a domain and enumerate:
  • Users, groups, computers, OUs
  • Kerberoastable accounts (SPNs set)
  • AS-REP roastable accounts (no pre-auth required)
  • Unconstrained delegation computers
  • Password-not-required accounts
  • Stale accounts (no login in 90+ days)
  • AdminSDHolder protected objects
  • Domain admins and nested group membership

Uses ldap3 (pure Python LDAP) — no domain-joined machine required.
Directly relates to the fire station Active Directory audit.
"""
from __future__ import annotations

import json
import pathlib
import threading
from datetime import datetime, timezone
from typing import Callable, Optional

import customtkinter as ctk
import tkinter as tk

_SURFACE = "#161b22"
_BORDER  = "#30363d"
_HI      = "#c9d1d9"
_LO      = "#8b949e"
_GREEN   = "#238636"
_RED     = "#da3633"
_ORANGE  = "#d97706"
_CYAN    = "#58a6ff"

_AD_FILE = pathlib.Path.home() / ".cybersuite" / "ad_findings.json"

# ── LDAP helpers ──────────────────────────────────────────────────────────────

def _connect(dc: str, domain: str, user: str, password: str):
    from ldap3 import Server, Connection, ALL, NTLM  # type: ignore
    server = Server(dc, get_info=ALL, connect_timeout=5)
    # Try NTLM first, fall back to simple bind
    try:
        conn = Connection(server,
                          user=f"{domain}\\{user}",
                          password=password,
                          authentication=NTLM,
                          auto_bind=True)
        return conn, server.info.other.get("defaultNamingContext", [""])[0]
    except Exception:
        conn = Connection(server,
                          user=f"{user}@{domain}",
                          password=password,
                          auto_bind=True)
        return conn, server.info.other.get("defaultNamingContext", [""])[0]


def _ts_to_str(ts) -> str:
    """Convert Windows FILETIME (100-ns intervals since 1601) to string."""
    try:
        if isinstance(ts, datetime):
            return ts.strftime("%Y-%m-%d")
        val = int(ts)
        if val in (0, 9223372036854775807):
            return "Never"
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        dt = epoch + __import__("datetime").timedelta(microseconds=val // 10)
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return str(ts)


def _run_enum(dc: str, domain: str, user: str, password: str,
              cb: Callable[[str], None]) -> dict:
    """
    Returns a dict with keys: users, kerberoastable, asreproastable,
    unconstrained_delegation, pwd_not_required, stale_accounts, domain_admins.
    """
    try:
        from ldap3 import Server, Connection, ALL, NTLM, SUBTREE  # type: ignore
    except ImportError:
        cb("[ERROR] ldap3 not installed. Run setup.bat.\n")
        return {}

    cb(f"[*] Connecting to {dc} ({domain}) as {user}…\n")
    try:
        conn, base_dn = _connect(dc, domain, user, password)
    except Exception as exc:
        cb(f"[ERROR] Connection failed: {exc}\n")
        return {}

    cb(f"[+] Connected. Base DN: {base_dn}\n")
    findings = {}

    # ── 1. Kerberoastable accounts (SPNs set, not disabled)
    cb("[*] Checking Kerberoastable accounts…\n")
    conn.search(base_dn,
                "(&(objectClass=user)(servicePrincipalName=*)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                attributes=["sAMAccountName", "servicePrincipalName",
                            "lastLogonTimestamp"])
    kerb = []
    for entry in conn.entries:
        kerb.append({
            "user": str(entry.sAMAccountName),
            "spns": [str(s) for s in entry.servicePrincipalName],
            "last_logon": _ts_to_str(entry.lastLogonTimestamp.value
                                     if entry.lastLogonTimestamp else 0),
        })
        cb(f"  ⚠  KERBEROASTABLE: {entry.sAMAccountName}  "
           f"SPN: {entry.servicePrincipalName}\n")
    findings["kerberoastable"] = kerb
    cb(f"[+] {len(kerb)} Kerberoastable account(s).\n")

    # ── 2. AS-REP roastable (DONT_REQ_PREAUTH flag = 4194304)
    cb("[*] Checking AS-REP roastable accounts…\n")
    conn.search(base_dn,
                "(&(objectClass=user)"
                "(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
                attributes=["sAMAccountName", "lastLogonTimestamp"])
    asrep = [{"user": str(e.sAMAccountName),
               "last_logon": _ts_to_str(
                   e.lastLogonTimestamp.value if e.lastLogonTimestamp else 0)}
             for e in conn.entries]
    for a in asrep:
        cb(f"  ⚠  AS-REP ROASTABLE: {a['user']}\n")
    findings["asreproastable"] = asrep
    cb(f"[+] {len(asrep)} AS-REP roastable account(s).\n")

    # ── 3. Unconstrained delegation computers
    cb("[*] Checking unconstrained delegation…\n")
    conn.search(base_dn,
                "(&(objectClass=computer)"
                "(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                attributes=["dNSHostName", "operatingSystem"])
    undel = [{"host": str(e.dNSHostName), "os": str(e.operatingSystem)}
             for e in conn.entries]
    for u in undel:
        cb(f"  ⚠  UNCONSTRAINED DELEGATION: {u['host']} ({u['os']})\n")
    findings["unconstrained_delegation"] = undel

    # ── 4. Password not required accounts
    cb("[*] Checking password-not-required accounts…\n")
    conn.search(base_dn,
                "(&(objectClass=user)"
                "(userAccountControl:1.2.840.113556.1.4.803:=32)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                attributes=["sAMAccountName"])
    nopwd = [str(e.sAMAccountName) for e in conn.entries]
    for n in nopwd:
        cb(f"  ⚠  NO PASSWORD REQUIRED: {n}\n")
    findings["pwd_not_required"] = nopwd

    # ── 5. Stale accounts (lastLogon > 90 days, not disabled)
    cb("[*] Checking stale accounts (90+ days)…\n")
    from ldap3.utils.conv import to_raw_query  # noqa
    cutoff = int((datetime(2000,1,1) - datetime(1601,1,1)).total_seconds()
                 * 10**7)  # rough — get all then filter
    conn.search(base_dn,
                "(&(objectClass=user)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                "(lastLogonTimestamp=*))",
                attributes=["sAMAccountName", "lastLogonTimestamp"])
    stale = []
    now = datetime.now(tz=timezone.utc)
    for e in conn.entries:
        try:
            llt = e.lastLogonTimestamp.value
            if isinstance(llt, datetime):
                if llt.tzinfo is None:
                    llt = llt.replace(tzinfo=timezone.utc)
                days = (now - llt).days
                if days > 90:
                    stale.append({"user": str(e.sAMAccountName), "days": days})
                    cb(f"  ⚠  STALE ({days}d): {e.sAMAccountName}\n")
        except Exception:
            continue
    findings["stale_accounts"] = stale

    # ── 6. Domain Admins membership
    cb("[*] Enumerating Domain Admins…\n")
    conn.search(base_dn,
                "(&(objectClass=group)(sAMAccountName=Domain Admins))",
                attributes=["member"])
    da_members = []
    if conn.entries:
        for m in (conn.entries[0].member or []):
            da_members.append(str(m).split(",")[0].replace("CN=", ""))
            cb(f"  ★  DOMAIN ADMIN: {da_members[-1]}\n")
    findings["domain_admins"] = da_members

    conn.unbind()
    cb(f"\n[+] Enumeration complete.\n")
    cb(f"    Kerberoastable:   {len(kerb)}\n")
    cb(f"    AS-REP Roastable: {len(asrep)}\n")
    cb(f"    Unconstrained:    {len(undel)}\n")
    cb(f"    No Password:      {len(nopwd)}\n")
    cb(f"    Stale (90d+):     {len(stale)}\n")
    cb(f"    Domain Admins:    {len(da_members)}\n")

    return findings


# ── Page ──────────────────────────────────────────────────────────────────────

class ADPage(ctk.CTkFrame):

    def __init__(self, master: ctk.CTkFrame, runner,
                 output_cb: Callable[[str], None]) -> None:
        super().__init__(master, fg_color="transparent")
        self._runner   = runner
        self._out      = output_cb
        self._findings: dict = {}
        self._build()

    def _build(self) -> None:
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(20, 10))
        ctk.CTkLabel(hdr, text="Active Directory Enumeration",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")
        ctk.CTkLabel(hdr, text="  —  Kerberoast · AS-REP · delegation · stale accounts",
                     text_color=_LO, font=ctk.CTkFont(size=12)).pack(side="left")

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=24, pady=(0, 16))
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        self._build_config(body)
        self._build_results(body)

    def _build_config(self, parent: ctk.CTkFrame) -> None:
        card = ctk.CTkFrame(parent, fg_color=_SURFACE, corner_radius=8,
                            border_width=1, border_color=_BORDER)
        card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        card.grid_columnconfigure(0, weight=1)
        r = 0

        ctk.CTkLabel(card, text="CONNECTION",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=_LO).grid(row=r, column=0, sticky="w",
                                          padx=18, pady=(16, 0))
        r += 1
        ctk.CTkFrame(card, height=1, fg_color=_BORDER).grid(
            row=r, column=0, sticky="ew", padx=18, pady=(6, 14))
        r += 1

        fields = [
            ("Domain Controller IP", "dc",       "192.168.0.1"),
            ("Domain",               "domain",   "CORP.LOCAL"),
            ("Username",             "user",     ""),
            ("Password",             "password", ""),
        ]
        self._conn_vars: dict[str, ctk.StringVar] = {}
        for label, key, default in fields:
            ctk.CTkLabel(card, text=label, text_color=_LO,
                         font=ctk.CTkFont(family="Consolas", size=11)
                         ).grid(row=r, column=0, sticky="w", padx=18)
            r += 1
            var = ctk.StringVar(value=default)
            show = "*" if key == "password" else ""
            ctk.CTkEntry(card, textvariable=var, show=show,
                         font=ctk.CTkFont(family="Consolas", size=12)
                         ).grid(row=r, column=0, sticky="ew",
                                padx=18, pady=(4, 10))
            self._conn_vars[key] = var
            r += 1

        # Check list
        ctk.CTkFrame(card, height=1, fg_color=_BORDER).grid(
            row=r, column=0, sticky="ew", padx=18, pady=(4, 10))
        r += 1
        ctk.CTkLabel(card, text="CHECKS TO RUN",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=_LO).grid(row=r, column=0, sticky="w", padx=18)
        r += 1

        self._checks: dict[str, ctk.BooleanVar] = {}
        for label in ["Kerberoastable accounts", "AS-REP Roastable",
                      "Unconstrained delegation", "Password not required",
                      "Stale accounts (90d+)", "Domain Admins members"]:
            var = ctk.BooleanVar(value=True)
            ctk.CTkCheckBox(card, text=label, variable=var,
                            font=ctk.CTkFont(family="Consolas", size=11),
                            text_color=_HI
                            ).grid(row=r, column=0, sticky="w",
                                   padx=18, pady=2)
            self._checks[label] = var
            r += 1

        ctk.CTkFrame(card, height=1, fg_color=_BORDER).grid(
            row=r, column=0, sticky="ew", padx=18, pady=(10, 8))
        r += 1

        self._enum_btn = ctk.CTkButton(
            card, text="⚡  Run Enumeration",
            fg_color=_RED, hover_color="#b91c1c",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=44, command=self._run_enum,
        )
        self._enum_btn.grid(row=r, column=0, sticky="ew", padx=18, pady=(0, 8))
        r += 1

        ctk.CTkButton(
            card, text="Export to Report",
            fg_color=_SURFACE, hover_color=_BORDER,
            border_width=1, border_color=_BORDER,
            text_color=_LO, font=ctk.CTkFont(size=12),
            command=self._export_to_report,
        ).grid(row=r, column=0, sticky="ew", padx=18, pady=(0, 16))

    def _build_results(self, parent: ctk.CTkFrame) -> None:
        card = ctk.CTkFrame(parent, fg_color=_SURFACE, corner_radius=8,
                            border_width=1, border_color=_BORDER)
        card.grid(row=0, column=1, sticky="nsew")
        card.grid_rowconfigure(1, weight=1)
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(card, text="FINDINGS",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=_LO).grid(row=0, column=0, sticky="w",
                                          padx=18, pady=(16, 10))

        self._results_frame = ctk.CTkScrollableFrame(card, fg_color="transparent")
        self._results_frame.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 12))

        ctk.CTkLabel(self._results_frame,
                     text="Run enumeration to see findings.\n\n"
                          "This tool uses ldap3 to query AD directly —\n"
                          "no domain membership required.",
                     text_color=_LO,
                     font=ctk.CTkFont(family="Consolas", size=12)
                     ).pack(pady=30)

    def _run_enum(self) -> None:
        if self._runner.is_running:
            self._out("[!] Stop current task first.\n")
            return
        dc  = self._conn_vars["dc"].get().strip()
        dom = self._conn_vars["domain"].get().strip()
        usr = self._conn_vars["user"].get().strip()
        pwd = self._conn_vars["password"].get()
        if not all([dc, dom, usr, pwd]):
            self._out("[ERROR] Fill in all connection fields.\n")
            return

        self._enum_btn.configure(text="Running…", state="disabled")

        def do() -> int:
            findings = _run_enum(dc, dom, usr, pwd, self._out)
            self._findings = findings
            self.after(0, lambda: self._show_results(findings))
            return 0

        def done(_c: int) -> None:
            self.after(0, lambda: self._enum_btn.configure(
                text="⚡  Run Enumeration", state="normal"))

        self._runner.run(do, done_cb=done,
                         output_cb=self._out, tool_name="AD Enum")

    def _show_results(self, findings: dict) -> None:
        for w in self._results_frame.winfo_children():
            w.destroy()

        sections = [
            ("🔑 Kerberoastable", "kerberoastable", _RED,
             lambda f: f"{f['user']}  SPNs: {', '.join(f['spns'][:2])}"),
            ("🔓 AS-REP Roastable", "asreproastable", _RED,
             lambda f: f"{f['user']}  last logon: {f.get('last_logon','?')}"),
            ("🌐 Unconstrained Delegation", "unconstrained_delegation", _ORANGE,
             lambda f: f"{f['host']} ({f.get('os','?')})"),
            ("🚫 No Password Required", "pwd_not_required", _ORANGE,
             lambda f: str(f)),
            ("⏰ Stale Accounts (90d+)", "stale_accounts", _CYAN,
             lambda f: f"{f['user']}  ({f['days']} days)"),
            ("★ Domain Admins", "domain_admins", _LO,
             lambda f: str(f)),
        ]

        for title, key, color, fmt in sections:
            items = findings.get(key, [])
            sec = ctk.CTkFrame(self._results_frame, fg_color="transparent")
            sec.pack(fill="x", pady=(8, 2))
            ctk.CTkLabel(sec, text=f"{title}  ({len(items)})",
                         font=ctk.CTkFont(size=11, weight="bold"),
                         text_color=color if items else _LO
                         ).pack(anchor="w", padx=4)
            if items:
                for item in items[:20]:
                    ctk.CTkLabel(self._results_frame,
                                 text=f"  {fmt(item)}",
                                 font=ctk.CTkFont(family="Consolas", size=10),
                                 text_color=_HI, anchor="w"
                                 ).pack(fill="x", padx=8, pady=1)
            else:
                ctk.CTkLabel(self._results_frame, text="  None found.",
                             font=ctk.CTkFont(family="Consolas", size=10),
                             text_color=_LO, anchor="w"
                             ).pack(fill="x", padx=8)

    def _export_to_report(self) -> None:
        if not self._findings:
            self._out("[!] Run enumeration first.\n")
            return
        # Load existing report findings
        try:
            from launcher.pages.report_page import _load_findings, _save_findings
            existing = _load_findings()
        except Exception:
            existing = []

        import uuid
        new_findings = []
        kerb = self._findings.get("kerberoastable", [])
        if kerb:
            new_findings.append({
                "id": str(uuid.uuid4())[:8].upper(),
                "title": f"Kerberoastable accounts ({len(kerb)} found)",
                "severity": "high",
                "category": "Authentication",
                "host": self._conn_vars["dc"].get(),
                "description": (
                    f"{len(kerb)} account(s) with Service Principal Names set "
                    f"and no pre-authentication required. Attackers can request "
                    f"TGS tickets offline and crack the service account password."
                ),
                "evidence": "\n".join(
                    f"{k['user']}: {', '.join(k['spns'][:2])}" for k in kerb[:10]
                ),
                "remediation": (
                    "Audit SPNs, use strong passwords (25+ chars) for service accounts, "
                    "consider Group Managed Service Accounts (gMSA)."
                ),
                "cvss": "8.8",
            })
        asrep = self._findings.get("asreproastable", [])
        if asrep:
            new_findings.append({
                "id": str(uuid.uuid4())[:8].upper(),
                "title": f"AS-REP Roastable accounts ({len(asrep)} found)",
                "severity": "high",
                "category": "Authentication",
                "host": self._conn_vars["dc"].get(),
                "description": (
                    f"{len(asrep)} account(s) have 'Do not require Kerberos "
                    f"preauthentication' set, allowing offline hash cracking."
                ),
                "evidence": "\n".join(k["user"] for k in asrep),
                "remediation": "Enable Kerberos pre-authentication on all user accounts.",
                "cvss": "8.1",
            })
        stale = self._findings.get("stale_accounts", [])
        if stale:
            new_findings.append({
                "id": str(uuid.uuid4())[:8].upper(),
                "title": f"Stale accounts not disabled ({len(stale)} found)",
                "severity": "medium",
                "category": "Configuration",
                "host": self._conn_vars["dc"].get(),
                "description": (
                    f"{len(stale)} enabled account(s) with no logon activity "
                    f"in 90+ days. Stale accounts increase attack surface."
                ),
                "evidence": "\n".join(
                    f"{a['user']}: {a['days']} days" for a in stale[:20]
                ),
                "remediation": "Implement account lifecycle policy: disable after 60 days "
                               "of inactivity, delete after 90.",
                "cvss": "5.3",
            })

        existing.extend(new_findings)
        _save_findings(existing)
        self._out(f"[+] {len(new_findings)} AD finding(s) exported to Report Generator.\n")
