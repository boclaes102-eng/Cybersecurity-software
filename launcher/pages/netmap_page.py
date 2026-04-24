"""
Network Map — discover and visualize the local network topology.

Phase 1 (ARP):  fast host discovery via Scapy, topology shown immediately.
Phase 2 (nmap): optional deep enrichment — OS fingerprint, open ports,
                MAC vendor.  Nodes update live as results come in.

Clicking a node selects it as the active attack target
(written to ~/.cybersuite/config.json, shared with Recon Workspace).
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import math
import pathlib
import socket
from typing import Callable, Optional

import customtkinter as ctk
import tkinter as tk

# ── Palette ───────────────────────────────────────────────────────────────────
_BG      = "#0d1117"
_SURFACE = "#161b22"
_BORDER  = "#30363d"
_HI      = "#c9d1d9"
_LO      = "#8b949e"
_CYAN    = "#58a6ff"
_GREEN   = "#238636"
_RED     = "#da3633"
_ORANGE  = "#d97706"

_COL_ROUTER  = "#1f6aa5"
_COL_SELF    = "#4ade80"
_COL_HOST    = "#238636"
_COL_APPLE   = "#a78bfa"
_COL_PHONE   = _ORANGE
_COL_WIN     = "#2563eb"
_COL_LINUX   = "#16a34a"
_COL_SELECT  = "#f0883e"
_COL_DANGER  = "#dc2626"
_COL_WARN    = "#d97706"
_COL_OFFLINE = "#334155"   # SNMP-only hosts (not seen by ARP — offline)

_R    = 20   # normal node radius
_R_GW = 26   # gateway radius

# Ports that warrant a danger ring
_HIGH_RISK = {21, 23, 445, 3389, 5900, 1433, 3306, 2049, 512, 513, 514}
_MED_RISK  = {80, 8080, 8443, 8888, 27017, 6379, 5432, 9200}

_CFG = pathlib.Path.home() / ".cybersuite" / "config.json"

# ── Network helpers ───────────────────────────────────────────────────────────

def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _default_subnet(ip: str) -> str:
    p = ip.split(".")
    return f"{p[0]}.{p[1]}.{p[2]}.0/24"


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


_OUI_MAP: dict[str, tuple[str, str]] = {
    "000393": ("Apple",  _COL_APPLE), "001124": ("Apple",  _COL_APPLE),
    "0017F2": ("Apple",  _COL_APPLE), "001CB3": ("Apple",  _COL_APPLE),
    "3C0754": ("Apple",  _COL_APPLE), "A88195": ("Apple",  _COL_APPLE),
    "ACBC32": ("Apple",  _COL_APPLE), "F0DCE2": ("Apple",  _COL_APPLE),
    "000C29": ("VMware", _COL_HOST),  "D4CA6D": ("Router", _COL_ROUTER),
    "B4750E": ("Router", _COL_ROUTER),"E4956E": ("Router", _COL_ROUTER),
    "C0A0BB": ("Router", _COL_ROUTER),"001A11": ("Router", _COL_ROUTER),
}


def _classify_arp(mac: str, hostname: str) -> tuple[str, str]:
    oui = mac.upper().replace(":", "").replace("-", "")[:6]
    if oui in _OUI_MAP:
        return _OUI_MAP[oui]
    h = hostname.lower()
    if any(k in h for k in ("router", "gateway", "fritzbox", "livebox", "bbox", "dlink", "zyxel")):
        return "Router/GW", _COL_ROUTER
    if any(k in h for k in ("iphone", "ipad", "macbook", "apple")):
        return "Apple", _COL_APPLE
    if any(k in h for k in ("android", "phone", "pixel", "samsung", "oneplus")):
        return "Phone", _COL_PHONE
    if any(k in h for k in ("printer", "print", "hp", "epson", "canon")):
        return "Printer", _COL_PHONE
    return "Host", _COL_HOST


def _os_color(os_name: str) -> Optional[str]:
    n = os_name.lower()
    if "windows" in n:
        return _COL_WIN
    if any(k in n for k in ("linux", "ubuntu", "debian", "centos", "fedora", "kali")):
        return _COL_LINUX
    if any(k in n for k in ("macos", "os x", "darwin")):
        return _COL_APPLE
    if "android" in n:
        return _COL_PHONE
    if "ios" in n:
        return _COL_APPLE
    return None


def _risk_level(ports: list[dict]) -> str:
    """Returns 'high', 'med', or '' based on open ports."""
    open_ports = {p["port"] for p in ports if p["state"] == "open"}
    if open_ports & _HIGH_RISK:
        return "high"
    if open_ports & _MED_RISK:
        return "med"
    return ""


# ── Phase 1: ARP scan ─────────────────────────────────────────────────────────

def _arp_scan(subnet: str, cb: Callable[[str], None]) -> list[dict]:
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore
    except ImportError:
        cb("[ERROR] Scapy not installed.\n")
        return []
    cb(f"[*] Phase 1 — ARP scan {subnet}\n")
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        ans, _ = srp(pkt, timeout=3, verbose=0)
    except Exception as e:
        cb(f"[ERROR] ARP failed: {e}\n")
        return []
    hosts = []
    for _, rcv in ans:
        ip  = rcv.psrc
        mac = rcv.hwsrc
        hn  = _reverse_dns(ip)
        dev_type, color = _classify_arp(mac, hn)
        hosts.append({
            "ip": ip, "mac": mac, "hostname": hn,
            "type": dev_type, "color": color,
            # nmap fields, filled in phase 2
            "os": "", "os_accuracy": 0,
            "vendor": "", "ports": [], "risk": "",
            "enriched": False,
        })
        cb(f"  ↳  {ip:<16}  {mac}  {hn or dev_type}\n")
    hosts.sort(key=lambda h: list(map(int, h["ip"].split("."))))
    cb(f"[+] {len(hosts)} host(s) found.\n")
    return hosts


# ── Phase 2: nmap enrichment ──────────────────────────────────────────────────

def _nmap_enrich(hosts: list[dict], cb: Callable[[str], None],
                 update_cb: Callable[[list[dict]], None]) -> None:
    try:
        import nmap as nm_lib  # type: ignore
    except ImportError:
        cb("[ERROR] python-nmap not installed.\n")
        return

    nm = nm_lib.PortScanner()
    ips = [h["ip"] for h in hosts]
    cb(f"\n[*] Phase 2 — nmap enrichment ({len(ips)} host(s))\n")
    cb("[*] Running: -sV -O --top-ports 100 -T4  (this takes 1-3 min)\n")

    try:
        nm.scan(hosts=" ".join(ips), arguments="-sV -O --top-ports 100 -T4")
    except Exception as e:
        cb(f"[ERROR] nmap failed: {e}\n")
        cb("[!] Make sure nmap is installed and you are running as Administrator.\n")
        return

    enriched = 0
    for host in hosts:
        ip = host["ip"]
        if ip not in nm.all_hosts():
            continue

        h = nm[ip]

        # OS
        if h.get("osmatch"):
            best = h["osmatch"][0]
            host["os"]          = best["name"]
            host["os_accuracy"] = int(best.get("accuracy", 0))
            c = _os_color(best["name"])
            if c:
                host["color"] = c

        # Vendor (nmap OUI database is more complete than ours)
        mac = h["addresses"].get("mac", host["mac"])
        if mac:
            host["mac"]    = mac
            host["vendor"] = h.get("vendor", {}).get(mac, "")

        # Hostname from nmap (often better than reverse DNS)
        hn = h.hostname()
        if hn:
            host["hostname"] = hn

        # Open ports
        ports: list[dict] = []
        for proto in h.all_protocols():
            for port, info in sorted(h[proto].items()):
                ports.append({
                    "port":    port,
                    "proto":   proto,
                    "state":   info["state"],
                    "service": info.get("name", ""),
                    "version": (info.get("product", "") + " " +
                                info.get("version", "")).strip(),
                })
        host["ports"] = ports
        host["risk"]  = _risk_level(ports)

        # Update device type from OS if it was unknown
        if host["os"] and host["type"] == "Host":
            n = host["os"].lower()
            if "windows" in n:
                host["type"] = "Windows"
            elif any(k in n for k in ("linux", "ubuntu", "debian", "kali")):
                host["type"] = "Linux"
            elif any(k in n for k in ("macos", "os x")):
                host["type"] = "macOS"

        host["enriched"] = True
        enriched += 1

        open_count = sum(1 for p in ports if p["state"] == "open")
        cb(f"  ✓  {ip:<16}  {host['os'] or 'OS unknown':<30}  {open_count} port(s) open\n")

        # Push live update to canvas after each host
        update_cb(hosts[:])

    cb(f"\n[+] Enrichment complete — {enriched}/{len(hosts)} host(s) updated.\n")


# ── Phase 3: SNMP router ARP table ───────────────────────────────────────────

async def _snmp_walk_async(router_ip: str, community: str) -> list[tuple[str, object]]:
    from pysnmp.hlapi.v3arch.asyncio import (  # type: ignore
        SnmpEngine, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity, walk_cmd,
    )
    results: list[tuple[str, object]] = []
    engine = SnmpEngine()
    try:
        async for err_ind, err_status, _, var_binds in walk_cmd(
            engine,
            CommunityData(community, mpModel=1),
            UdpTransportTarget((router_ip, 161), timeout=3, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.4.22.1.2")),  # ipNetToMediaPhysAddress
            lexicographicMode=False,
        ):
            if err_ind or err_status:
                break
            for oid, val in var_binds:
                results.append((str(oid), val))
    finally:
        engine.close_dispatcher()
    return results


def _snmp_arp_table(router_ip: str, community: str,
                    cb: Callable[[str], None]) -> list[dict]:
    cb(f"[*] SNMP query → {router_ip}  community='{community}'\n")
    try:
        var_binds = asyncio.run(_snmp_walk_async(router_ip, community))
    except ImportError:
        cb("[ERROR] pysnmp not installed — run setup.bat.\n")
        return []
    except Exception as exc:
        cb(f"[ERROR] SNMP: {exc}\n")
        return []

    if not var_binds:
        cb("[!] No SNMP response — router may have SNMP disabled,\n"
           "    or the community string is wrong.\n")
        return []

    hosts: list[dict] = []
    for oid_str, mac_val in var_binds:
        # OID: 1.3.6.1.2.1.4.22.1.2.<ifIndex>.<a>.<b>.<c>.<d>
        parts = oid_str.split(".")
        if len(parts) < 4:
            continue
        ip = ".".join(parts[-4:])
        try:
            raw = bytes(mac_val)
            if len(raw) != 6:
                continue
            mac = ":".join(f"{b:02x}" for b in raw)
            if ip == "0.0.0.0":
                continue
            hn = _reverse_dns(ip)
            dev_type, color = _classify_arp(mac, hn)
            hosts.append({
                "ip": ip, "mac": mac, "hostname": hn,
                "type": dev_type, "color": _COL_OFFLINE,
                "os": "", "os_accuracy": 0,
                "vendor": "", "ports": [], "risk": "",
                "enriched": False, "online": False,
                "_base_color": color,   # restored if host comes online
            })
            cb(f"  ↳  {ip:<16}  {mac}  {'(offline)' if True else ''}\n")
        except Exception:
            continue

    cb(f"[+] SNMP returned {len(hosts)} ARP entr(ies).\n")
    return hosts


# ── Canvas ────────────────────────────────────────────────────────────────────

class _NetCanvas(tk.Canvas):

    def __init__(self, master: tk.Widget,
                 on_select: Callable[[Optional[dict]], None], **kw) -> None:
        super().__init__(master, bg=_BG, highlightthickness=0, **kw)
        self._nodes:    list[dict]     = []
        self._gateway:  Optional[dict] = None
        self._selected: Optional[dict] = None
        self._on_select = on_select
        self._drag: dict = {"node": None, "ox": 0, "oy": 0}

        self.bind("<Button-1>",  self._click)
        self.bind("<B1-Motion>", self._drag_move)
        self.bind("<Configure>", self._resize)

    # ── Public ────────────────────────────────────────────────────────────────

    def load(self, hosts: list[dict], local_ip: str) -> None:
        prev_positions = {n["ip"]: (n["x"], n["y"]) for n in self._nodes}
        sel_ip = self._selected["ip"] if self._selected else None

        self._nodes   = []
        self._gateway = None

        w = max(self.winfo_width(),  600)
        h = max(self.winfo_height(), 400)
        cx, cy = w / 2, h / 2

        parts  = local_ip.split(".")
        gw_ip  = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        gw_set = {h2["ip"] for h2 in hosts if h2["ip"] == gw_ip}
        gateway_ip = next(iter(gw_set), hosts[0]["ip"] if hosts else None)

        non_gw = [h2 for h2 in hosts if h2["ip"] != gateway_ip]
        radius = min(w, h) * 0.33

        for host in hosts:
            is_gw   = host["ip"] == gateway_ip
            is_self = host["ip"] == local_ip
            if host["ip"] in prev_positions:
                x, y = prev_positions[host["ip"]]
            elif is_gw:
                x, y = cx, cy
            else:
                idx   = non_gw.index(host)
                angle = 2 * math.pi * idx / max(len(non_gw), 1) - math.pi / 2
                x = cx + radius * math.cos(angle)
                y = cy + radius * math.sin(angle)

            online = host.get("online", True)
            node = {**host, "x": x, "y": y, "is_gw": is_gw, "is_self": is_self, "online": online}
            if is_gw:
                self._gateway = node
            self._nodes.append(node)
            if node["ip"] == sel_ip:
                self._selected = node

        self._draw()

    def refresh(self, hosts: list[dict]) -> None:
        """Update node data in-place without re-layouting."""
        data = {h["ip"]: h for h in hosts}
        sel_ip = self._selected["ip"] if self._selected else None
        for node in self._nodes:
            if node["ip"] in data:
                node.update(data[node["ip"]])
            if node["ip"] == sel_ip:
                self._selected = node
        self._draw()

    # ── Drawing ───────────────────────────────────────────────────────────────

    def _draw(self) -> None:
        self.delete("all")
        gw = self._gateway
        for node in self._nodes:
            if gw and node is not gw:
                self.create_line(gw["x"], gw["y"], node["x"], node["y"],
                                 fill="#21262d", width=1.5)
        for node in self._nodes:
            self._draw_node(node)

    def _draw_node(self, node: dict) -> None:
        x, y    = node["x"], node["y"]
        r       = _R_GW if node["is_gw"] else _R
        sel     = node is self._selected
        offline = not node.get("online", True)
        color   = _COL_SELECT if sel else node["color"]
        ol      = "#ffffff" if sel else (_LO if offline else _BORDER)
        lw      = 3         if sel else 1.5

        # Risk ring (drawn behind node)
        risk = node.get("risk", "")
        if risk == "high":
            self.create_oval(x-r-5, y-r-5, x+r+5, y+r+5,
                             outline=_COL_DANGER, width=2, fill="")
        elif risk == "med":
            self.create_oval(x-r-4, y-r-4, x+r+4, y+r+4,
                             outline=_COL_WARN, width=1.5, fill="")

        # Shadow
        self.create_oval(x-r+2, y-r+2, x+r+2, y+r+2,
                         fill="#000000", outline="", stipple="gray25")
        # Circle — dashed for offline nodes
        if offline and not sel:
            self.create_oval(x-r, y-r, x+r, y+r,
                             fill=color, outline=ol, width=lw, dash=(4, 3))
        else:
            self.create_oval(x-r, y-r, x+r, y+r,
                             fill=color, outline=ol, width=lw)

        # Offline label inside node
        if offline:
            self.create_text(x, y, text="off", fill=_LO,
                             font=("Consolas", 7))

        # Open-port count badge (bottom-right)
        open_ports = [p for p in node.get("ports", []) if p["state"] == "open"]
        if open_ports:
            bx, by = x + r - 4, y + r - 4
            br = 9
            badge_color = _COL_DANGER if risk == "high" else (_COL_WARN if risk == "med" else "#334155")
            self.create_oval(bx-br, by-br, bx+br, by+br,
                             fill=badge_color, outline=_BG, width=1.5)
            self.create_text(bx, by, text=str(len(open_ports)),
                             fill="#ffffff", font=("Consolas", 7, "bold"))

        # "this machine" dot
        if node["is_self"]:
            self.create_oval(x-5, y-5, x+5, y+5, fill=_COL_SELF, outline="")

        # Enrichment spinner (⟳ on nodes not yet enriched during deep scan)
        if node.get("_enriching") and not node.get("enriched"):
            self.create_text(x, y, text="…", fill=_HI,
                             font=("Consolas", 10, "bold"))

        # IP below
        self.create_text(x, y + r + 11, text=node["ip"],
                         fill=_HI, font=("Consolas", 9))

        # OS label (shown after enrichment) — or hostname
        if node.get("os"):
            os_short = node["os"][:18] + "…" if len(node["os"]) > 18 else node["os"]
            self.create_text(x, y - r - 11, text=os_short,
                             fill=_LO, font=("Consolas", 8))
        elif node.get("hostname"):
            hn = node["hostname"]
            if len(hn) > 20:
                hn = hn[:18] + "…"
            self.create_text(x, y - r - 11, text=hn,
                             fill=_LO, font=("Consolas", 8))

    # ── Interaction ───────────────────────────────────────────────────────────

    def _node_at(self, x: float, y: float) -> Optional[dict]:
        for node in self._nodes:
            r = _R_GW if node["is_gw"] else _R
            if math.hypot(node["x"] - x, node["y"] - y) <= r + 6:
                return node
        return None

    def _click(self, ev: tk.Event) -> None:
        node = self._node_at(ev.x, ev.y)
        self._selected = node
        self._drag = {"node": node, "ox": ev.x, "oy": ev.y}
        self._draw()
        self._on_select(node)

    def _drag_move(self, ev: tk.Event) -> None:
        node = self._drag["node"]
        if node:
            node["x"] += ev.x - self._drag["ox"]
            node["y"] += ev.y - self._drag["oy"]
            self._drag["ox"] = ev.x
            self._drag["oy"] = ev.y
            self._draw()

    def _resize(self, _ev: tk.Event) -> None:
        if self._nodes:
            self._draw()


# ── Page ──────────────────────────────────────────────────────────────────────

class NetMapPage(ctk.CTkFrame):

    def __init__(self, master: ctk.CTkFrame, runner,
                 output_cb: Callable[[str], None]) -> None:
        super().__init__(master, fg_color="transparent")
        self._runner   = runner
        self._out      = output_cb
        self._local_ip = _local_ip()
        self._hosts:    list[dict]     = []
        self._selected: Optional[dict] = None
        self._build()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        # Header
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(20, 6))
        ctk.CTkLabel(hdr, text="Network Map",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")
        ctk.CTkLabel(hdr, text="  —  ARP discovery · nmap deep scan · click to target",
                     text_color=_LO, font=ctk.CTkFont(size=12)).pack(side="left")

        # Toolbar
        tb = ctk.CTkFrame(self, fg_color=_SURFACE, corner_radius=8,
                          border_width=1, border_color=_BORDER)
        tb.pack(fill="x", padx=24, pady=(0, 8))

        ctk.CTkLabel(tb, text="Subnet:", text_color=_LO,
                     font=ctk.CTkFont(family="Consolas", size=12)
                     ).pack(side="left", padx=(14, 4), pady=8)

        self._subnet_var = ctk.StringVar(value=_default_subnet(self._local_ip))
        ctk.CTkEntry(tb, textvariable=self._subnet_var, width=175,
                     font=ctk.CTkFont(family="Consolas", size=12)
                     ).pack(side="left", padx=4, pady=8)

        ctk.CTkLabel(tb, text="Depth:", text_color=_LO,
                     font=ctk.CTkFont(family="Consolas", size=12)
                     ).pack(side="left", padx=(10, 4))

        self._depth_var = ctk.StringVar(value="Deep (nmap)")
        ctk.CTkComboBox(tb, variable=self._depth_var, width=130,
                        values=["ARP only", "Deep (nmap)"],
                        state="readonly",
                        font=ctk.CTkFont(family="Consolas", size=12)
                        ).pack(side="left", padx=4)

        self._scan_btn = ctk.CTkButton(
            tb, text="⟳  Scan", width=110,
            fg_color=_GREEN, hover_color="#2ea043",
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self._scan,
        )
        self._scan_btn.pack(side="left", padx=(10, 6), pady=8)

        self._status_lbl = ctk.CTkLabel(
            tb, text=f"Local: {self._local_ip}",
            text_color=_LO, font=ctk.CTkFont(family="Consolas", size=11))
        self._status_lbl.pack(side="left", padx=8)

        # SNMP row
        tb2 = ctk.CTkFrame(self, fg_color=_SURFACE, corner_radius=8,
                           border_width=1, border_color=_BORDER)
        tb2.pack(fill="x", padx=24, pady=(0, 8))

        ctk.CTkLabel(tb2, text="SNMP:", text_color=_LO,
                     font=ctk.CTkFont(family="Consolas", size=12)
                     ).pack(side="left", padx=(14, 4), pady=6)
        ctk.CTkLabel(tb2, text="Router:", text_color=_LO,
                     font=ctk.CTkFont(family="Consolas", size=11)
                     ).pack(side="left", padx=(4, 2))

        self._snmp_ip_var = ctk.StringVar(value=_default_subnet(self._local_ip).rsplit(".", 2)[0] + ".1")
        ctk.CTkEntry(tb2, textvariable=self._snmp_ip_var, width=130,
                     font=ctk.CTkFont(family="Consolas", size=12)
                     ).pack(side="left", padx=4, pady=6)

        ctk.CTkLabel(tb2, text="Community:", text_color=_LO,
                     font=ctk.CTkFont(family="Consolas", size=11)
                     ).pack(side="left", padx=(8, 2))

        self._snmp_comm_var = ctk.StringVar(value="public")
        ctk.CTkEntry(tb2, textvariable=self._snmp_comm_var, width=90,
                     font=ctk.CTkFont(family="Consolas", size=12)
                     ).pack(side="left", padx=4, pady=6)

        self._snmp_btn = ctk.CTkButton(
            tb2, text="Query Router ARP", width=150,
            fg_color=_SURFACE, hover_color=_BORDER,
            border_width=1, border_color=_CYAN,
            text_color=_CYAN,
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._snmp_query,
        )
        self._snmp_btn.pack(side="left", padx=(10, 6), pady=6)

        self._snmp_status = ctk.CTkLabel(
            tb2, text="Query router SNMP ARP table to reveal offline devices",
            text_color=_LO, font=ctk.CTkFont(family="Consolas", size=10))
        self._snmp_status.pack(side="left", padx=8)

        # Legend
        legend = ctk.CTkFrame(tb, fg_color="transparent")
        legend.pack(side="right", padx=14)
        items = [("Router", _COL_ROUTER), ("Windows", _COL_WIN),
                 ("Linux",  _COL_LINUX),  ("Apple",   _COL_APPLE),
                 ("Phone",  _COL_PHONE),  ("You",     _COL_SELF),
                 ("⚠ High", _COL_DANGER)]
        for label, color in items:
            dot = tk.Canvas(legend, width=10, height=10,
                            bg=_SURFACE, highlightthickness=0)
            dot.create_oval(1, 1, 9, 9, fill=color, outline="")
            dot.pack(side="left", padx=(5, 2))
            ctk.CTkLabel(legend, text=label, text_color=_LO,
                         font=ctk.CTkFont(size=10)).pack(side="left", padx=(0, 4))

        # Body: canvas | info panel
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=24, pady=(0, 16))
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=0)
        body.grid_rowconfigure(0, weight=1)

        canvas_card = ctk.CTkFrame(body, fg_color=_SURFACE, corner_radius=8,
                                   border_width=1, border_color=_BORDER)
        canvas_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        canvas_card.grid_rowconfigure(0, weight=1)
        canvas_card.grid_columnconfigure(0, weight=1)

        self._canvas = _NetCanvas(canvas_card, on_select=self._on_select)
        self._canvas.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)

        self._empty_lbl = ctk.CTkLabel(
            canvas_card,
            text="No hosts discovered yet.\n\nClick  ⟳ Scan  to start.",
            text_color=_LO, font=ctk.CTkFont(family="Consolas", size=13))
        self._empty_lbl.place(relx=0.5, rely=0.5, anchor="center")

        self._panel = ctk.CTkFrame(body, fg_color=_SURFACE, corner_radius=8,
                                   border_width=1, border_color=_BORDER,
                                   width=240)
        self._panel.grid(row=0, column=1, sticky="nsew")
        self._panel.grid_propagate(False)
        self._build_panel()

    def _build_panel(self) -> None:
        p = self._panel

        ctk.CTkLabel(p, text="SELECTED NODE",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=_LO).pack(anchor="w", padx=16, pady=(18, 0))
        ctk.CTkFrame(p, height=1, fg_color=_BORDER).pack(fill="x", padx=16, pady=(6, 12))

        self._fvars: dict[str, ctk.StringVar] = {}
        for field in ("IP", "MAC", "Hostname", "Vendor", "Type", "OS"):
            row = ctk.CTkFrame(p, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=2)
            ctk.CTkLabel(row, text=f"{field}:", width=60,
                         text_color=_LO,
                         font=ctk.CTkFont(family="Consolas", size=11),
                         anchor="w").pack(side="left")
            var = ctk.StringVar(value="—")
            ctk.CTkLabel(row, textvariable=var, text_color=_HI,
                         font=ctk.CTkFont(family="Consolas", size=11),
                         anchor="w", wraplength=145).pack(side="left")
            self._fvars[field] = var

        ctk.CTkFrame(p, height=1, fg_color=_BORDER).pack(fill="x", padx=16, pady=(12, 8))

        self._target_btn = ctk.CTkButton(
            p, text="⊛  Set as Target", state="disabled",
            fg_color=_GREEN, hover_color="#2ea043",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._set_target,
        )
        self._target_btn.pack(fill="x", padx=16, pady=(0, 6))

        self._copy_btn = ctk.CTkButton(
            p, text="Copy IP", state="disabled",
            fg_color=_SURFACE, hover_color=_BORDER,
            border_width=1, border_color=_BORDER,
            text_color=_HI, font=ctk.CTkFont(size=12),
            command=self._copy_ip,
        )
        self._copy_btn.pack(fill="x", padx=16, pady=(0, 8))

        ctk.CTkFrame(p, height=1, fg_color=_BORDER).pack(fill="x", padx=16, pady=(2, 8))

        # Open ports section
        ports_hdr = ctk.CTkFrame(p, fg_color="transparent")
        ports_hdr.pack(fill="x", padx=16, pady=(0, 4))
        ctk.CTkLabel(ports_hdr, text="OPEN PORTS",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=_LO).pack(side="left")
        self._port_count_lbl = ctk.CTkLabel(
            ports_hdr, text="", text_color=_LO,
            font=ctk.CTkFont(size=10))
        self._port_count_lbl.pack(side="right")

        self._ports_frame = ctk.CTkScrollableFrame(
            p, fg_color="transparent", height=130)
        self._ports_frame.pack(fill="x", padx=8, pady=(0, 8))

        ctk.CTkFrame(p, height=1, fg_color=_BORDER).pack(fill="x", padx=16, pady=(0, 8))

        # All-hosts list
        ctk.CTkLabel(p, text="ALL HOSTS",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=_LO).pack(anchor="w", padx=16, pady=(0, 4))

        self._list_frame = ctk.CTkScrollableFrame(
            p, fg_color="transparent", height=120)
        self._list_frame.pack(fill="both", expand=True, padx=8, pady=(0, 12))

    # ── Scan ──────────────────────────────────────────────────────────────────

    def _scan(self) -> None:
        if self._runner.is_running:
            self._runner.stop()
            return

        subnet = self._subnet_var.get().strip()
        try:
            ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            self._out(f"[ERROR] Invalid subnet: {subnet}\n")
            return

        deep = self._depth_var.get() == "Deep (nmap)"

        self._scan_btn.configure(text="◼  Stop", fg_color=_RED, hover_color="#b91c1c")
        self._status_lbl.configure(text="Phase 1: ARP scan…")
        self._empty_lbl.configure(text="Scanning…")
        self._empty_lbl.place(relx=0.5, rely=0.5, anchor="center")
        self._canvas.delete("all")
        self._hosts = []

        def do() -> int:
            # Phase 1
            hosts = _arp_scan(subnet, self._out)
            self.after(0, lambda h=hosts: self._on_arp_done(h, deep))

            # Phase 2
            if hosts and deep:
                self.after(0, lambda: self._status_lbl.configure(
                    text=f"Phase 2: nmap enriching {len(hosts)} host(s)…"))
                for h in hosts:
                    h["_enriching"] = True
                _nmap_enrich(
                    hosts, self._out,
                    update_cb=lambda h: self.after(0, lambda hh=h: self._canvas.refresh(hh)),
                )
                self.after(0, lambda h=hosts: self._on_enrich_done(h))
            return 0

        def done(code: int) -> None:
            self.after(0, lambda: self._scan_btn.configure(
                text="⟳  Scan", fg_color=_GREEN, hover_color="#2ea043"))

        self._runner.run(do, done_cb=done,
                         output_cb=self._out, tool_name="NetMap")

    def _on_arp_done(self, hosts: list[dict], deep: bool) -> None:
        self._hosts = hosts
        if hosts:
            self._empty_lbl.place_forget()
            self._canvas.load(hosts, self._local_ip)
            suffix = "  ·  enriching…" if deep else ""
            self._status_lbl.configure(
                text=f"Local: {self._local_ip}  ·  {len(hosts)} host(s){suffix}")
            self._build_host_list()
        else:
            self._empty_lbl.configure(
                text="No hosts found.\nTry running as Administrator.")

    def _on_enrich_done(self, hosts: list[dict]) -> None:
        self._hosts = hosts
        self._canvas.refresh(hosts)
        self._build_host_list()
        risky = sum(1 for h in hosts if h.get("risk") == "high")
        msg = f"Local: {self._local_ip}  ·  {len(hosts)} host(s)"
        if risky:
            msg += f"  ·  ⚠ {risky} high-risk"
        self._status_lbl.configure(text=msg)
        if self._selected:
            for node in self._canvas._nodes:
                if node["ip"] == self._selected.get("ip"):
                    self._on_select(node)
                    break

    def _build_host_list(self) -> None:
        for w in self._list_frame.winfo_children():
            w.destroy()
        for host in self._hosts:
            row = ctk.CTkFrame(self._list_frame, fg_color="transparent")
            row.pack(fill="x", pady=1)
            dot = tk.Canvas(row, width=8, height=8,
                            bg=_SURFACE, highlightthickness=0)
            dot.create_oval(1, 1, 7, 7, fill=host["color"], outline="")
            dot.pack(side="left", padx=(2, 4))
            label = host["ip"]
            if host.get("risk") == "high":
                label += "  ⚠"
            ctk.CTkLabel(row, text=label,
                         font=ctk.CTkFont(family="Consolas", size=11),
                         text_color=_COL_DANGER if host.get("risk") == "high" else _HI,
                         cursor="hand2").pack(side="left")
            row.bind("<Button-1>",   lambda _e, h=host: self._select_from_list(h))
            for w in row.winfo_children():
                w.bind("<Button-1>", lambda _e, h=host: self._select_from_list(h))

    def _select_from_list(self, host: dict) -> None:
        for node in self._canvas._nodes:
            if node["ip"] == host["ip"]:
                self._canvas._selected = node
                self._canvas._draw()
                self._on_select(node)
                break

    # ── Selection ─────────────────────────────────────────────────────────────

    def _on_select(self, node: Optional[dict]) -> None:
        self._selected = node
        if node:
            self._fvars["IP"].set(node["ip"])
            self._fvars["MAC"].set(node["mac"])
            self._fvars["Hostname"].set(node["hostname"] or "—")
            self._fvars["Vendor"].set(node.get("vendor") or "—")
            self._fvars["Type"].set(node["type"])
            os_str = node.get("os", "")
            if os_str and node.get("os_accuracy"):
                os_str += f" ({node['os_accuracy']}%)"
            self._fvars["OS"].set(os_str or ("scanning…" if node.get("_enriching") and not node.get("enriched") else "—"))
            self._target_btn.configure(state="normal")
            self._copy_btn.configure(state="normal")
            self._build_ports_panel(node)
        else:
            for v in self._fvars.values():
                v.set("—")
            self._target_btn.configure(state="disabled")
            self._copy_btn.configure(state="disabled")
            self._port_count_lbl.configure(text="")
            for w in self._ports_frame.winfo_children():
                w.destroy()

    def _build_ports_panel(self, node: dict) -> None:
        for w in self._ports_frame.winfo_children():
            w.destroy()

        ports = [p for p in node.get("ports", []) if p["state"] == "open"]
        self._port_count_lbl.configure(
            text=f"{len(ports)} open" if ports else
                 ("not scanned" if not node.get("enriched") else "none"))

        if not ports:
            ctk.CTkLabel(self._ports_frame,
                         text="—" if node.get("enriched") else "run Deep scan",
                         text_color=_LO,
                         font=ctk.CTkFont(family="Consolas", size=11)
                         ).pack(anchor="w", padx=4)
            return

        for p in ports:
            risk_col = (_COL_DANGER if p["port"] in _HIGH_RISK else
                        (_COL_WARN  if p["port"] in _MED_RISK  else _HI))
            row = ctk.CTkFrame(self._ports_frame, fg_color="transparent")
            row.pack(fill="x", pady=1)
            ctk.CTkLabel(row,
                         text=f"{p['port']:<6}/{p['proto']:<4}",
                         font=ctk.CTkFont(family="Consolas", size=10),
                         text_color=risk_col, width=80, anchor="w"
                         ).pack(side="left")
            svc = p["service"]
            if p.get("version"):
                svc += f"  {p['version'][:20]}"
            ctk.CTkLabel(row, text=svc,
                         font=ctk.CTkFont(family="Consolas", size=10),
                         text_color=_LO, anchor="w"
                         ).pack(side="left", fill="x", expand=True)

    # ── SNMP ──────────────────────────────────────────────────────────────────

    def _snmp_query(self) -> None:
        if self._runner.is_running:
            self._out("[!] Wait for current scan to finish first.\n")
            return

        router_ip = self._snmp_ip_var.get().strip()
        community = self._snmp_comm_var.get().strip() or "public"

        self._snmp_btn.configure(text="Querying…", state="disabled")
        self._snmp_status.configure(text="Querying router ARP table…")

        def do() -> int:
            # Try 'public', then the user-supplied string if different
            communities = list(dict.fromkeys([community, "public", "private"]))
            snmp_hosts: list[dict] = []
            for comm in communities:
                snmp_hosts = _snmp_arp_table(router_ip, comm, self._out)
                if snmp_hosts:
                    break
            self.after(0, lambda h=snmp_hosts: self._merge_snmp(h))
            return 0

        def done(_code: int) -> None:
            self.after(0, lambda: self._snmp_btn.configure(
                text="Query Router ARP", state="normal"))

        self._runner.run(do, done_cb=done,
                         output_cb=self._out, tool_name="SNMP")

    def _merge_snmp(self, snmp_hosts: list[dict]) -> None:
        if not snmp_hosts:
            self._snmp_status.configure(text="No SNMP data — SNMP may be disabled on router")
            return

        existing_ips = {h["ip"] for h in self._hosts}
        new_hosts = [h for h in snmp_hosts if h["ip"] not in existing_ips]

        if not new_hosts:
            self._snmp_status.configure(
                text=f"SNMP returned {len(snmp_hosts)} entr(ies) — all already on map")
            return

        self._hosts.extend(new_hosts)
        self._canvas.load(self._hosts, self._local_ip)
        self._build_host_list()
        self._snmp_status.configure(
            text=f"Added {len(new_hosts)} offline device(s) from router ARP table")
        self._out(f"[+] {len(new_hosts)} new offline host(s) added to map.\n")

    # ── Actions ───────────────────────────────────────────────────────────────

    def _set_target(self) -> None:
        if not self._selected:
            return
        ip = self._selected["ip"]
        _CFG.parent.mkdir(parents=True, exist_ok=True)
        cfg: dict = {}
        if _CFG.exists():
            try:
                cfg = json.loads(_CFG.read_text())
            except Exception:
                pass
        cfg["active_target"] = ip
        _CFG.write_text(json.dumps(cfg, indent=2))
        self._out(f"[+] Active target set → {ip}\n")
        self._status_lbl.configure(text=f"Target: {ip}")
        self._copy_ip()

    def _copy_ip(self) -> None:
        if self._selected:
            self.clipboard_clear()
            self.clipboard_append(self._selected["ip"])
            self._out(f"[+] Copied {self._selected['ip']} to clipboard.\n")
