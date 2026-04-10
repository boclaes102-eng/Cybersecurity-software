"""
Scapy packet → ParsedPacket normalisation layer.

Decouples all detection logic from Scapy internals.  Every detector
receives a ParsedPacket and never touches a raw Scapy object; this
makes unit-testing trivial (just construct ParsedPackets directly).

TCP flag bitmask reference (RFC 793 + ECN extensions):
  0x01 FIN  0x02 SYN  0x04 RST  0x08 PSH
  0x10 ACK  0x20 URG  0x40 ECE  0x80 CWR
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from scapy.packet import Packet  # type: ignore[import-untyped]

# Deferred imports so the module loads even when Scapy isn't installed
# (useful for running unit tests without the full capture stack).
try:
    from scapy.layers.dns import DNS                    # type: ignore
    from scapy.layers.inet import ICMP, IP, TCP, UDP    # type: ignore
    from scapy.layers.l2 import ARP, Ether              # type: ignore
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False

_TCP_FLAG_NAMES: dict[int, str] = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
    0x40: "ECE",
    0x80: "CWR",
}


@dataclass
class ParsedPacket:
    """
    Protocol-normalised packet representation.

    All fields are optional; populate only what the encapsulated protocols
    actually provide.  Boolean helpers (is_syn, is_syn_ack …) centralise
    flag-mask logic so detectors stay readable.
    """

    timestamp: float
    length:    int
    protocol:  str          # "TCP" | "UDP" | "ICMP" | "ARP" | "DNS" | "OTHER"

    # Layer 2 ─────────────────────────────────────────────────────────────
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None

    # Layer 3 ─────────────────────────────────────────────────────────────
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ttl:    Optional[int] = None

    # Layer 4 ─────────────────────────────────────────────────────────────
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    # TCP ──────────────────────────────────────────────────────────────────
    tcp_flags: Optional[int] = None   # raw bitmask

    # ICMP ─────────────────────────────────────────────────────────────────
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None

    # ARP ──────────────────────────────────────────────────────────────────
    arp_op:    Optional[int] = None   # 1 = request, 2 = reply
    arp_hwsrc: Optional[str] = None   # sender MAC
    arp_hwdst: Optional[str] = None   # target MAC
    arp_psrc:  Optional[str] = None   # sender IP
    arp_pdst:  Optional[str] = None   # target IP

    # DNS ──────────────────────────────────────────────────────────────────
    dns_qname:       Optional[str] = None
    dns_qtype:       Optional[int] = None
    dns_is_response: bool = False
    dns_ancount:     int  = 0
    dns_payload_len: int  = 0

    # ── TCP flag helpers ──────────────────────────────────────────────────

    @property
    def is_syn(self) -> bool:
        """Pure SYN — no ACK set (i.e. a new connection attempt)."""
        return bool(
            self.tcp_flags is not None
            and (self.tcp_flags & 0x02)
            and not (self.tcp_flags & 0x10)
        )

    @property
    def is_syn_ack(self) -> bool:
        return bool(
            self.tcp_flags is not None
            and (self.tcp_flags & 0x12) == 0x12
        )

    @property
    def is_rst(self) -> bool:
        return bool(self.tcp_flags is not None and self.tcp_flags & 0x04)

    @property
    def is_fin(self) -> bool:
        return bool(self.tcp_flags is not None and self.tcp_flags & 0x01)

    @property
    def flag_names(self) -> list[str]:
        if self.tcp_flags is None:
            return []
        return [name for bit, name in _TCP_FLAG_NAMES.items() if self.tcp_flags & bit]


# ---------------------------------------------------------------------------
# Public parser
# ---------------------------------------------------------------------------

def parse_packet(pkt: "Packet") -> Optional[ParsedPacket]:  # type: ignore[return]
    """
    Convert a raw Scapy packet into a ParsedPacket.

    Returns None for frames we cannot meaningfully analyse (e.g. raw
    Ethernet without IP or ARP, or packets that raise during parsing).
    We intentionally swallow all exceptions here; a single malformed
    packet must never crash the capture loop.
    """
    if not _SCAPY_OK:
        return None
    try:
        parsed = ParsedPacket(
            timestamp=float(pkt.time),
            length=len(pkt),
            protocol="OTHER",
        )

        # ── Ethernet ──────────────────────────────────────────────────────
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            parsed.src_mac = eth.src
            parsed.dst_mac = eth.dst

        # ── ARP (no IP layer) ─────────────────────────────────────────────
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            parsed.protocol  = "ARP"
            parsed.arp_op    = int(arp.op)
            parsed.arp_hwsrc = arp.hwsrc
            parsed.arp_hwdst = arp.hwdst
            parsed.arp_psrc  = arp.psrc
            parsed.arp_pdst  = arp.pdst
            parsed.src_ip    = arp.psrc
            parsed.dst_ip    = arp.pdst
            return parsed

        # ── Require IP from this point ────────────────────────────────────
        if not pkt.haslayer(IP):
            return None

        ip = pkt[IP]
        parsed.src_ip = ip.src
        parsed.dst_ip = ip.dst
        parsed.ttl    = ip.ttl

        # ── ICMP ──────────────────────────────────────────────────────────
        if pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            parsed.protocol  = "ICMP"
            parsed.icmp_type = int(icmp.type)
            parsed.icmp_code = int(icmp.code)
            return parsed

        # ── TCP ───────────────────────────────────────────────────────────
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            parsed.protocol  = "TCP"
            parsed.src_port  = tcp.sport
            parsed.dst_port  = tcp.dport
            parsed.tcp_flags = int(tcp.flags)

        # ── UDP ───────────────────────────────────────────────────────────
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            parsed.protocol = "UDP"
            parsed.src_port = udp.sport
            parsed.dst_port = udp.dport

        # ── DNS (rides on TCP port 53 or UDP port 53) ─────────────────────
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            parsed.protocol        = "DNS"
            parsed.dns_is_response = bool(dns.qr)
            parsed.dns_ancount     = int(dns.ancount or 0)
            parsed.dns_payload_len = len(dns)
            if dns.qd:
                try:
                    raw = dns.qd.qname
                    parsed.dns_qname = (
                        raw.decode("utf-8", errors="replace").rstrip(".")
                        if isinstance(raw, bytes)
                        else str(raw).rstrip(".")
                    )
                    parsed.dns_qtype = int(dns.qd.qtype)
                except Exception:
                    pass

        return parsed

    except Exception:
        return None
