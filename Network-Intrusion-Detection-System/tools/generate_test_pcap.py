"""
Synthetic attack traffic generator.

Produces a PCAP file containing one crafted example of every attack
pattern this NIDS detects.  Use it to verify each detector fires without
needing a live network or a real threat actor.

Run standalone:
    python tools/generate_test_pcap.py                 # → test_traffic.pcap
    python tools/generate_test_pcap.py my_output.pcap  # custom path

Or import the generate() function from main.py (menu option 3).

Attack timeline
---------------
 T +  0 s   Background traffic   — warms up per-host baselines
 T + 30 s   Vertical port scan   — 10.0.0.99 → 192.168.1.100 (200 ports)
 T + 41 s   Distributed SYN flood— many sources → 192.168.1.200:80
 T + 48 s   DNS tunneling        — base32 payloads in subdomains
 T + 56 s   ARP cache poisoning  — IP–MAC binding conflict + GARP flood
 T + 65 s   ICMP amplification   — broadcast echo + reply flood on victim
"""

from __future__ import annotations

import base64
import os
import sys
import time

try:
    from scapy.layers.dns import DNS, DNSQR          # type: ignore
    from scapy.layers.inet import ICMP, IP, TCP, UDP  # type: ignore
    from scapy.layers.l2 import ARP, Ether            # type: ignore
    from scapy.utils import wrpcap                    # type: ignore
except ImportError:
    sys.exit("[error] Scapy is required: pip install scapy")


def generate(output_path: str = "test_traffic.pcap") -> str:
    """
    Build a list of crafted Scapy packets covering all six attack categories
    and write them to a PCAP file.

    Timestamps are set manually on each packet so the PCAP replays in a
    realistic time order regardless of how fast Python processes the loop.

    Returns the output path.
    """
    packets = []
    # Anchor all timestamps to a fixed base so the PCAP is reproducible
    base = time.time()

    def ts(offset: float) -> float:
        """Absolute timestamp = base + offset seconds."""
        return base + offset

    # ------------------------------------------------------------------
    # 1. Background / baseline-warmup traffic (T = 0 – 29 s)
    # ------------------------------------------------------------------
    # 60 packets at 0.5-second intervals between various internal hosts.
    # This gives every detector's Welford accumulator enough observations
    # to exit its warm-up phase before the attacks begin.
    for i in range(60):
        src = f"192.168.1.{10 + (i % 20)}"       # rotate through 20 source IPs
        pkt = (
            IP(src=src, dst="8.8.8.8")
            / TCP(sport=40000 + i, dport=443, flags="A")  # normal ACK (data flow)
        )
        pkt.time = ts(i * 0.5)
        packets.append(pkt)

    # ------------------------------------------------------------------
    # 2. Vertical port scan — T1046 (T = 30 – 40 s)
    # ------------------------------------------------------------------
    # Attacker 10.0.0.99 probes 200 ports on 192.168.1.100.
    # All packets are SYN-only (no ACK) — classic stealth / half-open scan.
    # Triggers: PortScanDetector  (unique_contacts > 25, unique_hosts <= 5)
    for i, port in enumerate(range(1, 201)):
        pkt = (
            IP(src="10.0.0.99", dst="192.168.1.100")
            / TCP(sport=54321, dport=port, flags="S")  # SYN only
        )
        pkt.time = ts(30 + i * 0.05)   # 20 probe packets per second
        packets.append(pkt)

    # ------------------------------------------------------------------
    # 3. Distributed SYN flood — T1498.001 (T = 41 – 47 s)
    # ------------------------------------------------------------------
    # 1 200 spoofed SYN packets at ~200 SYN/s flood port 80 on 192.168.1.200.
    # Using many different source IPs simulates a botnet / amplification source.
    # Triggers: SYNFloodDetector  (syn_rate >= 100/s within 10-second window)
    for i in range(1200):
        # Rotate through a /24 of fake source IPs so no single source looks bad
        src = f"10.1.{(i // 255) % 256}.{(i % 255) + 1}"
        pkt = (
            IP(src=src, dst="192.168.1.200")
            / TCP(sport=1024 + (i % 60000), dport=80, flags="S")
        )
        pkt.time = ts(41 + i / 200.0)   # 200 SYN packets per second
        packets.append(pkt)

    # ------------------------------------------------------------------
    # 4. DNS tunneling — T1071.004 (T = 48 – 55 s)
    # ------------------------------------------------------------------
    # The iodine / dns2tcp pattern: binary payloads are base32-encoded and
    # packed into DNS query labels.  Each label is ~52 chars of high-entropy
    # text — well above the 40-char / 3.8-bit thresholds in dns_tunnel.py.
    # Triggers: DNSTunnelDetector  (entropy > 3.8 AND label_len > 40)
    for i in range(25):
        # os.urandom(32) → 32 random bytes → base32 → 52-char high-entropy label
        encoded = base64.b32encode(os.urandom(32)).decode().lower().rstrip("=")
        qname = f"{encoded}.tunnel.c2server.net"   # external domain (not .local)
        pkt = (
            IP(src="192.168.1.50", dst="8.8.8.8")
            / UDP(sport=1024, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=qname, qtype="A"))
        )
        pkt.time = ts(48 + i * 0.3)
        packets.append(pkt)

    # ------------------------------------------------------------------
    # 5. ARP cache poisoning — T1557.002 (T = 56 – 64 s)
    # ------------------------------------------------------------------
    # Step A: legitimate ARP reply establishes the binding for gateway .1
    # Step B: attacker sends a conflicting reply claiming the same IP with
    #         a different MAC — this overwrites victim ARP caches (MITM).
    # Step C: flood of gratuitous ARPs amplifies the campaign.
    # Triggers: ARPSpoofDetector  (IP–MAC conflict + GARP flood)

    # A — legitimate gateway binding (MAC ends :ff)
    legit = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2,
              psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff",
              pdst="192.168.1.50", hwdst="ff:ff:ff:ff:ff:ff")
    )
    legit.time = ts(56)
    packets.append(legit)

    # B — attacker poisons with a different MAC (ends :66)
    poison = (
        Ether(src="11:22:33:44:55:66", dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2,
              psrc="192.168.1.1", hwsrc="11:22:33:44:55:66",
              pdst="192.168.1.50", hwdst="ff:ff:ff:ff:ff:ff")
    )
    poison.time = ts(57)
    packets.append(poison)

    # C — gratuitous ARP flood to maintain the poisoned cache entries
    for i in range(15):
        garp = (
            Ether(src="11:22:33:44:55:66", dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=2,
                  psrc="192.168.1.1", hwsrc="11:22:33:44:55:66",
                  pdst="192.168.1.50", hwdst="ff:ff:ff:ff:ff:ff")
        )
        garp.time = ts(57.5 + i * 0.4)
        packets.append(garp)

    # ------------------------------------------------------------------
    # 6. ICMP amplification / Smurf — T1498.002 (T = 65 – 75 s)
    # ------------------------------------------------------------------
    # Part A: echo requests sent to the subnet broadcast → Smurf pattern.
    # Part B: 600 echo replies flood victim 192.168.1.75 from many sources,
    #         simulating a reflection attack.  Rate exceeds 50 replies/s,
    #         amplification ratio >> 5 (victim sent zero requests).
    # Triggers: ICMPAmpDetector  (broadcast dest + reply/request asymmetry)

    # A — broadcast echo requests (Smurf source signature)
    for i in range(10):
        pkt = (
            IP(src="10.0.0.99", dst="192.168.1.255")  # subnet broadcast
            / ICMP(type=8, code=0)                     # Echo Request
        )
        pkt.time = ts(65 + i * 0.1)
        packets.append(pkt)

    # B — reply flood directed at victim 192.168.1.75
    for i in range(600):
        src = f"10.2.{(i // 255) % 256}.{(i % 255) + 1}"   # reflector pool
        pkt = (
            IP(src=src, dst="192.168.1.75")
            / ICMP(type=0, code=0)                          # Echo Reply
        )
        pkt.time = ts(66 + i / 60.0)   # 60 replies per second
        packets.append(pkt)

    # ------------------------------------------------------------------
    # Write PCAP
    # ------------------------------------------------------------------
    # Sort ascending by timestamp so Wireshark and our parser see a coherent
    # capture rather than interleaved attack blocks.
    packets.sort(key=lambda p: float(p.time))
    wrpcap(output_path, packets)

    total = len(packets)
    print(f"[+] Generated {total} packets → {output_path}")
    print(f"    Attack patterns included:")
    print(f"      • Vertical port scan      (T1046)     ~200 SYN packets")
    print(f"      • Distributed SYN flood   (T1498.001) ~1200 SYN packets")
    print(f"      • DNS tunneling           (T1071.004) 25 high-entropy queries")
    print(f"      • ARP cache poisoning     (T1557.002) IP–MAC conflict + 15 GARPs")
    print(f"      • ICMP amplification      (T1498.002) 10 broadcast + 600 replies")
    return output_path


# ── Standalone entry point ────────────────────────────────────────────────────

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "test_traffic.pcap"
    generate(out)
    print(f"\nRun:  python main.py --pcap {out}")
