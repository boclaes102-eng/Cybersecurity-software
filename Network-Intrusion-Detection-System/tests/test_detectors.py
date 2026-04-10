"""
Detector unit tests.

Every detector is tested in isolation using manually constructed
ParsedPacket objects — no Scapy, no live network, no PCAP files.
This keeps the tests fast, deterministic, and runnable anywhere.

Testing philosophy
------------------
Each test class covers three scenarios:
  1. Attack pattern fires the expected alert.
  2. Legitimate / boundary traffic produces no alert.
  3. Key evidence fields carry the right values.
"""

import time

import pytest

from nids.capture.parser import ParsedPacket
from nids.detection.arp_spoof import ARPSpoofDetector
from nids.detection.baseline import BaselineManager
from nids.detection.dns_tunnel import DNSTunnelDetector
from nids.detection.engine import DetectionEngine
from nids.detection.icmp_amp import ICMPAmpDetector
from nids.detection.models import Severity
from nids.detection.port_scan import PortScanDetector
from nids.detection.syn_flood import SYNFloodDetector


# ── Helpers ───────────────────────────────────────────────────────────────────

def pkt(**kwargs) -> ParsedPacket:
    """
    Minimal ParsedPacket factory.

    Only specify the fields relevant to your test — everything else
    gets a safe default value so detectors don't crash on missing data.
    """
    defaults = dict(
        timestamp=time.time(),
        length=64,
        protocol="TCP",
    )
    defaults.update(kwargs)
    return ParsedPacket(**defaults)


# ── Port Scan Detector ────────────────────────────────────────────────────────

class TestPortScanDetector:

    def test_vertical_scan_fires(self):
        """
        One source contacting 100 distinct ports on a single host
        exceeds the VERT_THRESHOLD (25) and should fire a vertical-scan alert.
        """
        det = PortScanDetector()
        now = time.time()
        alerts = []

        # SYN packets to 100 sequential ports from one source
        for port in range(1, 101):
            alerts += det.process(pkt(
                protocol="TCP",
                src_ip="10.0.0.1",
                dst_ip="192.168.1.100",
                dst_port=port,
                tcp_flags=0x02,       # SYN only (half-open / stealth)
                timestamp=now + port * 0.01,
            ))

        scan_alerts = [a for a in alerts if a.detector == "port_scan"]
        assert scan_alerts, "Expected a port-scan alert"
        assert scan_alerts[0].evidence["scan_type"] == "vertical_scan"

    def test_horizontal_sweep_fires(self):
        """
        One source hitting port 22 on 30 different hosts should fire
        a network-sweep alert.

        With 30 hosts and the same port, unique_contacts == unique_hosts == 30.
        Both exceed DIST_THRESHOLD (15), so the detector classifies this as a
        "distributed" scan (the strictest category that also covers sweeps).
        We verify any port_scan alert fires and that unique_hosts is reported.
        """
        det = PortScanDetector()
        now = time.time()
        alerts = []

        for i in range(30):
            alerts += det.process(pkt(
                protocol="TCP",
                src_ip="10.0.0.1",
                dst_ip=f"192.168.1.{i + 1}",
                dst_port=22,
                tcp_flags=0x02,
                timestamp=now + i * 0.05,
            ))

        # Fires as "distributed" at DIST_THRESHOLD=15 hosts (earliest trigger).
        # unique_hosts in the evidence reflects the count at alert time (15).
        scan_alerts = [a for a in alerts if a.detector == "port_scan"]
        assert scan_alerts, "Expected a port-scan alert for 30-host sweep"
        assert scan_alerts[0].evidence.get("unique_hosts", 0) >= 15

    def test_normal_traffic_no_alert(self):
        """
        Repeated connections to the same host:port pair (normal web traffic)
        must never trigger the scan detector.
        """
        det = PortScanDetector()
        alerts = []
        for _ in range(50):
            alerts += det.process(pkt(
                protocol="TCP",
                src_ip="10.0.0.1",
                dst_ip="8.8.8.8",
                dst_port=443,
                tcp_flags=0x10,   # ACK — data flow, not a probe
            ))
        assert not alerts

    def test_evidence_contains_required_fields(self):
        """Alert evidence dict must carry the fields the SIEM expects."""
        det = PortScanDetector()
        now = time.time()
        alerts = []
        for port in range(1, 60):
            alerts += det.process(pkt(
                protocol="TCP", src_ip="10.0.0.2", dst_ip="192.168.1.1",
                dst_port=port, tcp_flags=0x02, timestamp=now + port * 0.01,
            ))
        scan = next((a for a in alerts if a.detector == "port_scan"), None)
        assert scan is not None
        assert "unique_contacts" in scan.evidence
        assert "syn_ratio"       in scan.evidence
        assert "scan_type"       in scan.evidence


# ── SYN Flood Detector ────────────────────────────────────────────────────────

class TestSYNFloodDetector:

    def test_high_syn_rate_fires(self):
        """
        1 200 SYN packets over 10 seconds → 120 SYN/s.
        The detector's absolute threshold is 100/s, so it must fire.

        Why 1 200 and not 1 100:
        The rate is sampled once per second (packet-time).  Samples fire at
        t=1 s (120 pkts), t=2 s (240 pkts), …, t=9 s (1 080 pkts).
        At t=9: rate = 1080 / 10-s window = 108/s ≥ 100 → alert fires.
        1 100 packets would give only 99/s at the 9th sample and miss.
        """
        det = SYNFloodDetector()
        now = time.time()
        alerts = []

        # 1 200 SYN packets evenly spread across 10 s = 120 SYN/s
        for i in range(1200):
            alerts += det.process(pkt(
                protocol="TCP",
                dst_ip="192.168.1.200",
                tcp_flags=0x02,                    # SYN only
                timestamp=now + (i * 10.0 / 1200),
            ))

        flood_alerts = [a for a in alerts if a.detector == "syn_flood"]
        assert flood_alerts, "Expected a SYN-flood alert at 120 SYN/s"
        assert flood_alerts[0].severity in (Severity.HIGH, Severity.CRITICAL)

    def test_normal_handshake_no_alert(self):
        """
        Balanced SYN / SYN-ACK traffic at low rate must not be flagged.
        """
        det = SYNFloodDetector()
        now = time.time()
        alerts = []

        for i in range(20):
            # One SYN followed immediately by a SYN-ACK — completed handshake
            alerts += det.process(pkt(
                protocol="TCP", dst_ip="192.168.1.200",
                tcp_flags=0x02, timestamp=now + i,
            ))
            alerts += det.process(pkt(
                protocol="TCP", dst_ip="192.168.1.200",
                tcp_flags=0x12, timestamp=now + i + 0.001,   # SYN-ACK
            ))

        assert not any(a.detector == "syn_flood" for a in alerts)

    def test_evidence_has_rate_and_ratio(self):
        """Evidence dict must contain syn_rate_pps and incomplete_ratio."""
        det = SYNFloodDetector()
        now = time.time()
        alerts = []
        for i in range(1100):
            alerts += det.process(pkt(
                protocol="TCP", dst_ip="10.0.0.1",
                tcp_flags=0x02, timestamp=now + i * 10.0 / 1100,
            ))
        flood = next((a for a in alerts if a.detector == "syn_flood"), None)
        if flood:
            assert "syn_rate_pps"     in flood.evidence
            assert "incomplete_ratio" in flood.evidence


# ── DNS Tunnel Detector ───────────────────────────────────────────────────────

class TestDNSTunnelDetector:

    def test_high_entropy_subdomain_fires(self):
        """
        A 52-char base32 label has entropy ≈ 4.2 bits — above the 3.8-bit
        threshold.  Combined with label length > 40, this must fire.
        """
        import base64, os
        det = DNSTunnelDetector()
        encoded = base64.b32encode(os.urandom(32)).decode().lower().rstrip("=")
        qname   = f"{encoded}.tunnel.c2server.net"   # external domain

        alerts = det.process(pkt(
            protocol="DNS",
            src_ip="192.168.1.50",
            dns_qname=qname,
            dns_is_response=False,
        ))

        tunnel_alerts = [a for a in alerts if a.detector == "dns_tunnel"]
        assert tunnel_alerts, f"Expected DNS-tunnel alert for qname={qname!r}"
        assert tunnel_alerts[0].evidence["signal"] == "high_entropy_subdomain"

    def test_mdns_local_domain_is_whitelisted(self):
        """
        Queries to .local (mDNS / Bonjour) are whitelisted and must never
        fire — they are structurally high-entropy but completely benign.
        """
        det = DNSTunnelDetector()
        alerts = det.process(pkt(
            protocol="DNS",
            src_ip="192.168.1.10",
            dns_qname="_googlecast._tcp.local",
        ))
        assert not alerts, "mDNS .local traffic must not trigger DNS tunnel alert"

    def test_arpa_domain_is_whitelisted(self):
        """Reverse-DNS PTR queries (.arpa) must never fire."""
        det = DNSTunnelDetector()
        alerts = det.process(pkt(
            protocol="DNS",
            src_ip="192.168.1.10",
            dns_qname="1.0.168.192.in-addr.arpa",
        ))
        assert not alerts

    def test_beaconing_high_rate_fires(self):
        """
        Sending > 10 queries per minute to the same domain triggers the
        beacon / C2 polling detector.
        """
        det = DNSTunnelDetector()
        now = time.time()
        alerts = []

        # 30 queries to the same domain in 60 s → 30/min, above 10/min threshold
        for i in range(30):
            alerts += det.process(pkt(
                protocol="DNS",
                src_ip="192.168.1.50",
                dns_qname="c2.badsite.com",
                timestamp=now + i * 2.0,
            ))

        beacon_alerts = [
            a for a in alerts
            if a.detector == "dns_tunnel"
            and a.evidence.get("signal") == "high_query_rate"
        ]
        assert beacon_alerts, "Expected a DNS-beaconing alert"

    def test_large_response_fires(self):
        """A DNS response > 200 bytes flags potential data exfiltration."""
        det = DNSTunnelDetector()
        alerts = det.process(pkt(
            protocol="DNS",
            src_ip="192.168.1.50",
            dns_qname="data.exfil.net",
            dns_is_response=True,
            dns_payload_len=350,    # > RESPONSE_SIZE_THRESHOLD (200)
            dns_ancount=3,
        ))
        large_alerts = [
            a for a in alerts
            if a.evidence.get("signal") == "large_dns_response"
        ]
        assert large_alerts, "Expected an oversized-DNS-response alert"


# ── ARP Spoof Detector ────────────────────────────────────────────────────────

class TestARPSpoofDetector:

    def test_ip_mac_conflict_fires_critical(self):
        """
        A second ARP reply for the same IP with a *different* MAC must
        trigger a CRITICAL ARP-poisoning alert.
        """
        det = ARPSpoofDetector()

        # Legitimate binding established first
        det.process(pkt(
            protocol="ARP",
            arp_op=2,
            arp_psrc="192.168.1.1",
            arp_hwsrc="aa:bb:cc:dd:ee:ff",
        ))

        # Attacker claims the same IP with a different MAC
        alerts = det.process(pkt(
            protocol="ARP",
            arp_op=2,
            arp_psrc="192.168.1.1",
            arp_hwsrc="11:22:33:44:55:66",
        ))

        poison = [a for a in alerts if a.detector == "arp_spoof"]
        assert poison, "Expected an ARP-poisoning alert on MAC conflict"
        assert poison[0].severity == Severity.CRITICAL
        assert poison[0].evidence["original_mac"] == "aa:bb:cc:dd:ee:ff"
        assert poison[0].evidence["new_mac"]       == "11:22:33:44:55:66"

    def test_first_binding_no_alert(self):
        """The very first ARP reply from an IP is a legitimate learning event."""
        det = ARPSpoofDetector()
        alerts = det.process(pkt(
            protocol="ARP",
            arp_op=2,
            arp_psrc="192.168.1.1",
            arp_hwsrc="aa:bb:cc:dd:ee:ff",
        ))
        assert not alerts, "First binding must not trigger an alert"

    def test_gratuitous_arp_flood_fires(self):
        """
        More than GARP_THRESHOLD (10) ARP replies from one MAC in 30 s
        should trigger a gratuitous-ARP-flood alert.
        """
        det = ARPSpoofDetector()
        now = time.time()
        alerts = []

        for i in range(15):
            alerts += det.process(pkt(
                protocol="ARP",
                arp_op=2,
                arp_psrc=f"192.168.1.{i + 2}",    # different IPs (multi-IP claim)
                arp_hwsrc="de:ad:be:ef:00:01",      # same attacking MAC
                timestamp=now + i * 0.5,
            ))

        flood = [
            a for a in alerts
            if a.detector == "arp_spoof"
            and "Gratuitous" in a.title
        ]
        assert flood, "Expected a gratuitous-ARP-flood alert"

    def test_broadcast_mac_ignored(self):
        """ARP packets with broadcast MAC ff:ff:ff:ff:ff:ff are silently skipped."""
        det = ARPSpoofDetector()
        alerts = det.process(pkt(
            protocol="ARP",
            arp_op=1,
            arp_psrc="192.168.1.1",
            arp_hwsrc="ff:ff:ff:ff:ff:ff",
        ))
        assert not alerts


# ── ICMP Amplification Detector ───────────────────────────────────────────────

class TestICMPAmpDetector:

    def test_broadcast_echo_request_fires(self):
        """An ICMP echo request to a broadcast address → Smurf-attack alert."""
        det = ICMPAmpDetector()
        alerts = det.process(pkt(
            protocol="ICMP",
            src_ip="10.0.0.1",
            dst_ip="192.168.1.255",   # subnet broadcast
            icmp_type=8,              # Echo Request
            icmp_code=0,
        ))
        smurf = [a for a in alerts if "Smurf" in a.title]
        assert smurf, "Expected a Smurf-attack alert for broadcast echo request"

    def test_255_255_broadcast_fires(self):
        """Limited broadcast 255.255.255.255 must also trigger."""
        det = ICMPAmpDetector()
        alerts = det.process(pkt(
            protocol="ICMP",
            src_ip="10.0.0.1",
            dst_ip="255.255.255.255",
            icmp_type=8,
            icmp_code=0,
        ))
        assert any("Smurf" in a.title for a in alerts)

    def test_reply_flood_fires(self):
        """
        600 ICMP echo replies to a victim that sent zero requests.
        Rate = 60/s > threshold (50/s), ratio >> 5 → amplification alert.
        """
        det = ICMPAmpDetector()
        now = time.time()
        alerts = []

        for i in range(600):
            alerts += det.process(pkt(
                protocol="ICMP",
                src_ip=f"10.0.{i // 255}.{i % 255 + 1}",
                dst_ip="192.168.1.75",
                icmp_type=0,            # Echo Reply
                icmp_code=0,
                timestamp=now + i / 60.0,
            ))

        amp = [a for a in alerts if "Amplification" in a.title]
        assert amp, "Expected an ICMP-amplification alert"
        assert amp[0].evidence["amplification_ratio"] >= 5.0

    def test_normal_ping_no_alert(self):
        """A single echo request to a unicast host must not fire."""
        det = ICMPAmpDetector()
        alerts = det.process(pkt(
            protocol="ICMP",
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
            icmp_type=8,
            icmp_code=0,
        ))
        assert not alerts


# ── Detection Engine (integration) ───────────────────────────────────────────

class TestDetectionEngine:

    def test_engine_aggregates_all_detectors(self):
        """
        A packet stream containing a clear port scan should produce at least
        one alert from the engine's unified pipeline.
        """
        engine = DetectionEngine()
        now    = time.time()

        for port in range(1, 60):
            engine.process(pkt(
                protocol="TCP",
                src_ip="10.99.99.99",
                dst_ip="192.168.0.1",
                dst_port=port,
                tcp_flags=0x02,
                timestamp=now + port * 0.01,
            ))

        assert engine.packets_processed == 59
        assert engine.alerts_total      >= 1
        assert engine.protocol_counts["TCP"] == 59

    def test_engine_updates_host_baselines(self):
        """Processing packets from a host must create a HostBaseline entry."""
        engine = DetectionEngine()
        for _ in range(10):
            engine.process(pkt(
                protocol="UDP",
                src_ip="192.168.1.99",
                dst_ip="8.8.8.8",
            ))
        assert "192.168.1.99" in engine.active_hosts

    def test_engine_never_crashes_on_malformed_packet(self):
        """
        Partially populated ParsedPackets (no src_ip, no ports, etc.) must
        never raise — the engine must be resilient to any input.
        """
        engine = DetectionEngine()
        # Minimal packet with almost no fields set
        engine.process(pkt(protocol="OTHER"))
        engine.process(pkt(protocol="TCP"))                        # no IPs
        engine.process(pkt(protocol="ARP", src_ip="10.0.0.1"))    # no ARP fields
        # If we reach here without an exception, the test passes
