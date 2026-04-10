# Network Intrusion Detection System

A production-grade, real-time network intrusion detection system in Python.
Combines **statistical anomaly detection** with **protocol-level heuristics** to identify
threats without relying on static rule sets alone.

> Built to demonstrate: network protocol depth, statistical anomaly detection,
> real-time async systems programming, and security domain knowledge.

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. On Windows — install Npcap for live capture (one-time setup)
#    https://npcap.com  →  check "WinPcap API-compatible mode"

# 3. Run — an interactive menu appears when no flags are given
python main.py
```

The startup menu lets you choose between:

| Option | What it does | Privileges needed |
|---|---|---|
| **1** Live capture | Sniff your active network interface | Admin / root |
| **2** Analyze PCAP | Replay any `.pcap` / `.pcapng` file | None |
| **3** Generate test PCAP | Craft synthetic attacks and analyze them | None |
| **4** List interfaces | Show available capture interfaces | None |

---

## Dashboard

```
┌─────────────────────────────────────────────────────────────────────┐
│  NIDS   Interface: eth0   Uptime: 00:05:12   Captured: 14,231      │
│  ■ CRITICAL: 0   ■ HIGH: 2   ■ MEDIUM: 1   ■ LOW: 0               │
├──────────────────────────────────┬──────────────────────────────────┤
│  Live Alerts  [3 total]          │  Host Baselines                 │
│                                  │  IP              Pkts  Rate  σ  │
│  23:41  [HIGH]  port_scan        │  192.168.1.116    211   4.1  ↑  │
│    Port Scan Detected            │  192.168.1.149    187   1.6  —  │
│    10.0.0.99 → 192.168.1.100     │  192.168.1.50      44   0.2  —  │
│                                  ├─────────────────────────────────┤
│  23:42  [HIGH]  dns_tunnel       │  Protocol Distribution          │
│    DNS Tunneling Detected        │  TCP  ████████████████  55%     │
│    192.168.1.50 → c2server.net   │  DNS  ████████          27%     │
│                                  │  UDP  ██████            17%     │
│  23:43  [CRIT]  arp_spoof        │  ARP  █                  1%     │
│    ARP Cache Poisoning           │                                 │
│    192.168.1.1  MAC conflict     │                                 │
├──────────────────────────────────┴──────────────────────────────────┤
│  [q] Quit   MITRE ATT&CK mapped   SIEM → alerts.ndjson             │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Detectors

### Port Scan / Network Sweep — T1046
Maintains a per-source **sliding window (60 s)** of unique `(dst_ip, dst_port)` contacts
using a `SlidingWindowSet` — O(1) amortised per packet.

| Pattern | Signal | Severity |
|---|---|---|
| Vertical scan | Many ports, 1–5 hosts | MEDIUM / HIGH |
| Horizontal sweep | Many hosts, same port | MEDIUM / HIGH |
| Distributed scan | Both dimensions high | CRITICAL |

Also tracks SYN-only ratio — a ratio near 1.0 (no RSTs seen) indicates a
**stealth / half-open scan** (nmap -sS).

### SYN Flood — T1498.001
Two complementary signals per destination:
1. **Absolute SYN rate** ≥ 100/s → fires immediately (no warmup)
2. **Statistical z-score** > 4σ above Welford baseline **and** SYN ratio > 85%
   → catches distributed floods where no single source exceeds rate limits

### DNS Tunneling — T1071.004
Four independent signals reduce false positives:

| Signal | Threshold | Catches |
|---|---|---|
| Subdomain Shannon entropy | > 3.8 bits | base32/64 encoded payloads |
| Max label length | > 40 chars | iodine / dns2tcp default chunk size |
| Query rate per domain | > 10/min | C2 beacon polling interval |
| DNS response size | > 200 bytes | Data exfiltration via TXT/NULL records |

`.local`, `.arpa`, `.internal`, and `.localhost` are **whitelisted** to prevent
mDNS / Bonjour false positives.

### ARP Cache Poisoning — T1557.002
Maintains a trusted **IP → MAC binding table** (first-packet-wins).

| Signal | Severity | Description |
|---|---|---|
| IP–MAC conflict | CRITICAL | Same IP, new MAC = poisoning attempt |
| Gratuitous ARP flood | HIGH | > 10 unsolicited replies / 30 s |
| MAC claiming multiple IPs | HIGH | One MAC, many IPs = active spoofing tool |

### ICMP Amplification / Smurf — T1498.002
- **Echo request to broadcast** (.255 or 255.255.255.255) → Smurf source alert
- **Reply/request ratio** ≥ 5× at ≥ 50 replies/s → victim-side reflection alert

### Statistical Baseline Anomaly
Per-host **Welford accumulator** tracks packet rate. Fires when instantaneous rate
deviates > 4σ from the established mean. Warm-up of 200 packets suppresses false
positives on cold start.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Scapy AsyncSniffer  (OS thread)                                 │
│         │  loop.call_soon_threadsafe()  [thread boundary]        │
│         ▼                                                        │
│  asyncio.Queue[raw Scapy Packet]   (bounded 20 000)             │
│         │                                                        │
│  process_task  (event loop)                                      │
│    parse_packet() → ParsedPacket   [normalisation layer]         │
│    DetectionEngine.process()                                     │
│      ├── BaselineManager   Welford per-host statistics           │
│      ├── PortScanDetector  SlidingWindowSet unique contacts      │
│      ├── SYNFloodDetector  EWMA + Welford rate baseline          │
│      ├── DNSTunnelDetector Shannon entropy + beacon rate         │
│      ├── ARPSpoofDetector  IP→MAC binding table                  │
│      └── ICMPAmpDetector   reply/request asymmetry ratio         │
│         │                                                        │
│  asyncio.Queue[Alert]   (bounded 2 000)                         │
│         │                                                        │
│  alert_task                                                      │
│    AlertManager.add()  +  SIEMWriter.write()                    │
│                                                                  │
│  dashboard_task   Rich Live, 2 Hz refresh                        │
└──────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
nids/
├── capture/
│   ├── sniffer.py        AsyncSniffer → asyncio.Queue bridge
│   └── parser.py         Scapy Packet → ParsedPacket normalisation
├── utils/
│   └── stats.py          WelfordAccumulator, EWMA, SlidingWindow*, shannon_entropy
├── detection/
│   ├── models.py         Alert, Severity, MITRETag dataclasses
│   ├── baseline.py       Per-host Welford statistical baseline
│   ├── port_scan.py      Sliding-window scan detector
│   ├── syn_flood.py      Half-open connection ratio + rate detector
│   ├── dns_tunnel.py     Entropy + beacon + payload-size detector
│   ├── arp_spoof.py      IP→MAC binding table + flood detector
│   ├── icmp_amp.py       Smurf + reflection detector
│   └── engine.py         Pipeline orchestrator
├── alerts/
│   ├── manager.py        Ring-buffer alert store
│   └── siem.py           NDJSON SIEM writer (ECS-aligned)
└── dashboard/
    └── ui.py             Rich Live full-screen terminal UI
tools/
└── generate_test_pcap.py Crafts a PCAP with all six attack patterns
tests/
├── test_stats.py         Unit tests for all statistical primitives
└── test_detectors.py     Unit tests for every detector + engine
main.py                   CLI entry point, interactive menu, asyncio runtime
```

---

## Installation

```bash
pip install -r requirements.txt
```

**Windows:**
```
1. Install Npcap from https://npcap.com
   - Check "WinPcap API-compatible mode" during install
2. Run terminal as Administrator for live capture
```

**Linux / macOS:**
```bash
sudo setcap cap_net_raw+ep $(which python3)   # or run as root
```

---

## Usage

```bash
# Interactive menu (recommended)
python main.py

# Live capture on a specific interface
python main.py -i eth0

# Replay a PCAP file (no privileges required)
python main.py --pcap captures/traffic.pcap

# Generate synthetic attack PCAP and replay immediately
python tools/generate_test_pcap.py
python main.py --pcap test_traffic.pcap

# Headless / CI mode — alerts to SIEM file only
python main.py --no-ui --siem /var/log/nids/alerts.ndjson

# List available interfaces
python main.py --list-interfaces

# Verbose logging
python main.py -v
```

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

```
tests/test_stats.py
  TestWelfordAccumulator
    ✓ test_single_value_mean
    ✓ test_single_value_variance_is_zero
    ✓ test_known_dataset_mean_and_std
    ✓ test_z_score_returns_zero_when_std_is_zero
    ✓ test_z_score_known_value
    ✓ test_is_anomalous_fires_on_outlier
    ✓ test_is_anomalous_quiet_during_warmup
    ✓ test_normal_value_not_anomalous
    ✓ test_incremental_equals_batch
  TestEWMA ... (4 tests)
  TestShannonEntropy ... (6 tests)
  TestSlidingWindowCounter ... (4 tests)
  TestSlidingWindowSet ... (3 tests)

tests/test_detectors.py
  TestPortScanDetector ... (4 tests)
  TestSYNFloodDetector ... (3 tests)
  TestDNSTunnelDetector ... (5 tests)
  TestARPSpoofDetector ... (4 tests)
  TestICMPAmpDetector ... (4 tests)
  TestDetectionEngine ... (3 tests)
```

---

## SIEM Alert Format (ECS-aligned NDJSON)

```json
{
  "alert_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "@timestamp": "2024-11-15T14:32:07.000Z",
  "severity": "HIGH",
  "title": "DNS Tunneling Detected",
  "description": "High-entropy DNS query from 10.0.0.42 to 'c2server.net' (entropy=4.23 bits, label_len=52)",
  "detector": "dns_tunnel",
  "network": {
    "src_ip": "10.0.0.42",
    "dst_ip": null,
    "src_port": null,
    "dst_port": null
  },
  "threat": {
    "technique_id": "T1071.004",
    "technique": "Application Layer Protocol: DNS",
    "tactic": "Command and Control"
  },
  "evidence": {
    "base_domain": "c2server.net",
    "subdomain_entropy": 4.23,
    "max_label_length": 52,
    "entropy_z_score": 3.87,
    "signal": "high_entropy_subdomain"
  }
}
```

Compatible with: **Elastic / ECS**, **Splunk HEC**, **Filebeat tail**, **QRadar LEEF** (via transform).

---

## Key Algorithms

### Welford's Online Algorithm
Computes running mean and variance in a single pass, O(1) memory.

```
n   += 1
δ    = x − mean_old
mean += δ / n
δ₂   = x − mean_new        ← uses updated mean (Welford's trick)
M₂  += δ × δ₂
variance = M₂ / (n − 1)    ← Bessel's correction (unbiased)
```

Avoids catastrophic cancellation in `Σx²/n − (Σx/n)²` for large values.

### Shannon Entropy
`H(X) = −Σ p(x) · log₂ p(x)` — bits of information per symbol.

| Source | Entropy (bits) |
|---|---|
| Legitimate hostname ("www") | 1.5 – 2.5 |
| Random English text | 2.5 – 3.5 |
| Hex-encoded data | 3.5 – 4.0 |
| Base32 (iodine default) | 4.0 – 4.5 |
| Base64 random data | 4.5 – 5.2 |

### Sliding-Window Unique Set
Each source IP maintains a `deque` of `(timestamp, value)` pairs.
Expired entries are lazily pruned on access — amortised O(1).
Used for unique port / destination IP counting in scan detection.
