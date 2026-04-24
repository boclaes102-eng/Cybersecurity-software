# CyberSuite Pro

**The desktop attack layer of a three-platform cybersecurity ecosystem — 15 integrated security modules in one dark-themed GUI launcher.**

CyberSuite Pro is a professional penetration testing toolkit built in Python and CustomTkinter. It covers the full offensive workflow: network discovery, MITM attacks, credential harvesting, exploitation, Active Directory enumeration, and professional report generation — all from one application that requests UAC admin elevation automatically on launch.

**Web Dashboard:** [Online-Cyber-Dashboard](https://github.com/boclaes102-eng/Online-Cyber-dashboard) &nbsp;·&nbsp; **Backend API:** [Threat Intel Platform](https://github.com/boclaes102-eng/threat-intel-platform)

---

## Three-Platform Ecosystem

```
┌──────────────────────────────────────────────────────────────────────┐
│                  CyberOps Dashboard  (Next.js · Vercel)              │
│                                                                       │
│   Operator runs 56 recon tools: IP lookup, subdomain enum,           │
│   SSL inspection, port scan, IOC enrichment, etc.                    │
│   ↓  clicks "Save to Workspace" on any result                        │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ HTTPS · X-API-Key (server-side proxy)
                                ▼
┌──────────────────────────────────────────────────────────────────────┐
│              Threat Intel Platform  (Fastify · Railway)              │
│                                                                       │
│   recon_sessions table stores: tool · target · summary · full JSON   │
│   Background workers: CVE feed · IOC enrichment · SIEM correlation   │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ X-API-Key (from ~/.cybersuite/config.json)
                                ▼
┌──────────────────────────────────────────────────────────────────────┐
│              CyberSuite Pro  (this repo · Python · Windows)          │
│                                                                       │
│   Recon page → fetches sessions → one click → active target set      │
│   NetMap → MITM → Creds → MSF: complete recon-to-exploitation chain  │
│   AD Enumeration → Report Generator: findings delivered to client    │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Modules

### Network & Discovery
| Module | What it does |
|---|---|
| **Network Map** | Phase 1: ARP scan via Scapy — live hosts, MAC, hostname. Phase 2: nmap deep scan — OS fingerprint, open ports with service versions, MAC vendor. Phase 3: SNMP router ARP table query to reveal offline devices. Interactive 2D canvas with draggable nodes, colour-coded by OS and risk level (red ring = high-risk port open). Click any node → Set as Target → pre-fills all attack tools. |
| **NIDS** | Real-time packet capture with 6 attack detectors: Port Scan, SYN Flood, DNS Tunneling, ARP Poisoning, ICMP Amplification, Statistical Anomaly. Live interface or PCAP replay. |
| **WiFi Recon** | Survey nearby networks (netsh, no monitor mode needed). WPA2 handshake capture via airodump-ng + deauth attack via aireplay-ng. Export capture for hashcat cracking. |

### Attack
| Module | What it does |
|---|---|
| **MITM / ARP Spoof** | MAC changer (Windows registry + adapter restart, random or custom). Bidirectional ARP poisoning via Scapy — tells target that gateway is at your MAC and vice versa. IP forwarding keeps both sides connected and unaware. |
| **SSL Interceptor** | mitmproxy launched in transparent mode. Automatic port 80/443 redirect via `netsh portproxy`. Web UI opens at localhost:8081 — full request/response inspection live. CA cert path copied to clipboard for silent HTTPS interception. |
| **Credential Harvester** | Scapy packet sniffer extracts credentials from HTTP POST forms, Basic Auth headers, and NTLM authenticate messages. Live table with raw packet detail panel. One-click export to hashcat-ready format (`hashcat -m 5600`). |
| **Metasploit Bridge** | Built-in CVE → module map (EternalBlue, BlueKeep, PrintNightmare, Log4Shell, ZeroLogon, etc.). Search Metasploit modules from the GUI. Pre-fills RHOST, RPORT, LHOST, LPORT, and payload — launches msfconsole in a new window with `use module; set options; show options` pre-executed. |
| **Payload Generator** | Reverse shells, bind shells, web shells. Encoder (base64 / URL / hex / PowerShell). Built-in TCP listener. |

### Post-Exploitation & Analysis
| Module | What it does |
|---|---|
| **AD Enumeration** | Pure-Python LDAP via ldap3 — no domain join required. Enumerates: Kerberoastable accounts (SPNs set), AS-REP roastable (no pre-auth), unconstrained delegation computers, password-not-required accounts, stale accounts (90+ days inactive), Domain Admins members. One click exports all findings directly into the Report Generator. |
| **Password Auditing** | Hash identification, offline cracking, entropy scoring, HIBP k-anonymity breach check, wordlist mutation. |
| **Static Malware Analyzer** | PE/ELF binary analysis without execution. Shannon entropy per section, 18 MITRE ATT&CK behavioral rules, YARA scanning, VirusTotal v3 lookup. |
| **Web App Tester** | Directory brute-force, header security audit, SQLi detection, reflected XSS detection. Multi-threaded. |
| **CVE & Exploit Helper** | NVD API v2 CVE search, ExploitDB lookup, results by CVSS score. |

### Reporting & Workspace
| Module | What it does |
|---|---|
| **Report Generator** | Persistent findings tracker (severity, category, host, CVSS, description, evidence, remediation). Auto-imports high-risk hosts from the last NetMap scan. Generates a professional styled HTML report with executive summary, risk bar, findings table, and per-finding evidence blocks. Print to PDF from the browser. Findings persist between sessions in `~/.cybersuite/findings.json`. |
| **Recon Workspace** | Fetches saved recon sessions from the Threat Intel Platform backend. One click sets active target across all tools. Full offline fallback with manual entry. |

---

## What Makes This Special

### Tools run in-process, not as subprocesses

Each tool is loaded at runtime via `importlib.util.spec_from_file_location()` — no child process, no subprocess pipes. The trade-off (a tool crash affects the launcher) is mitigated by running every tool in a daemon `threading.Thread` with a `try/except` wrapper.

### Thread-aware stdout interceptor

`launcher/utils/writer.py` wraps `sys.stdout` with a `threading.local()` based `_Writer`. Each worker thread carries its own GUI callback; the main thread falls through to the original stream. **Zero changes to any tool's source code.**

### Two-layer stop mechanism

1. Set `stop_event` (cooperative — tool checks at checkpoints)
2. Inject `KeyboardInterrupt` via `ctypes.PyThreadState_SetAsyncExc` (pre-emptive fallback)

### Auto UAC elevation

`launcher/main.py` checks `ctypes.windll.shell32.IsUserAnAdmin()` at startup. If not admin, re-launches itself via `ShellExecuteW("runas", ...)` — the UAC prompt appears automatically. Works for both the Python script and the compiled `.exe`.

### Shared palette and UI helpers

`launcher/utils/colors.py` — single shared colour palette imported by all pages.
`launcher/utils/ui.py` — shared component builders (`card()`, `btn_primary()`, `btn_ghost()`, `toolbar()`, etc.) — new modules are built in a third of the code.

---

## Quick Start

Requires **Python 3.11+** on PATH and **Npcap** for packet capture tools.

```bat
setup.bat    # create .venv, install all dependencies (first run only)
run.bat      # launch GUI — UAC prompt appears automatically
```

### Build a standalone `.exe`

```bat
.venv\Scripts\activate
python build.py
# → dist/CyberSuite.exe  (portable, no Python needed on target)
```

---

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+L` | Clear output console |
| `Escape` | Stop running tool |

---

## Project Structure

```
CyberSuite/
├── launcher/
│   ├── main.py               Entry point + UAC auto-elevation
│   ├── app.py                Main window — grouped sidebar, console, nav
│   ├── pages/
│   │   ├── home_page.py      Dashboard overview (all 15 modules)
│   │   ├── recon_page.py     Recon Workspace (online + offline)
│   │   ├── netmap_page.py    Network Map (ARP + nmap + SNMP)
│   │   ├── mitm_page.py      MAC Changer + ARP Spoof + mitmproxy
│   │   ├── creds_page.py     Credential Harvester
│   │   ├── msf_page.py       Metasploit Bridge
│   │   ├── wifi_page.py      WiFi Recon & Attack
│   │   ├── ad_page.py        Active Directory Enumeration
│   │   ├── report_page.py    Pentest Report Generator
│   │   ├── nids_page.py      Network Intrusion Detection
│   │   ├── pas_page.py       Password Auditing Suite
│   │   ├── sma_page.py       Static Malware Analyzer
│   │   ├── wat_page.py       Web App Tester
│   │   ├── pgn_page.py       Payload Generator
│   │   └── ceh_page.py       CVE & Exploit Helper
│   └── utils/
│       ├── colors.py         Shared colour palette
│       ├── ui.py             Shared UI component helpers
│       ├── runner.py         Thread runner + two-layer stop
│       ├── writer.py         Thread-aware stdout interceptor
│       └── paths.py          Tool directory resolution
├── Network-Intrusion-Detection-System/
├── Password-Auditing-Suite/
├── Static-Malware-Analyzer/
├── Web-Application-Tester/
├── Payload-Generator/
├── CVE-Exploit-Helper/
├── tests/                    pytest test suite (headless)
├── requirements_launcher.txt
├── setup.bat
├── run.bat
└── build.py
```

---

## Dependencies

Core: `customtkinter`, `scapy`, `rich`, `numpy`, `python-nmap`, `pysnmp`, `psutil`, `mitmproxy`, `ldap3`, `requests`, `pefile`, `pyelftools`, `passlib`, `click`

Optional: `yara-python` (SMA YARA scanning), `aircrack-ng` suite (WiFi attacks), `metasploit-framework` (MSF Bridge)

---

## Notes

- **Packet capture (NIDS, NetMap ARP, Credential Harvester)** requires [Npcap](https://npcap.com/) on Windows.
- **nmap OS detection** requires Administrator — the app requests this automatically.
- **WiFi deauth / handshake capture** requires a WiFi adapter in monitor mode and the aircrack-ng suite.
- **Metasploit Bridge** requires Metasploit Framework installed (`msfconsole` in PATH).
- **VirusTotal** (SMA) requires a free API key from virustotal.com — set as `VT_API_KEY`.

---

## License

[MIT](LICENSE)
