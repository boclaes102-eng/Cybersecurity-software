# CyberSuite Pro

**Three professional security tools — one unified launcher.**

| Tool | What it does |
|------|-------------|
| **NIDS** — Network Intrusion Detection System | Real-time packet capture with 6 attack detectors (Port Scan, SYN Flood, DNS Tunneling, ARP Poisoning, ICMP Amplification, Statistical Anomaly). Live interface capture or PCAP replay. SIEM export. |
| **PAS** — Password Auditing Suite | Hash identification, offline cracking, entropy scoring, HIBP k-anonymity breach check, wordlist mutation, and full audit pipeline. |
| **SMA** — Static Malware Analyzer | PE / ELF binary analysis without execution. Shannon entropy, 18 MITRE ATT&CK behavioral rules, YARA scanning, VirusTotal v3 lookup, JSON report. |

---

## Quick start

### 1 — Install (first time on a new machine)

Requires **Python 3.11+** on PATH.

```bat
setup.bat
```

This creates a `.venv` and installs all dependencies from `requirements_launcher.txt`.

### 2 — Run the launcher

```bat
run.bat
```

A dark-themed GUI window opens. Choose any tool from the left sidebar.

---

## Build a standalone `.exe`

```bat
.venv\Scripts\activate
python build.py
```

Produces `dist/CyberSuite.exe` — a single portable executable you can distribute.  
No Python installation required on the target machine.

---

## Keyboard shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+L` | Clear output console |
| `Escape` | Stop the running tool |

---

## Project structure

```
CyberSuite/
├── launcher/               GUI launcher (CustomTkinter)
│   ├── main.py             Entry point
│   ├── app.py              Main window (sidebar + console)
│   ├── pages/              One page per tool + home dashboard
│   └── utils/              Thread runner, stdout interceptor, path resolution
├── Network-Intrusion-Detection-System/
├── Password-Auditing-Suite/
├── Static-Malware-Analyzer/
├── requirements_launcher.txt
├── setup.bat               One-time dependency installer
├── run.bat                 Launch in dev mode
└── build.py                Produce dist/CyberSuite.exe
```

---

## Notes

- **Live NIDS capture** requires [Npcap](https://npcap.com/) (Windows) or `cap_net_raw+ep` / root (Linux).
- **VirusTotal** lookups require a free API key from [virustotal.com](https://www.virustotal.com/).  
  Set `VT_API_KEY` as an environment variable or paste it directly in the SMA page.
- `yara-python` is optional — SMA gracefully skips YARA scanning if it isn't installed.
