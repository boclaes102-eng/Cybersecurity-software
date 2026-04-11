# CyberSuite Pro

**Three professional security tools — one unified dark-themed GUI launcher.**

CyberSuite integrates a Network Intrusion Detection System, a Password Auditing Suite, and a Static Malware Analyzer into a single CustomTkinter application. The malware analyzer maps findings to **18 MITRE ATT\&CK behavioral rules**, and every tool runs in its own background thread so the GUI never freezes. A single `setup.bat` + `run.bat` workflow gets you from zero to running in under a minute; `build.py` produces a portable single-file `.exe` via PyInstaller.

---

## Screenshot

![CyberSuite Pro launcher](assets/screenshot.png)

> **Note:** drop a screenshot into `assets/screenshot.png` to make this render on GitHub.

---

## Tools

| Tool | What it does |
|------|-------------|
| **NIDS** — Network Intrusion Detection System | Real-time packet capture with 6 attack detectors (Port Scan, SYN Flood, DNS Tunneling, ARP Poisoning, ICMP Amplification, Statistical Anomaly). Live interface capture or PCAP replay. SIEM export. |
| **PAS** — Password Auditing Suite | Hash identification, offline cracking, entropy scoring, HIBP k-anonymity breach check, wordlist mutation, and full audit pipeline. |
| **SMA** — Static Malware Analyzer | PE / ELF binary analysis without execution. Shannon entropy, **18 MITRE ATT\&CK behavioral rules**, YARA scanning, VirusTotal v3 lookup, JSON report. |

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

## Architecture decisions

Building a unified launcher for three independent CLI tools involved a few non-obvious design choices.

**Tools run in-process, not as subprocesses.**  
Each tool is loaded at runtime via `importlib.util.spec_from_file_location()` into the same Python interpreter. This avoids the overhead of spawning a child process and lets the launcher share the same virtual environment without any path juggling. The trade-off is that a tool crash can theoretically affect the launcher — mitigated by running every tool in a daemon `threading.Thread`.

**Thread-aware stdout interceptor.**  
The three tools all print to `sys.stdout`. Rather than patching every `print()` call inside each tool, `launcher/utils/writer.py` wraps `sys.stdout` with a custom `_Writer` class. It uses `threading.local()` so each worker thread carries its own GUI callback; the main thread and other threads fall through to the original stream untouched. This means zero changes were needed to the underlying tools' source code.

**`sys.argv` surgery for argparse-based tools.**  
NIDS and SMA use `argparse`. The launcher saves `sys.argv`, replaces it with the constructed argument list, calls `mod.main()`, then restores `sys.argv` in a `finally` block. PAS uses Click, which is invoked programmatically via `mod.cli.main(args, standalone_mode=False)` — no `sys.argv` manipulation needed.

**Stopping a thread gracefully.**  
Background threads are stopped by injecting `KeyboardInterrupt` via `ctypes.PyThreadState_SetAsyncExc`. This works reliably as long as the thread is executing Python bytecode. It does **not** work when a thread is blocked inside a C-level call such as `input()` — which is why the NIDS "Interactive Menu" mode was removed. The GUI already surfaces all five menu options as individual form fields, so nothing was lost.

**Headless test suite.**  
The launcher's GUI classes are tested without a display by stubbing `customtkinter` in `sys.modules` before any imports. Widget stubs must be real Python classes (not `MagicMock` instances) because page classes inherit from them — `MagicMock`'s metaclass conflicts with normal class creation. 147 tests cover the thread runner, stdout interceptor, path resolution, every `_build_argv` mode/flag combination, tag classification, and integration smoke tests.

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
├── assets/                 Screenshots and images for README
├── tests/                  Launcher unit + integration tests (pytest)
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

---

## License

[MIT](LICENSE)
