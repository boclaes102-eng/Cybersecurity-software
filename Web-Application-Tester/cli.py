"""Web Application Tester — CLI entry point."""
from __future__ import annotations

import sys
import threading
from pathlib import Path

import click

# Ensure the WAT package is importable when run directly
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from wat.dir_scanner import scan as _dir_scan
from wat.header_analyzer import analyze as _header_analyze
from wat.sqli_fuzzer import fuzz as _sqli_fuzz
from wat.xss_fuzzer import fuzz as _xss_fuzz
from wat.models import Finding
from wat import reporter


def _print_finding(f: Finding) -> None:
    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
    icon = icons.get(f.severity, "•")
    if f.severity == "INFO" and f.type == "header_present":
        print(f"  {icon} {f.detail}")
        return
    print(f"\n{icon} [{f.severity}] {f.type.upper()} — {f.url}")
    print(f"   {f.detail}")
    if f.evidence:
        for k, v in f.evidence.items():
            print(f"   {k}: {v}")


@click.group()
def cli() -> None:
    """WAT — Web Application Tester"""


@cli.command()
@click.argument("url")
@click.option("--wordlist", "-w", default=None, help="Custom wordlist file")
@click.option("--ext", "-e", multiple=True, default=[".php", ".html", ".txt", ".bak"],
              show_default=True, help="Extensions to append (repeatable)")
@click.option("--threads", "-t", default=10, show_default=True)
@click.option("--timeout", default=5.0, show_default=True)
@click.option("--output", "-o", default=None, help="Save JSON report")
def dirscan(url: str, wordlist: str, ext: tuple, threads: int, timeout: float, output: str) -> None:
    """Brute-force directories and files on a web target."""
    stop = threading.Event()
    print(f"\n[*] Dir scan on {url}  (threads={threads})\n")
    try:
        findings = _dir_scan(url, wordlist, list(ext), threads, timeout, stop,
                             _print_finding, lambda m: print(m, end="", flush=True))
    except KeyboardInterrupt:
        stop.set()
        findings = []
    print(f"\n[+] Found {len(findings)} interesting paths")
    if output:
        reporter.save(findings, output)
        print(f"[+] Report → {output}")


@cli.command()
@click.argument("url")
@click.option("--timeout", default=10.0, show_default=True)
@click.option("--output", "-o", default=None, help="Save JSON report")
def headers(url: str, timeout: float, output: str) -> None:
    """Analyse HTTP security headers for a target URL."""
    print(f"\n[*] Header analysis for {url}\n")
    findings = _header_analyze(url, timeout, _print_finding)
    by_sev: dict[str, int] = {}
    for f in findings:
        if f.type != "header_present":
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    print(f"\n[+] Issues found: {by_sev or 'none'}")
    if output:
        reporter.save(findings, output)
        print(f"[+] Report → {output}")


@cli.command()
@click.argument("url")
@click.option("--timeout", default=10.0, show_default=True)
@click.option("--output", "-o", default=None, help="Save JSON report")
def sqli(url: str, timeout: float, output: str) -> None:
    """Fuzz GET parameters for SQL injection."""
    stop = threading.Event()
    print(f"\n[*] SQLi fuzzing {url}\n")
    try:
        findings = _sqli_fuzz(url, timeout, stop, _print_finding,
                              lambda m: print(m, end="", flush=True))
    except KeyboardInterrupt:
        stop.set()
        findings = []
    print(f"\n[+] {len(findings)} SQLi hit(s) found")
    if output:
        reporter.save(findings, output)
        print(f"[+] Report → {output}")


@cli.command()
@click.argument("url")
@click.option("--timeout", default=10.0, show_default=True)
@click.option("--output", "-o", default=None, help="Save JSON report")
def xss(url: str, timeout: float, output: str) -> None:
    """Fuzz GET parameters for reflected XSS."""
    stop = threading.Event()
    print(f"\n[*] XSS fuzzing {url}\n")
    try:
        findings = _xss_fuzz(url, timeout, stop, _print_finding,
                             lambda m: print(m, end="", flush=True))
    except KeyboardInterrupt:
        stop.set()
        findings = []
    print(f"\n[+] {len(findings)} XSS hit(s) found")
    if output:
        reporter.save(findings, output)
        print(f"[+] Report → {output}")


if __name__ == "__main__":
    cli()
