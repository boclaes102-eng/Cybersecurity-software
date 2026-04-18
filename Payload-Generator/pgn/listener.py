"""Simple TCP listener — catches reverse shell connections."""
from __future__ import annotations

import socket
import threading
from typing import Callable


def listen(
    port: int,
    stop_event: threading.Event,
    on_output: Callable[[str], None],
) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", port))
        srv.listen(1)
        srv.settimeout(1.0)
        on_output(f"[*] Listening on 0.0.0.0:{port} — waiting for connection…\n")

        conn: socket.socket | None = None
        addr = None
        while not stop_event.is_set():
            try:
                conn, addr = srv.accept()
                break
            except socket.timeout:
                continue

        if conn and not stop_event.is_set():
            on_output(f"[+] Shell received from {addr[0]}:{addr[1]}\n")
            on_output("[*] Type commands below (output appears here).\n\n")
            conn.settimeout(0.5)
            while not stop_event.is_set():
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    on_output(data.decode(errors="replace"))
                except socket.timeout:
                    continue
                except OSError:
                    break
            if conn:
                conn.close()
    except OSError as exc:
        on_output(f"[error] Cannot bind to port {port}: {exc}\n")
    finally:
        srv.close()
        on_output(f"[*] Listener on port {port} closed.\n")
