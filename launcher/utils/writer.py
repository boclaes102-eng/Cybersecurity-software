"""
Thread-aware stdout/stderr interceptor.

Install once at startup (before any tool imports). Because Rich's Console
stores a reference to sys.stdout at creation time, and this writer IS
sys.stdout, all Console output is automatically routed per-thread to
whatever callback the active tool registered.
"""
from __future__ import annotations

import re
import sys
import threading
from typing import Callable, Optional

_ANSI = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_BARE_CR = re.compile(r"\r(?!\n)")

_local = threading.local()
_installed = False
_orig_stdout = None
_orig_stderr = None


def install() -> None:
    """Replace sys.stdout/stderr with thread-aware writers (idempotent)."""
    global _installed, _orig_stdout, _orig_stderr
    if _installed:
        return
    _orig_stdout = sys.stdout
    _orig_stderr = sys.stderr
    sys.stdout = _Writer(_orig_stdout)
    sys.stderr = _Writer(_orig_stderr)
    _installed = True


def set_callback(cb: Callable[[str], None]) -> None:
    """Route current thread's output to *cb*."""
    _local.callback = cb


def clear_callback() -> None:
    """Remove the current thread's output callback."""
    _local.callback = None


class _Writer:
    """Proxy that delegates per-thread to a registered callback or original stream."""

    def __init__(self, original):
        self._orig = original

    def write(self, text: str) -> int:
        cb: Optional[Callable] = getattr(_local, "callback", None)
        if cb is not None:
            cleaned = _BARE_CR.sub("", _ANSI.sub("", text))
            if cleaned:
                cb(cleaned)
        else:
            self._orig.write(text)
        return len(text)

    def flush(self) -> None:
        if getattr(_local, "callback", None) is None:
            self._orig.flush()

    def isatty(self) -> bool:
        # Returning False tells Rich to skip ANSI colour codes and spinners.
        return False

    def __getattr__(self, name):
        return getattr(self._orig, name)
