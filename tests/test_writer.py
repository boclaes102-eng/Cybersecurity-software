"""
Tests for launcher/utils/writer.py — thread-aware stdout interceptor.

Strategy: we test _Writer directly using io.StringIO as the backing
stream — this avoids pytest's own stdout capture intercepting our writes
before they reach the callback, which would make every routing test fail.

We still test install() for the side-effects on sys.stdout/sys.stderr,
but we save and restore those references ourselves.
"""
from __future__ import annotations

import io
import sys
import threading
import time

import pytest

import launcher.utils.writer as _mod
from launcher.utils.writer import _Writer, set_callback, clear_callback


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_writer() -> tuple[_Writer, io.StringIO]:
    """Create a _Writer backed by a fresh StringIO (no sys.stdout touching)."""
    buf = io.StringIO()
    return _Writer(buf), buf


def _with_cb(cb):
    """Context manager: set callback for current thread, clear on exit."""
    set_callback(cb)
    try:
        yield
    finally:
        clear_callback()


# ── install() ─────────────────────────────────────────────────────────────────

class TestInstall:
    def test_install_replaces_stdout(self):
        old_stdout  = sys.stdout
        old_stderr  = sys.stderr
        old_flag    = _mod._installed
        old_orig_o  = _mod._orig_stdout
        old_orig_e  = _mod._orig_stderr
        try:
            _mod._installed = False
            _mod.install()
            assert isinstance(sys.stdout, _Writer)
            assert isinstance(sys.stderr, _Writer)
        finally:
            sys.stdout        = old_stdout
            sys.stderr        = old_stderr
            _mod._installed   = old_flag
            _mod._orig_stdout = old_orig_o
            _mod._orig_stderr = old_orig_e

    def test_install_idempotent(self):
        _mod._installed = False
        _mod.install()
        first = sys.stdout
        _mod.install()   # second call — must be a no-op
        assert sys.stdout is first
        # Restore
        _mod._installed = False

    def test_orig_stdout_is_not_a_writer(self):
        old_flag   = _mod._installed
        old_orig_o = _mod._orig_stdout
        old_orig_e = _mod._orig_stderr
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        try:
            _mod._installed = False
            _mod.install()
            assert not isinstance(_mod._orig_stdout, _Writer)
        finally:
            sys.stdout        = old_stdout
            sys.stderr        = old_stderr
            _mod._installed   = old_flag
            _mod._orig_stdout = old_orig_o
            _mod._orig_stderr = old_orig_e


# ── _Writer.write — routing ────────────────────────────────────────────────────

class TestWriteRouting:
    def test_routes_to_callback_when_set(self):
        w, _buf = _make_writer()
        captured: list[str] = []
        set_callback(captured.append)
        try:
            w.write("hello\n")
        finally:
            clear_callback()
        assert "hello\n" in captured

    def test_falls_through_to_orig_when_no_callback(self):
        w, buf = _make_writer()
        clear_callback()
        w.write("fallthrough\n")
        assert buf.getvalue() == "fallthrough\n"

    def test_does_not_write_orig_when_callback_is_set(self):
        """When a callback is active, the original stream must stay empty."""
        w, buf = _make_writer()
        set_callback(lambda _: None)
        try:
            w.write("should-not-reach-buf\n")
        finally:
            clear_callback()
        assert buf.getvalue() == ""

    def test_empty_string_not_forwarded_to_callback(self):
        """Empty text should not trigger the callback (empty string)."""
        w, _buf = _make_writer()
        captured: list[str] = []
        set_callback(captured.append)
        try:
            w.write("")
        finally:
            clear_callback()
        assert captured == []

    def test_write_returns_byte_count(self):
        w, _buf = _make_writer()
        result = w.write("abc")
        assert result == 3

    def test_set_callback_overwrites_previous(self):
        w, _buf = _make_writer()
        first: list[str] = []
        second: list[str] = []
        set_callback(first.append)
        set_callback(second.append)   # overwrite
        try:
            w.write("only-second\n")
        finally:
            clear_callback()
        assert first == []
        assert any("only-second" in s for s in second)

    def test_clear_callback_stops_routing(self):
        w, buf = _make_writer()
        captured: list[str] = []
        set_callback(captured.append)
        w.write("before\n")
        clear_callback()
        w.write("after\n")
        assert any("before" in s for s in captured)
        assert not any("after" in s for s in captured)
        assert "after\n" in buf.getvalue()


# ── _Writer.write — output cleaning ───────────────────────────────────────────

class TestOutputCleaning:
    def test_ansi_colour_codes_stripped(self):
        w, _buf = _make_writer()
        captured: list[str] = []
        set_callback(captured.append)
        try:
            w.write("\x1b[31mred text\x1b[0m\n")
        finally:
            clear_callback()
        result = "".join(captured)
        assert "\x1b" not in result
        assert "red text" in result

    def test_ansi_bold_stripped(self):
        w, _buf = _make_writer()
        captured: list[str] = []
        set_callback(captured.append)
        try:
            w.write("\x1b[1mbold\x1b[0m")
        finally:
            clear_callback()
        result = "".join(captured)
        assert "\x1b" not in result
        assert "bold" in result

    def test_bare_cr_stripped(self):
        """A bare \\r (not followed by \\n) is removed."""
        w, _buf = _make_writer()
        captured: list[str] = []
        set_callback(captured.append)
        try:
            w.write("progress\r100%\n")
        finally:
            clear_callback()
        result = "".join(captured)
        assert "\r" not in result

    def test_crlf_preserved(self):
        """\\r\\n (Windows line ending) must NOT be stripped."""
        w, _buf = _make_writer()
        captured: list[str] = []
        set_callback(captured.append)
        try:
            w.write("line\r\n")
        finally:
            clear_callback()
        result = "".join(captured)
        assert "\r\n" in result


# ── isatty ────────────────────────────────────────────────────────────────────

class TestIsatty:
    def test_always_returns_false(self):
        w, _buf = _make_writer()
        assert w.isatty() is False

    def test_tells_rich_to_skip_ansi(self):
        """Rich checks .isatty() to decide whether to emit ANSI codes."""
        w, _buf = _make_writer()
        # Must be exactly False so `if not sys.stdout.isatty()` works
        assert w.isatty() is False


# ── flush ─────────────────────────────────────────────────────────────────────

class TestFlush:
    def test_flush_with_no_callback_calls_orig(self):
        buf = io.StringIO()
        w = _Writer(buf)
        clear_callback()
        w.flush()   # should not raise

    def test_flush_with_callback_does_not_raise(self):
        w, _buf = _make_writer()
        set_callback(lambda _: None)
        try:
            w.flush()   # should be a no-op when callback is active
        finally:
            clear_callback()


# ── Thread isolation ──────────────────────────────────────────────────────────

class TestThreadIsolation:
    def test_callbacks_are_per_thread(self):
        w, _buf = _make_writer()
        main_captured:   list[str] = []
        thread_captured: list[str] = []
        thread_ready = threading.Event()
        thread_done  = threading.Event()

        def thread_fn():
            set_callback(thread_captured.append)
            thread_ready.set()
            time.sleep(0.05)
            w.write("from-thread\n")
            clear_callback()
            thread_done.set()

        set_callback(main_captured.append)
        t = threading.Thread(target=thread_fn, daemon=True)
        t.start()

        thread_ready.wait(timeout=1)
        w.write("from-main\n")

        thread_done.wait(timeout=2)
        clear_callback()

        assert any("from-main" in s for s in main_captured)
        assert any("from-thread" in s for s in thread_captured)
        assert not any("from-thread" in s for s in main_captured)
        assert not any("from-main" in s for s in thread_captured)

    def test_new_thread_has_no_callback_by_default(self):
        has_cb: list[bool] = []

        def thread_fn():
            cb = getattr(_mod._local, "callback", None)
            has_cb.append(cb is not None)

        t = threading.Thread(target=thread_fn, daemon=True)
        t.start()
        t.join(timeout=2)
        assert has_cb == [False]
