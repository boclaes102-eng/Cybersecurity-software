"""
Smoke / integration tests — no GUI, no tool execution.

Verifies that:
  - All launcher modules import cleanly
  - Each tool directory has the expected source layout
  - The writer → runner pipeline works end-to-end: stdout written inside a
    runner thread reaches the output callback without ANSI noise
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

from launcher.utils.paths import NIDS_DIR, PAS_DIR, SMA_DIR


# ── Tool directory structure ───────────────────────────────────────────────────

EXPECTED_FILES = {
    "NIDS": (NIDS_DIR, ["main.py"]),
    "PAS":  (PAS_DIR,  ["cli.py"]),   # PAS uses cli.py (Click-based), not main.py
    "SMA":  (SMA_DIR,  ["main.py"]),
}


@pytest.mark.parametrize("tool,info", EXPECTED_FILES.items())
def test_tool_main_py_exists(tool, info):
    directory, files = info
    for fname in files:
        p = directory / fname
        assert p.is_file(), f"[{tool}] Expected file missing: {p}"


@pytest.mark.parametrize("tool,info", EXPECTED_FILES.items())
def test_tool_directory_is_not_empty(tool, info):
    directory, _ = info
    contents = list(directory.iterdir())
    assert contents, f"[{tool}] Directory appears empty: {directory}"


# ── Launcher module imports ────────────────────────────────────────────────────

def test_writer_importable():
    import launcher.utils.writer  # noqa: F401

def test_paths_importable():
    import launcher.utils.paths  # noqa: F401

def test_runner_importable():
    import launcher.utils.runner  # noqa: F401

def test_nids_page_importable():
    import launcher.pages.nids_page  # noqa: F401

def test_pas_page_importable():
    import launcher.pages.pas_page  # noqa: F401

def test_sma_page_importable():
    import launcher.pages.sma_page  # noqa: F401

def test_app_importable():
    import launcher.app  # noqa: F401


# ── End-to-end: writer + runner pipeline ──────────────────────────────────────

def test_writer_callback_installed_in_runner_thread():
    """
    Pipeline test: ToolRunner must call set_callback(output_cb) in the worker
    thread so any writes via the writer module reach the caller's list.
    We verify this by reading _local from within the work function, avoiding
    any conflict with pytest's own stdout capture.
    """
    import launcher.utils.writer as w_mod
    from launcher.utils.runner import ToolRunner

    had_cb: list[bool] = []
    captured: list[str] = []
    done = threading.Event()

    def work():
        # Verify the callback is registered in this thread
        cb = getattr(w_mod._local, "callback", None)
        had_cb.append(cb is not None)
        # Send a message through it (simulates what _Writer.write does)
        if cb:
            cb("pipeline-ok\n")

    r = ToolRunner()
    r.run(work, output_cb=captured.append, done_cb=lambda _: done.set())
    done.wait(timeout=3)

    assert had_cb == [True], "runner did not install output_cb in the worker thread"
    assert any("pipeline-ok" in s for s in captured)


def test_multiple_tools_run_sequentially():
    """After one tool finishes, a second can be started."""
    from launcher.utils.runner import ToolRunner

    results: list[int] = []
    done1 = threading.Event()
    done2 = threading.Event()

    r = ToolRunner()
    r.run(lambda: 1, done_cb=lambda c: (results.append(c), done1.set()))
    done1.wait(timeout=3)
    import time; time.sleep(0.05)

    r.run(lambda: 2, done_cb=lambda c: (results.append(c), done2.set()))
    done2.wait(timeout=3)

    assert results == [1, 2]


def test_runner_rejects_concurrent_start():
    """A second run() while busy must return False, not start a second thread."""
    from launcher.utils.runner import ToolRunner

    done = threading.Event()
    r = ToolRunner()
    r.run(lambda: done.wait(), tool_name="first")

    second = r.run(lambda: None, tool_name="second")
    assert second is False

    done.set()


# ── PyInstaller hook file ──────────────────────────────────────────────────────

def test_pyi_hook_exists():
    hook = Path(__file__).parent.parent / "launcher" / "_pyi_hook.py"
    assert hook.is_file(), f"PyInstaller hook missing: {hook}"

def test_pyi_hook_contains_freeze_support():
    hook = Path(__file__).parent.parent / "launcher" / "_pyi_hook.py"
    content = hook.read_text()
    assert "freeze_support" in content
