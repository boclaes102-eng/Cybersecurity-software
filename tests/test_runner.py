"""
Tests for launcher/utils/runner.py — background-thread tool runner.

Verifies:
  - Initial state: not running, no active_tool
  - run() starts a background thread and returns True
  - run() returns False and is a no-op when a tool is already running
  - active_tool is set during execution and cleared afterwards
  - done_cb is called with the function's return code
  - done_cb receives code=0 when the function returns a non-int
  - output captured via stdout write is forwarded to output_cb
  - Exceptions are caught, reported to output_cb, and done_cb gets code=1
  - SystemExit propagates its exit code to done_cb
  - stop() injects KeyboardInterrupt and "[Stopped by user]" is output
  - is_running returns False promptly after the thread finishes
"""
from __future__ import annotations

import threading
import time

import pytest

from launcher.utils.runner import ToolRunner
from launcher.utils.writer import install as install_writer

# Ensure our writer is installed so stdout.write() in threads is captured
install_writer()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _wait(event: threading.Event, timeout: float = 3.0) -> bool:
    """Assert that *event* fires within *timeout* seconds."""
    ok = event.wait(timeout=timeout)
    assert ok, f"Timed out waiting for event after {timeout}s"
    return ok


# ── Tests ──────────────────────────────────────────────────────────────────────

class TestInitialState:
    def test_not_running(self):
        r = ToolRunner()
        assert r.is_running is False

    def test_active_tool_empty(self):
        r = ToolRunner()
        assert r.active_tool == ""


class TestRunBasics:
    def test_run_returns_true(self):
        r = ToolRunner()
        done = threading.Event()
        result = r.run(lambda: done.wait(), tool_name="t")
        assert result is True
        done.set()

    def test_run_starts_thread(self):
        r = ToolRunner()
        done = threading.Event()
        r.run(lambda: done.wait(), tool_name="t")
        assert r.is_running is True
        done.set()

    def test_run_rejects_second_call_while_running(self):
        r = ToolRunner()
        done = threading.Event()
        r.run(lambda: done.wait(), tool_name="first")
        second = r.run(lambda: None, tool_name="second")
        assert second is False
        done.set()

    def test_active_tool_set_during_run(self):
        r = ToolRunner()
        done = threading.Event()
        r.run(lambda: done.wait(), tool_name="MyTool")
        assert r.active_tool == "MyTool"
        done.set()

    def test_thread_is_daemon(self):
        r = ToolRunner()
        done = threading.Event()
        r.run(lambda: done.wait(), tool_name="t")
        assert r._thread is not None
        assert r._thread.daemon is True
        done.set()


class TestDoneCallback:
    def test_done_cb_called(self):
        r = ToolRunner()
        called = threading.Event()
        r.run(lambda: None, done_cb=lambda _: called.set())
        _wait(called)

    def test_done_cb_receives_int_return_code(self):
        r = ToolRunner()
        codes: list[int] = []
        done = threading.Event()
        r.run(lambda: 42, done_cb=lambda c: (codes.append(c), done.set()))
        _wait(done)
        assert codes == [42]

    def test_done_cb_gets_zero_for_none_return(self):
        r = ToolRunner()
        codes: list[int] = []
        done = threading.Event()
        r.run(lambda: None, done_cb=lambda c: (codes.append(c), done.set()))
        _wait(done)
        assert codes == [0]

    def test_active_tool_cleared_after_done(self):
        r = ToolRunner()
        done = threading.Event()
        r.run(lambda: None, tool_name="X",
              done_cb=lambda _: done.set())
        _wait(done)
        # Give the thread a moment to finish fully
        time.sleep(0.05)
        assert r.active_tool == ""

    def test_not_running_after_done(self):
        r = ToolRunner()
        done = threading.Event()
        r.run(lambda: None, done_cb=lambda _: done.set())
        _wait(done)
        time.sleep(0.05)
        assert r.is_running is False


class TestOutputCapture:
    def test_output_cb_registered_in_worker_thread(self):
        """
        run() must call set_callback(output_cb) inside the worker thread so
        tool writes reach the callback.  We verify by reading _local directly
        from within the work function.
        """
        import launcher.utils.writer as w_mod

        had_cb: list[bool] = []
        done = threading.Event()

        def work():
            cb = getattr(w_mod._local, "callback", None)
            had_cb.append(cb is not None)

        r = ToolRunner()
        r.run(work, output_cb=lambda _: None, done_cb=lambda _: done.set())
        _wait(done)
        assert had_cb == [True], "output_cb was not installed in the worker thread"

    def test_output_cb_receives_data_sent_to_it(self):
        """Data sent directly through the registered callback must arrive."""
        import launcher.utils.writer as w_mod

        captured: list[str] = []
        done = threading.Event()

        def work():
            cb = getattr(w_mod._local, "callback", None)
            if cb:
                cb("hello from tool\n")
                cb("second line\n")

        r = ToolRunner()
        r.run(work, output_cb=captured.append, done_cb=lambda _: done.set())
        _wait(done)
        combined = "".join(captured)
        assert "hello from tool" in combined
        assert "second line" in combined

    def test_output_cb_cleared_after_work(self):
        """After work completes, the thread-local callback must be cleared."""
        import launcher.utils.writer as w_mod

        leftover: list[bool] = []
        after_done = threading.Event()

        def done_cb(_):
            leftover.append(getattr(w_mod._local, "callback", None) is not None)
            after_done.set()

        r = ToolRunner()
        r.run(lambda: None, output_cb=lambda _: None, done_cb=done_cb)
        _wait(after_done)
        assert leftover == [False]


class TestErrorHandling:
    def test_exception_reported_to_output_cb(self):
        msgs: list[str] = []
        done = threading.Event()

        def bad():
            raise ValueError("something went wrong")

        r = ToolRunner()
        r.run(bad, output_cb=msgs.append,
              done_cb=lambda _: done.set())
        _wait(done)
        combined = "".join(msgs)
        assert "ValueError" in combined
        assert "something went wrong" in combined

    def test_exception_sets_exit_code_1(self):
        codes: list[int] = []
        done = threading.Event()

        r = ToolRunner()
        r.run(lambda: 1 / 0, output_cb=lambda _: None,
              done_cb=lambda c: (codes.append(c), done.set()))
        _wait(done)
        assert codes == [1]

    def test_system_exit_code_propagated(self):
        codes: list[int] = []
        done = threading.Event()

        def exits():
            raise SystemExit(3)

        r = ToolRunner()
        r.run(exits, output_cb=lambda _: None,
              done_cb=lambda c: (codes.append(c), done.set()))
        _wait(done)
        assert codes == [3]

    def test_keyboard_interrupt_shows_stopped_message(self):
        msgs: list[str] = []
        done = threading.Event()

        def raises_ki():
            raise KeyboardInterrupt

        r = ToolRunner()
        r.run(raises_ki, output_cb=msgs.append,
              done_cb=lambda _: done.set())
        _wait(done)
        assert any("Stopped" in m for m in msgs)


class TestStop:
    def test_stop_terminates_running_tool(self):
        msgs: list[str] = []
        done = threading.Event()

        def long_running():
            # Use very short sleeps so PyThreadState_SetAsyncExc is delivered quickly
            while True:
                time.sleep(0.01)

        r = ToolRunner()
        r.run(long_running, output_cb=msgs.append,
              done_cb=lambda _: done.set())

        # Wait for thread to be well inside the loop, then stop it
        time.sleep(0.1)
        r.stop()

        _wait(done, timeout=5)
        assert any("Stopped" in m for m in msgs)
        assert r.is_running is False

    def test_stop_when_not_running_is_safe(self):
        """stop() on an idle runner must not raise."""
        r = ToolRunner()
        r.stop()  # should be a no-op

    def test_can_run_again_after_stop(self):
        done1 = threading.Event()
        done2 = threading.Event()

        def long_running():
            while True:
                time.sleep(0.01)

        r = ToolRunner()
        r.run(long_running, output_cb=lambda _: None,
              done_cb=lambda _: done1.set())

        time.sleep(0.1)
        r.stop()
        _wait(done1, timeout=5)
        time.sleep(0.05)  # ensure thread fully exits

        # Should accept a new job now
        result = r.run(lambda: None,
                       done_cb=lambda _: done2.set())
        assert result is True
        _wait(done2)
