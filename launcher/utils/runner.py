"""
Background-thread tool runner with per-thread stdout capture and stop support.
"""
from __future__ import annotations

import ctypes
import threading
from typing import Callable, Optional

from .writer import clear_callback, set_callback


class ToolRunner:
    """
    Runs one tool at a time in a daemon thread.

    The thread-aware writer (writer.py) routes all tool stdout/stderr to
    *output_cb* without touching the GUI thread's output.

    Stop strategy (two layers):
      1. stop_event is set first — tools that accept a stop_event kwarg can
         exit cleanly at a checkpoint without waiting for the exception.
      2. PyThreadState_SetAsyncExc injects KeyboardInterrupt as a fallback for
         tools that don't check the event but do handle KeyboardInterrupt
         (asyncio tasks cancel, Rich Live stops, etc.).
         This works when the thread executes Python bytecode; it may not fire
         immediately if the thread is blocked inside a C extension call (e.g.
         Scapy's low-level sniffer loop).  The event gives such tools a
         cooperative exit path they can check at safe points.
    """

    def __init__(self) -> None:
        self._thread: Optional[threading.Thread] = None
        self.active_tool: str = ""
        self.stop_event: threading.Event = threading.Event()

    # ------------------------------------------------------------------
    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------
    def run(
        self,
        func: Callable,
        args: tuple = (),
        kwargs: Optional[dict] = None,
        output_cb: Optional[Callable[[str], None]] = None,
        done_cb: Optional[Callable[[int], None]] = None,
        tool_name: str = "",
    ) -> bool:
        """
        Start *func* in a background thread.

        Returns False (and does nothing) if a tool is already running.
        *tool_name* is stored in self.active_tool for status display.
        """
        if self.is_running:
            return False
        self.stop_event.clear()
        self.active_tool = tool_name
        self._thread = threading.Thread(
            target=self._body,
            args=(func, args or (), kwargs or {}, output_cb, done_cb),
            daemon=True,
            name=f"ToolRunner-{tool_name}",
        )
        self._thread.start()
        return True

    # ------------------------------------------------------------------
    def stop(self) -> None:
        """
        Signal the running tool to stop.

        Sets stop_event first (cooperative), then injects KeyboardInterrupt
        (pre-emptive fallback) for tools that don't poll the event.
        """
        self.stop_event.set()
        t = self._thread
        if t and t.is_alive() and t.ident:
            ctypes.pythonapi.PyThreadState_SetAsyncExc(
                ctypes.c_ulong(t.ident),
                ctypes.py_object(KeyboardInterrupt),
            )

    # ------------------------------------------------------------------
    def _body(
        self,
        func: Callable,
        args: tuple,
        kwargs: dict,
        output_cb: Optional[Callable[[str], None]],
        done_cb: Optional[Callable[[int], None]],
    ) -> None:
        if output_cb:
            set_callback(output_cb)
        code = 0
        try:
            result = func(*args, **kwargs)
            code = result if isinstance(result, int) else 0
        except (KeyboardInterrupt, SystemExit) as e:
            code = e.code if isinstance(e, SystemExit) and isinstance(e.code, int) else 0
            if output_cb:
                output_cb("\n[Stopped by user]\n")
        except Exception as e:
            if output_cb:
                output_cb(f"\n[ERROR] {type(e).__name__}: {e}\n")
            code = 1
        finally:
            self.active_tool = ""
            clear_callback()
            if done_cb:
                done_cb(code)
