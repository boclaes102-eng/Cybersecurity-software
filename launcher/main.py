"""
CyberSuite Pro — entry point.

Run with:
    python -m launcher.main          (from the repo root)
    python launcher/main.py          (from the repo root)
    CyberSuite.exe                   (PyInstaller bundle)
"""
from __future__ import annotations

import sys


def _ensure_admin() -> None:
    """On Windows: re-launch with UAC elevation if not already admin."""
    try:
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin():
            return
    except AttributeError:
        return  # not Windows

    import os
    import ctypes

    if getattr(sys, "frozen", False):
        # Running as a PyInstaller .exe
        exe    = sys.executable
        params = " ".join(sys.argv[1:])
    else:
        # Running as a Python script / module
        exe    = sys.executable
        params = " ".join(["-m", "launcher"] + sys.argv[1:])

    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", exe, params, os.getcwd(), 1
    )
    sys.exit(0)


def main() -> None:
    _ensure_admin()

    # 1. Install thread-aware stdout writer BEFORE any tool modules are imported.
    #    This ensures Rich Console objects pick up our interceptor from the start.
    from launcher.utils.writer import install as install_writer
    install_writer()

    # 2. Ensure the three tool directories are on sys.path so their packages
    #    (scapy, pas, analyzer, …) can be found when loaded lazily.
    from launcher.utils.paths import add_tools_to_path
    add_tools_to_path()

    # 3. Launch the GUI.
    try:
        import customtkinter  # noqa: F401
    except ImportError:
        print(
            "customtkinter is not installed.\n"
            "Run:  pip install customtkinter\n",
            file=sys.__stderr__,
        )
        sys.exit(1)

    from launcher.app import App

    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
