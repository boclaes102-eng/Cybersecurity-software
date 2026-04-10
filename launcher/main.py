"""
CyberSuite Pro — entry point.

Run with:
    python -m launcher.main          (from the repo root)
    python launcher/main.py          (from the repo root)
    CyberSuite.exe                   (PyInstaller bundle)
"""
from __future__ import annotations

import sys


def main() -> None:
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
