@echo off
REM Launch CyberSuite Pro (development mode — no .exe needed)

if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
)

pythonw -m launcher.main
