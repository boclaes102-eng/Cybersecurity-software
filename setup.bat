@echo off
REM CyberSuite — one-time setup (run once on a new machine)
REM Requires Python 3.11+ to be installed and on PATH.

echo ============================================================
echo  CyberSuite Pro — Setup
echo ============================================================
echo.

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not on PATH.
    echo Download from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Creating virtual environment ...
python -m venv .venv

echo Activating venv ...
call .venv\Scripts\activate.bat

echo Installing dependencies ...
pip install --upgrade pip
pip install -r requirements_launcher.txt

echo.
echo ============================================================
echo  Setup complete!
echo  Run the app with:   run.bat
echo  Build the .exe with: python build.py
echo ============================================================
pause
