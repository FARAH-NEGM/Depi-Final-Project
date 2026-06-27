@echo off
REM Convenience launcher for the Cyber Control Tower backend + frontend on Windows.
REM Usage: double-click this file, or run "run.bat" from Command Prompt.
REM Then open http://127.0.0.1:5000 in your browser.

cd /d "%~dp0backend"

if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

call venv\Scripts\activate.bat

echo Installing dependencies...
pip install -q -r requirements.txt

echo.
echo Starting Cyber Control Tower...
echo Open http://127.0.0.1:5000 in your browser once it says "Running on..."
echo.
python app.py

pause
