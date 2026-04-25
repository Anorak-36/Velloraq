@echo off
setlocal

if exist ".venv\Scripts\activate.bat" (
    call ".venv\Scripts\activate.bat"
)

where python >nul 2>nul
if errorlevel 1 (
    echo Python was not found on PATH. Install Python 3.10+ or activate a virtual environment.
    exit /b 1
)

python -c "import pytest" >nul 2>nul
if errorlevel 1 (
    echo pytest is not installed. Run: python -m pip install -e ".[all,dev]"
    exit /b 1
)

python -m pytest -q
exit /b %ERRORLEVEL%
