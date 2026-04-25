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

python -c "import sqlalchemy" >nul 2>nul
if errorlevel 1 (
    echo Missing worker dependencies. Run: python -m pip install -e ".[saas]"
    exit /b 1
)

python -m velloraq.backend.workers.scan_worker
exit /b %ERRORLEVEL%
