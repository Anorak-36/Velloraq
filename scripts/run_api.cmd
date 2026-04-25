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

if "%VELLORAQ_HOST%"=="" (
    if "%SLSSEC_HOST%"=="" (
        set "VELLORAQ_HOST=127.0.0.1"
    ) else (
        set "VELLORAQ_HOST=%SLSSEC_HOST%"
    )
)

if "%VELLORAQ_PORT%"=="" (
    if "%SLSSEC_PORT%"=="" (
        set "VELLORAQ_PORT=8000"
    ) else (
        set "VELLORAQ_PORT=%SLSSEC_PORT%"
    )
)

python -c "import uvicorn" >nul 2>nul
if errorlevel 1 (
    echo Missing API dependencies. Run: python -m pip install -e ".[saas]"
    exit /b 1
)

python -m velloraq.backend.database.init_db
if errorlevel 1 exit /b %ERRORLEVEL%

python -m uvicorn velloraq.backend.api_server:app --host "%VELLORAQ_HOST%" --port "%VELLORAQ_PORT%"
exit /b %ERRORLEVEL%
