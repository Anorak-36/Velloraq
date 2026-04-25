# Installation

Use the repository root as the working directory. The public repository name and root folder should be `velloraq`.

## Docker

Linux/macOS:

```bash
git clone https://github.com/velloraq/velloraq.git
cd velloraq
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
nano .env
docker compose up --build
```

Windows CMD:

```cmd
git clone https://github.com/velloraq/velloraq.git
cd velloraq
copy .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
notepad .env
docker compose up --build
```

Windows PowerShell:

```powershell
git clone https://github.com/velloraq/velloraq.git
Set-Location velloraq
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
notepad .env
docker compose up --build
```

## Manual Python

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[all]"
python -m velloraq.backend.database.init_db
python -m uvicorn velloraq.backend.api_server:app --host 127.0.0.1 --port 8000
```

Worker:

```bash
python -m velloraq.backend.workers.scan_worker
```

## Compatibility Names

Use `velloraq` for new commands and imports. `slssec`, `app.*`, and `serverless_security_scanner.*` remain available only as compatibility aliases.

## Windows CMD Helpers

From the repository root:

```cmd
scripts\run_api.cmd
scripts\run_worker.cmd
scripts\test.cmd
```

The scripts activate `.venv` when present and print a dependency hint if Python or required packages are missing.
