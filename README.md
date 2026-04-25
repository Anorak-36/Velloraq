# Velloraq

Velloraq is an open-source, self-hostable DevSecOps platform for defensive serverless and cloud-function security scanning. It includes a Python CLI scanner, a FastAPI backend, PostgreSQL persistence, a web dashboard, background scan workers, authenticated multi-user scan management, and JSON/HTML/SIEM report exports.

The preferred CLI command is `velloraq`. The former `slssec` command remains as a documented compatibility alias for existing users.

## 1. What Velloraq Is

Velloraq helps authorized teams inspect serverless and adjacent cloud assets for common security weaknesses without modifying cloud resources. It can run as a local CLI scanner, a self-hosted SaaS-style dashboard, a CI/CD gate, or an internal security service.

Velloraq is defensive software. Use it only on systems you own, administer, or have explicit permission to audit.

## 2. Main Features

- CLI scans for source code, dependencies, AWS, Azure, and GCP targets.
- FastAPI backend with authenticated scan creation and history.
- PostgreSQL storage for users, projects, scans, and reports.
- Background worker for asynchronous scan execution.
- HTML, JSON, and SIEM JSONL exports.
- Dashboard login, scan launch, history, findings, report preview, report download, and JSON view.
- Admin bootstrap through environment variables.
- Open registration control for local development versus production.
- Backward-compatible `slssec` console command and `serverless_security_scanner` import shim.
- Docker Compose self-hosting with `velloraq-api`, `velloraq-worker`, and `velloraq-db`.
- No proprietary, paid-only, closed-source, trial-only, GPL, or AGPL runtime dependencies.

## 3. Architecture Overview

```text
velloraq/
  backend/       FastAPI routes, auth, database, models, schemas, services, workers
  cli/           command-line entrypoint
  core/          shared CLI configuration parsing
  frontend/      static dashboard assets served by FastAPI
  integrations/  read-only AWS, Azure, GCP, source, dependency, and NVD collectors
  plugins/       local plugin loader
  reports/       HTML, JSON, SIEM, and local report helpers
  rules/         built-in security rules
  scanner/       provider-agnostic scan engine and scan domain models
app/             minimal compatibility alias for older SaaS imports
serverless_security_scanner/
                 minimal compatibility alias for the former package name
docker/          canonical Dockerfiles
docs/            detailed operator and contributor documentation
scripts/         local API and worker helpers
tests/           CLI, rules, API, report, auth, and config tests
```

Runtime flow:

1. A user creates a scan from the dashboard or CLI.
2. The API validates input, enforces ownership, and stores a queued scan.
3. The worker claims queued scans and runs the shared scanner engine.
4. Integrations collect read-only inventory and rules produce findings.
5. Results are persisted as JSON, HTML, and SIEM JSONL.
6. The dashboard reads JSON findings and previews HTML reports in a sandboxed iframe.

Frontend deployment model:

- The dashboard is static HTML, CSS, and JavaScript under `velloraq/frontend/`.
- `velloraq-api` serves both the REST API and the dashboard.
- There is no frontend build step in v0.1.0-alpha.
- A separate `velloraq-frontend` container is not required unless the architecture changes in a later release.

Compatibility folder policy:

- `velloraq/` is the canonical source package. Add new code there.
- `app/` is a FastAPI/Docker compatibility shim for older ASGI imports such as `app.main:app`.
- `serverless_security_scanner/` is a legacy import and module-execution compatibility shim.
- Each compatibility folder includes its own README explaining its purpose.

## 4. Supported Platforms

- Linux with Python 3.10+ and Docker Engine or Docker Desktop.
- macOS with Python 3.10+ and Docker Desktop.
- Windows 10/11 with Python 3.10+ and Docker Desktop.
- Windows Server 2019/2022+ with Python 3.10+ and a supported Docker runtime.
- PostgreSQL 14+ for the SaaS backend.

## 5. Requirements

Recommended Docker deployment:

- Git.
- Docker Compose v2.
- Internet access to download open-source Python and container dependencies.
- A local `.env` copied from `.env.example`, `.env.local.example`, or `.env.production.example`.

Manual Python deployment:

- Python 3.10 or newer.
- PostgreSQL 14 or newer.
- A compiler toolchain only if your platform cannot install prebuilt wheels for dependencies such as `bcrypt`.

Optional cloud tooling:

- AWS CLI for profile-based AWS scans.
- Azure CLI or service principal environment variables for Azure scans.
- Google Cloud SDK or ADC JSON credentials for GCP scans.

## 6. Quick Start With Docker

Linux/macOS:

```bash
git clone https://github.com/velloraq/velloraq.git
cd velloraq
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Open `.env`, replace `VELLORAQ_JWT_SECRET_KEY`, `POSTGRES_PASSWORD`, and `VELLORAQ_FIRST_ADMIN_PASSWORD`, then run:

```bash
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

Open the dashboard:

```text
http://localhost:8000
```

Default first-admin bootstrap comes from `.env`:

```env
VELLORAQ_FIRST_ADMIN_EMAIL=admin@example.local
VELLORAQ_FIRST_ADMIN_PASSWORD=change-me-admin-password-min-12
```

Replace those values before starting a shared instance.

## 7. Linux Installation

Docker path:

```bash
git clone https://github.com/velloraq/velloraq.git
cd velloraq
cp .env.local.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
nano .env
docker compose up --build
```

CLI-only path:

```bash
git clone https://github.com/velloraq/velloraq.git
cd velloraq
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[all]"
velloraq --help
velloraq scan --provider source --source-path examples/vulnerable_lambda.py --format all --output reports
```

## 8. macOS Installation

Install Python if needed:

```bash
brew install python
```

Docker path:

```bash
git clone https://github.com/velloraq/velloraq.git
cd velloraq
cp .env.local.example .env
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
nano .env
docker compose up --build
```

CLI-only path:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[all]"
velloraq scan --provider source --source-path examples/vulnerable_lambda.py --format json --output reports
```

## 9. Windows CMD Installation

```cmd
git clone https://github.com/velloraq/velloraq.git
cd velloraq
py -3 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -e ".[all]"
copy .env.local.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
notepad .env
docker compose up --build
```

CLI-only scan:

```cmd
velloraq scan --provider source --source-path examples\vulnerable_lambda.py --format all --output reports
```

Helper scripts:

```cmd
scripts\run_api.cmd
scripts\run_worker.cmd
scripts\test.cmd
```

## 10. Windows PowerShell Installation

```powershell
git clone https://github.com/velloraq/velloraq.git
Set-Location velloraq
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[all]"
Copy-Item .env.local.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
notepad .env
docker compose up --build
```

If PowerShell blocks virtualenv activation:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.\.venv\Scripts\Activate.ps1
```

CLI-only scan:

```powershell
velloraq scan --provider source --source-path examples\vulnerable_lambda.py --format all --output reports
```

## 11. Windows Server Notes

Install prerequisites from an elevated PowerShell session:

```powershell
winget install Python.Python.3.12
winget install Git.Git
```

Install a Docker runtime supported by your Windows Server baseline. Then:

```powershell
git clone https://github.com/velloraq/velloraq.git
Set-Location velloraq
Copy-Item .env.production.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
notepad .env
docker compose up -d --build
docker compose ps
docker compose logs --tail 80 velloraq-api velloraq-worker velloraq-db
```

Windows Server production checklist:

- Put Velloraq behind IIS, Nginx, Caddy, Traefik, or another TLS reverse proxy.
- Set `VELLORAQ_ALLOWED_ORIGINS` to the exact HTTPS origin users open.
- Keep `VELLORAQ_OPEN_REGISTRATION=false` after creating intended users.
- Store `.env` with administrator-only file permissions.
- Back up PostgreSQL using your normal server backup tooling.

## 12. Manual Python Installation Without Docker

Linux/macOS:

```bash
git clone https://github.com/velloraq/velloraq.git
cd velloraq
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[all]"
cp .env.local.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
nano .env
```

Windows PowerShell:

```powershell
git clone https://github.com/velloraq/velloraq.git
Set-Location velloraq
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[all]"
Copy-Item .env.local.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
notepad .env
```

Set a local PostgreSQL URL in `.env`:

```env
VELLORAQ_DATABASE_URL=postgresql+pg8000://velloraq:CHANGE_ME@localhost:5432/velloraq
```

Initialize the database and run services:

```bash
python -m velloraq.backend.database.init_db
python -m velloraq.backend.auth.create_admin --email admin@example.local
python -m uvicorn velloraq.backend.api_server:app --host 127.0.0.1 --port 8000
```

Start a second terminal for the worker:

```bash
python -m velloraq.backend.workers.scan_worker
```

## 13. Environment Variable Configuration

Use these files as starting points:

- `.env.example`: local Docker development.
- `.env.local.example`: local workstation profile.
- `.env.production.example`: production-style profile with safer defaults.

Linux/macOS:

```bash
cp .env.production.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
nano .env
```

Windows CMD:

```cmd
copy .env.production.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
notepad .env
```

Windows PowerShell:

```powershell
Copy-Item .env.production.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
notepad .env
```

Production must replace:

```env
VELLORAQ_APP_ENV=production
VELLORAQ_OPEN_REGISTRATION=false
VELLORAQ_JWT_SECRET_KEY=change-this-to-a-long-random-secret
POSTGRES_PASSWORD=change-this-to-a-long-random-postgres-password
VELLORAQ_FIRST_ADMIN_PASSWORD=change-this-to-a-long-random-admin-password
```

The application rejects placeholder-looking JWT secrets in production.

## 14. Full Environment Variable Table

| Variable | Required | Example | Purpose |
| --- | --- | --- | --- |
| `VELLORAQ_APP_NAME` | No | `Velloraq` | API and dashboard display name. |
| `VELLORAQ_APP_ENV` | No | `development` or `production` | Enables production safety checks. |
| `VELLORAQ_ALLOWED_ORIGINS` | Yes for browser use | `https://velloraq.example.com` | Comma-separated CORS origins. Do not use `*` in production. |
| `POSTGRES_USER` | Docker | `velloraq` | PostgreSQL container user. |
| `POSTGRES_PASSWORD` | Docker | random password | PostgreSQL container password. |
| `POSTGRES_DB` | Docker | `velloraq` | PostgreSQL database name. |
| `VELLORAQ_DATABASE_URL` | SaaS | `postgresql+pg8000://velloraq:...@velloraq-db:5432/velloraq` | SQLAlchemy database URL. |
| `VELLORAQ_JWT_SECRET_KEY` | SaaS | generated 48-byte token URL-safe string | JWT signing key. Must be unique and secret. |
| `VELLORAQ_JWT_ALGORITHM` | No | `HS256` | JWT signing algorithm. |
| `VELLORAQ_ACCESS_TOKEN_EXPIRE_MINUTES` | No | `60` | Token and session cookie lifetime. |
| `VELLORAQ_PASSWORD_BCRYPT_ROUNDS` | No | `12` | Password hash cost. |
| `VELLORAQ_RATE_LIMIT_REQUESTS` | No | `120` | Requests allowed per client per window. |
| `VELLORAQ_RATE_LIMIT_WINDOW_SECONDS` | No | `60` | Rate-limit rolling window. |
| `VELLORAQ_FIRST_ADMIN_EMAIL` | Optional | `admin@example.com` | Bootstrap admin email created at startup. |
| `VELLORAQ_FIRST_ADMIN_PASSWORD` | Optional | random password | Bootstrap admin password. |
| `VELLORAQ_OPEN_REGISTRATION` | No | `false` in production | Allows public self-registration when `true`. |
| `VELLORAQ_ALLOWED_SOURCE_ROOTS` | SaaS source scans | `/workspace,/app/examples` | Comma-separated roots allowed for local source scans. |
| `VELLORAQ_REPORTS_DIR` | No | `/app/reports` | Runtime report directory. |
| `VELLORAQ_SCAN_POLL_INTERVAL_SECONDS` | No | `5` | Worker idle polling interval. |
| `VELLORAQ_SCAN_WORKER_BATCH_SIZE` | No | `1` | Queued scans claimed per worker loop. |
| `VELLORAQ_ENABLE_WEBHOOKS` | No | `false` | Enables completion webhooks. |
| `VELLORAQ_WEBHOOK_TIMEOUT_SECONDS` | No | `10` | Webhook POST timeout. |
| `AWS_PROFILE` | Optional | `velloraq-readonly` | AWS SDK profile. |
| `AZURE_CLIENT_ID` | Optional | UUID | Azure service principal client ID. |
| `AZURE_TENANT_ID` | Optional | UUID | Azure tenant ID. |
| `AZURE_CLIENT_SECRET` | Optional | runtime secret | Azure service principal secret. Do not commit. |
| `GOOGLE_APPLICATION_CREDENTIALS` | Optional | `/run/secrets/gcp-readonly.json` | GCP ADC JSON path. Do not commit the JSON file. |
| `NVD_API_KEY` | Optional | runtime secret | Optional NVD API key for dependency lookups. |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | Optional | proxy URLs | Network proxy configuration. |

Legacy `SLSSEC_*` variables are read as compatibility aliases only. Prefer `VELLORAQ_*` for all new deployments.

## 15. Local Development Setup

Linux/macOS:

```bash
cp .env.local.example .env
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[all,dev]"
docker compose up -d velloraq-db
python -m velloraq.backend.database.init_db
python -m uvicorn velloraq.backend.api_server:app --reload --host 127.0.0.1 --port 8000
```

Second terminal:

```bash
. .venv/bin/activate
python -m velloraq.backend.workers.scan_worker
```

Windows CMD:

```cmd
copy .env.local.example .env
py -3 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -e ".[all,dev]"
docker compose up -d velloraq-db
scripts\run_api.cmd
```

Second CMD terminal:

```cmd
.venv\Scripts\activate.bat
scripts\run_worker.cmd
```

Windows PowerShell:

```powershell
Copy-Item .env.local.example .env
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[all,dev]"
docker compose up -d velloraq-db
python -m velloraq.backend.database.init_db
python -m uvicorn velloraq.backend.api_server:app --reload --host 127.0.0.1 --port 8000
```

Second PowerShell terminal:

```powershell
.\.venv\Scripts\Activate.ps1
python -m velloraq.backend.workers.scan_worker
```

## 16. Small Business/Internal Network Setup

Use this when the service is reachable only from an internal LAN or VPN.

Linux/macOS:

```bash
cp .env.production.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
nano .env
docker compose up -d --build
docker compose ps
docker compose logs --tail 80 velloraq-api velloraq-worker velloraq-db
```

Set `.env` values:

```env
VELLORAQ_APP_ENV=production
VELLORAQ_ALLOWED_ORIGINS=https://velloraq.internal.example
VELLORAQ_OPEN_REGISTRATION=false
VELLORAQ_ALLOWED_SOURCE_ROOTS=/workspace,/app/examples
```

Operate behind TLS. Do not expose PostgreSQL outside the host or private Docker network.

## 17. Cloud Lab Setup

```bash
cp .env.local.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
nano .env
docker compose up -d --build
```

AWS read-only profile example:

```bash
aws configure --profile velloraq-readonly
velloraq scan --provider aws --aws-profile velloraq-readonly --region us-east-1 --format all --output reports
```

Azure service principal example:

```bash
export AZURE_CLIENT_ID="00000000-0000-0000-0000-000000000000"
export AZURE_TENANT_ID="00000000-0000-0000-0000-000000000000"
read -r -s AZURE_CLIENT_SECRET
export AZURE_CLIENT_SECRET
velloraq scan --provider azure --azure-subscription 00000000-0000-0000-0000-000000000000 --format html --output reports
```

GCP ADC example:

```bash
export GOOGLE_APPLICATION_CREDENTIALS="/secure/path/velloraq-readonly.json"
velloraq scan --provider gcp --gcp-project my-project --region us-central1 --format all --output reports
```

## 18. CI/CD Setup

GitHub Actions CLI gate:

```yaml
name: Velloraq Security Scan

on:
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install -e ".[all]"
      - run: velloraq scan --provider source --source-path . --format all --output reports --fail-on High
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: velloraq-reports
          path: reports/
```

Local CI command:

```bash
python -m unittest discover -s tests
velloraq scan --provider source --source-path . --format all --output reports --fail-on High
```

## 19. Self-Hosted Production Setup

Linux/macOS server:

```bash
git clone https://github.com/velloraq/velloraq.git
cd velloraq
cp .env.production.example .env
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
nano .env
docker compose config
docker compose up -d --build
docker compose ps
```

Windows PowerShell server:

```powershell
git clone https://github.com/velloraq/velloraq.git
Set-Location velloraq
Copy-Item .env.production.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
notepad .env
docker compose config
docker compose up -d --build
docker compose ps
```

Minimum production `.env`:

```env
VELLORAQ_APP_ENV=production
VELLORAQ_ALLOWED_ORIGINS=https://velloraq.example.com
VELLORAQ_OPEN_REGISTRATION=false
VELLORAQ_JWT_SECRET_KEY=<paste-generated-secret>
POSTGRES_PASSWORD=<paste-generated-postgres-password>
VELLORAQ_FIRST_ADMIN_EMAIL=admin@example.com
VELLORAQ_FIRST_ADMIN_PASSWORD=<paste-generated-admin-password>
```

Terminate TLS before the API. The production cookie is marked Secure, so browser login requires HTTPS.

## 20. PostgreSQL Setup

Docker-managed PostgreSQL:

```bash
docker compose up -d velloraq-db
docker compose logs --tail 80 velloraq-db
```

Linux package PostgreSQL example:

```bash
sudo -u postgres createuser velloraq
sudo -u postgres createdb -O velloraq velloraq
sudo -u postgres psql -c "ALTER USER velloraq WITH PASSWORD 'CHANGE_ME_LONG_RANDOM_PASSWORD';"
export VELLORAQ_DATABASE_URL="postgresql+pg8000://velloraq:CHANGE_ME_LONG_RANDOM_PASSWORD@localhost:5432/velloraq"
```

Windows PowerShell with local PostgreSQL tools on `PATH`:

```powershell
createuser -U postgres velloraq
createdb -U postgres -O velloraq velloraq
psql -U postgres -c "ALTER USER velloraq WITH PASSWORD 'CHANGE_ME_LONG_RANDOM_PASSWORD';"
$env:VELLORAQ_DATABASE_URL = "postgresql+pg8000://velloraq:CHANGE_ME_LONG_RANDOM_PASSWORD@localhost:5432/velloraq"
```

## 21. Migrations/Database Initialization

Docker:

```bash
docker compose run --rm velloraq-api python -m velloraq.backend.database.init_db
```

Manual Python:

```bash
python -m velloraq.backend.database.init_db
```

Console script after installation:

```bash
velloraq-migrate
```

The API and worker also run migrations at startup.

## 22. First Admin User Setup

Environment bootstrap:

```env
VELLORAQ_FIRST_ADMIN_EMAIL=admin@example.com
VELLORAQ_FIRST_ADMIN_PASSWORD=<long-random-password>
```

Docker applies that at API startup:

```bash
docker compose up -d --build
docker compose logs --tail 80 velloraq-api
```

Manual command:

```bash
python -m velloraq.backend.auth.create_admin --email admin@example.com
```

Production recommendation:

1. Start once with `VELLORAQ_FIRST_ADMIN_EMAIL` and `VELLORAQ_FIRST_ADMIN_PASSWORD`.
2. Log in and verify the admin account.
3. Remove the bootstrap password from `.env`.
4. Keep `VELLORAQ_OPEN_REGISTRATION=false`.
5. Restart `velloraq-api`.

## 23. Login And Authentication

Dashboard login:

1. Open `http://localhost:8000` for local development or your HTTPS production URL.
2. Enter the admin email and password from `.env`.
3. After login, the dashboard stores a bearer token for API requests and receives an HttpOnly same-origin cookie for protected report iframe loading.

API login:

```bash
curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.local","password":"change-me-admin-password-min-12"}'
```

Windows PowerShell:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8000/auth/login -ContentType "application/json" -Body '{"email":"admin@example.local","password":"change-me-admin-password-min-12"}'
```

## 24. Running A Scan From The Dashboard

1. Log in.
2. In `Launch Scan`, keep provider `source` selected.
3. Set `Source paths` to `examples/vulnerable_lambda.py`.
4. Click `Launch scan`.
5. Click `Refresh` until the scan status changes from `queued` to `succeeded` or `failed`.
6. Click the scan row to load JSON findings.

For AWS/Azure/GCP scans, provide read-only cloud credentials to the API/worker environment before launching cloud provider scans.

## 25. Viewing HTML Reports

1. Select a completed scan.
2. Click `View HTML Report`.
3. The dashboard loads `/scans/<scan-id>/report/html` in a sandboxed iframe.
4. If the report is missing, the dashboard shows `Report not available`.

Direct authenticated URL:

```text
http://localhost:8000/scans/<scan-id>/report/html
```

## 26. Downloading Reports

Dashboard:

1. Select a completed scan.
2. Click `Download HTML Report`.
3. The file downloads as `report_<scan-id>.html`.

API:

```bash
curl -H "Authorization: Bearer <token>" \
  -o report.html \
  http://localhost:8000/scans/<scan-id>/report/download
```

Windows PowerShell:

```powershell
Invoke-WebRequest -Headers @{Authorization="Bearer <token>"} -OutFile report.html -Uri http://localhost:8000/scans/<scan-id>/report/download
```

## 27. Running CLI Scans

Source scan:

```bash
velloraq scan --provider source --source-path examples/vulnerable_lambda.py --format all --output reports
```

Dependency scan:

```bash
velloraq scan --provider source --dependency-manifest examples/requirements-vulnerable.txt --format json --output reports
```

AWS scan:

```bash
velloraq scan --provider aws --aws-profile velloraq-readonly --region us-east-1 --format all --output reports
```

Azure scan:

```bash
velloraq scan --provider azure --azure-subscription 00000000-0000-0000-0000-000000000000 --format html --output reports
```

GCP scan:

```bash
velloraq scan --provider gcp --gcp-project my-project --region us-central1 --format all --output reports
```

Compatibility alias:

```bash
slssec scan --provider source --source-path examples/vulnerable_lambda.py --format json --output reports
```

Python module commands:

```bash
python -m velloraq scan --provider source --source-path examples/vulnerable_lambda.py --format json --format html --output reports
python -m serverless_security_scanner scan --provider source --source-path examples/vulnerable_lambda.py --format json --format html --output reports
```

`python -m serverless_security_scanner` is kept only for migration compatibility. Prefer `python -m velloraq` and `velloraq`.

## 28. Exporting JSON/HTML Reports

CLI all formats:

```bash
velloraq scan --provider source --source-path examples/vulnerable_lambda.py --format json --format html --format siem --output reports
```

Expected files:

```text
reports/latest.json
reports/latest.html
reports/latest.siem.jsonl
```

API JSON export:

```bash
curl -H "Authorization: Bearer <token>" \
  http://localhost:8000/scans/<scan-id>/export/json
```

API HTML export:

```bash
curl -H "Authorization: Bearer <token>" \
  -o report.html \
  http://localhost:8000/scans/<scan-id>/export/html
```

## 29. Running Tests

Linux/macOS:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[all,dev]"
python -m pytest -q
python -m compileall app serverless_security_scanner velloraq tests examples
```

Windows CMD:

```cmd
py -3 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -e ".[all,dev]"
python -m pytest -q
python -m compileall app serverless_security_scanner velloraq tests examples
```

Or use the CMD helper:

```cmd
scripts\test.cmd
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[all,dev]"
python -m pytest -q
python -m compileall app serverless_security_scanner velloraq tests examples
```

Docker syntax check:

```bash
docker compose config
```

Final validation commands:

Windows CMD:

```cmd
cd path\to\velloraq
copy .env.example .env
docker compose up --build
```

Manual CLI test on Windows CMD:

```cmd
python -m venv .venv
.venv\Scripts\activate
pip install -e .
python -m pytest -q
velloraq scan --provider source --source-path examples\vulnerable_lambda.py --format json --format html --output reports
```

Windows PowerShell:

```powershell
cd path\to\velloraq
Copy-Item .env.example .env
docker compose up --build
```

Linux/macOS:

```bash
cd path/to/velloraq
cp .env.example .env
docker compose up --build
```

Manual CLI test on Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
python -m pytest -q
velloraq scan --provider source --source-path examples/vulnerable_lambda.py --format json --format html --output reports
```

## 30. Troubleshooting Common Errors

`Set VELLORAQ_JWT_SECRET_KEY before running in production.`

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Paste the generated value into `.env` as `VELLORAQ_JWT_SECRET_KEY`.

`VELLORAQ_ALLOWED_ORIGINS cannot contain '*' in production.`

```env
VELLORAQ_ALLOWED_ORIGINS=https://velloraq.example.com
```

`Registration is disabled`

```env
VELLORAQ_OPEN_REGISTRATION=true
```

Use that only for local development or a short controlled onboarding window.

`Path is outside allowed source roots`

```env
VELLORAQ_ALLOWED_SOURCE_ROOTS=/workspace,/app/examples
```

Then put source files under one of those directories.

`Report not available`

```bash
docker compose logs --tail 80 velloraq-worker
docker compose logs --tail 80 velloraq-api
```

Confirm the scan status is `succeeded` and the worker is running.

Older Compose releases cannot find `.env`

```bash
cp .env.example .env
docker compose config
```

Windows CMD:

```cmd
copy .env.example .env
docker compose config
```

## 31. Security Recommendations

- Keep `VELLORAQ_APP_ENV=production` for shared deployments.
- Keep `VELLORAQ_OPEN_REGISTRATION=false` in production.
- Generate a unique `VELLORAQ_JWT_SECRET_KEY` per deployment.
- Use HTTPS in production. Secure cookies require HTTPS.
- Set exact `VELLORAQ_ALLOWED_ORIGINS`; do not use wildcard origins.
- Use read-only cloud credentials with least privilege.
- Store `.env` outside public web roots and restrict file permissions.
- Do not commit `.env`, cloud keys, certificates, tokens, database files, logs, or generated reports.
- Put PostgreSQL on a private network.
- Back up PostgreSQL and test restore procedures.
- Review `SECURITY.md` before exposing Velloraq to a team.
- Treat generated reports as sensitive because they may identify resources and misconfigurations.

## 32. Legal Disclaimer

Velloraq is provided for defensive security assessment, compliance support, and authorized internal auditing. You are responsible for obtaining permission before scanning cloud accounts, source code, networks, or systems. The maintainers do not authorize misuse, unauthorized access, or violation of cloud provider terms.

## 33. Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Short version:

```bash
python -m pip install -e ".[all,dev]"
python -m unittest discover -s tests
python -m compileall app serverless_security_scanner velloraq tests examples
```

Contributions must keep Velloraq open source, avoid proprietary lock-in, preserve compatibility aliases unless a migration path exists, and include tests for behavior changes.

## 34. License

Velloraq is licensed under the MIT License. See [LICENSE](LICENSE).

Dependency notices are listed in [NOTICE.md](NOTICE.md). Security policy is documented in [SECURITY.md](SECURITY.md).

## Docker Strategy

Use only the root Compose file:

```bash
docker compose up --build
```

Docker files:

```text
docker/backend.Dockerfile
docker/worker.Dockerfile
```

Services and images:

```text
velloraq-api      image velloraq-api:latest
velloraq-worker   image velloraq-worker:latest
velloraq-db       image postgres:16-alpine
```

Frontend:

```text
velloraq-api serves the static dashboard from velloraq/frontend/.
No velloraq-frontend service or frontend build step is required for v0.1.0-alpha.
```

Do not run Compose from the `docker/` directory.

## Name Availability Note

The project name is **Velloraq**, but this README does not guarantee legal uniqueness. Before public/commercial release, maintainers should check GitHub, PyPI, Docker Hub, domain availability, trademark databases, and search engine results. A formal trademark review is required for legal certainty.

## Legacy Path Mapping

| Old path or name | Current path or name | Status |
| --- | --- | --- |
| `serverless_security_scanner.*` | `velloraq.*` | Compatibility shim only. New imports should use `velloraq`. |
| `app.*` | `velloraq.backend.*` | Compatibility shim only for older ASGI imports. |
| `slssec` | `velloraq` | Compatibility CLI alias. Prefer `velloraq`. |
| root `Dockerfile` | `docker/backend.Dockerfile` | Removed to avoid duplicate Docker strategy. |
| `docker/docker-compose.yml` | root `docker-compose.yml` | Removed. Run Compose from the repository root. |
