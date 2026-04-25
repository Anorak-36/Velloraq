# Contributing To Velloraq

Thanks for helping make Velloraq safer and more useful. Contributions should preserve the project as an open-source, defensive, self-hostable DevSecOps tool.

## Setup

Linux/macOS:

```bash
git clone https://github.com/velloraq/velloraq.git
cd velloraq
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[all,dev]"
cp .env.local.example .env
python -m unittest discover -s tests
```

Windows PowerShell:

```powershell
git clone https://github.com/velloraq/velloraq.git
Set-Location velloraq
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[all,dev]"
Copy-Item .env.local.example .env
python -m unittest discover -s tests
```

## Branch Workflow

1. Create a focused branch from `main`.
2. Keep compatibility shims unless the pull request includes migration documentation.
3. Make small, reviewable commits.
4. Update tests and docs with behavior changes.
5. Open a pull request with a clear summary, security impact, and test output.

## Code Style

- Prefer `pathlib` for filesystem paths.
- Keep functions small and named after behavior.
- Use docstrings for non-trivial modules, classes, and functions.
- Comments should explain security or design reasoning.
- Do not add proprietary, paid-only, closed-source, GPL, or AGPL dependencies without explicit maintainer approval.
- Do not commit `.env`, credentials, certificates, reports, logs, or local databases.

## Tests

Run:

```bash
python -m unittest discover -s tests
python -m compileall app serverless_security_scanner velloraq tests examples
```

Add or update tests when changing:

- Auth, registration, JWT, cookies, or CORS.
- Ownership checks for scans or reports.
- Report rendering or escaping.
- CLI command behavior.
- Docker or environment parsing.
- Cloud provider parsing or rule behavior.

## Pull Request Checklist

- The preferred name `Velloraq` is used in docs and commands.
- `velloraq` is the preferred CLI command.
- `slssec` and legacy import compatibility still work when touched.
- Docker still runs from the repository root with `docker compose up --build`.
- New environment variables are documented in README and `.env*.example`.
- No secrets or generated reports are committed.
- Security-sensitive behavior has tests.
