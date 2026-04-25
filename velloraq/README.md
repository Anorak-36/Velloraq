# Canonical Source Package

`velloraq/` is the canonical Python package for Velloraq.

Add new product code here:

- `velloraq/backend/` for the FastAPI SaaS backend, auth, database, services, and workers.
- `velloraq/cli/` for command-line behavior.
- `velloraq/frontend/` for the static dashboard served by the API.
- `velloraq/scanner/`, `velloraq/rules/`, `velloraq/integrations/`, and `velloraq/reports/` for scanner functionality.

The root-level `app/` and `serverless_security_scanner/` folders are compatibility layers only.
