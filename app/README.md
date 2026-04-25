# Compatibility Layer

This folder exists to preserve backwards-compatible FastAPI imports and deployment entrypoints from earlier Velloraq builds.

New application code should be added under `velloraq/`, especially `velloraq/backend/`.

Current purpose:

- `app.main:app` forwards to `velloraq.backend.api_server:app`.
- Subpackages such as `app.api`, `app.auth`, and `app.services` expose legacy import paths for older deployments and scripts.

Do not add new features here unless the change is specifically about compatibility.
