# Changelog

All notable changes to Velloraq are documented here.

## 0.1.0-alpha - Unreleased

### Added

- Canonical Velloraq package, CLI, backend, dashboard, worker, and Docker service names.
- Preferred `velloraq` CLI command with `slssec` compatibility alias.
- FastAPI SaaS backend with JWT auth, PostgreSQL persistence, projects, scans, and report endpoints.
- Static dashboard for login, scan launch, history, findings, HTML report preview, HTML download, and JSON export.
- HTML, JSON, and SIEM JSONL report generation.
- Production environment examples and security documentation.

### Changed

- Consolidated Docker usage around root `docker-compose.yml`.
- Moved Dockerfiles to `docker/backend.Dockerfile` and `docker/worker.Dockerfile`.
- Documented `app` and `serverless_security_scanner` as compatibility shims rather than canonical roots.
- Production defaults now disable open registration unless explicitly enabled.
- Production startup rejects placeholder JWT secrets and wildcard CORS origins.

### Security

- HTML reports escape dynamic scanned values.
- Report endpoints enforce owner/admin access.
- HTML report responses include no-store, nosniff, and restrictive content security policy headers.
- Dashboard renders HTML reports in a sandboxed iframe.
- Cookie-backed unsafe requests receive an Origin check.
