# Velloraq Architecture

Velloraq is split into independent layers so the CLI, API, worker, and report
generation paths can evolve without duplicating scanning logic.

```text
velloraq/
  backend/       SaaS API, auth, database, services, workers
  cli/           command-line interface
  scanner/       provider-agnostic scan orchestration and domain models
  integrations/  read-only cloud, source, and dependency collectors
  rules/         security rule catalog
  reports/       JSON, HTML, SIEM, and local report serving
  frontend/      static SaaS dashboard
```

## Data Flow

1. A user launches a scan through the CLI or `POST /scans`.
2. SaaS requests are validated and persisted as queued scan rows.
3. The worker claims queued scans, builds a scanner context, and runs the shared
   scan engine.
4. Integrations collect read-only inventory. Rules turn inventory into findings.
5. Reports are rendered and stored. The dashboard fetches JSON results and loads
   HTML reports through authenticated, sandboxed endpoints.

Security-sensitive choices are centralized:

- Authentication and role checks live under `velloraq.backend.auth`.
- Report ownership checks live in `velloraq.backend.services.report_service`.
- Source path validation lives in `velloraq.backend.services.scan_service`.
- HTML escaping lives in `velloraq.reports.html_reporter`.
