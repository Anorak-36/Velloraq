# Security Model

Velloraq is designed for defensive, read-only scanning.

## Authentication

- Passwords are hashed with bcrypt.
- API access uses signed JWT access tokens.
- Dashboard report iframes use an HttpOnly same-origin cookie so tokens are not placed in report URLs.
- Production cookies are Secure and require HTTPS.

## Authorization

- Normal users can see only their own scans and reports.
- Admin users can inspect all scans and reports.
- Report HTML retrieval goes through `velloraq.backend.services.report_service`.

## Report Rendering

- Dynamic report values are escaped by `velloraq.reports.html_reporter`.
- Dashboard report preview uses a sandboxed iframe.
- HTML report responses set no-store, nosniff, and restrictive content security policy headers.

## CSRF And CORS

- CORS origins are configured through `VELLORAQ_ALLOWED_ORIGINS`.
- Wildcard origins are rejected in production.
- Unsafe methods with session cookies receive an Origin check.
- Bearer token API automation remains supported.

## Source Path Controls

SaaS source scans are limited to `VELLORAQ_ALLOWED_SOURCE_ROOTS`. The API resolves paths and rejects paths outside those roots.

## Webhooks

Webhooks are disabled by default. When enabled, Velloraq rejects localhost and common private IPv4 destinations to reduce SSRF risk.
