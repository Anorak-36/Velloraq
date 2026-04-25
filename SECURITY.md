# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| `main` | Security fixes accepted before the first stable release. |
| `0.1.x` | Supported after public release. |
| Earlier snapshots | Not supported. Upgrade to `main` or the latest release. |

## Vulnerability Reporting

Please report suspected vulnerabilities privately before opening a public issue.

1. Use the repository's private GitHub Security Advisory flow when available.
2. If private advisories are not enabled yet, contact a maintainer privately through the contact method listed on the release repository before opening a public issue.
3. Include affected version or commit, impact, reproduction steps, logs with secrets removed, and whether the issue is already public.
4. Do not include real cloud credentials, private keys, customer data, or exploit payloads against third-party systems.
5. Expect an initial response within 7 calendar days after public release.

## Scope

In scope:

- Authentication, authorization, and report ownership checks.
- JWT and session cookie handling.
- Stored report rendering and HTML escaping.
- Source path validation.
- Docker and production configuration defaults.
- CLI behavior that could leak secrets or alter target systems.

Out of scope:

- Scans against systems you do not own or lack permission to test.
- Denial-of-service testing against public instances.
- Social engineering, phishing, or physical attacks.
- Vulnerabilities in optional cloud providers unless Velloraq usage makes them exploitable.

## Responsible Disclosure

- Give maintainers a reasonable window to investigate and release a fix.
- Do not publish exploit details before a fix or mitigation is available.
- Avoid accessing, modifying, or exfiltrating data that is not yours.
- Stop testing and report immediately if you encounter sensitive data.

## Security Assumptions

- Operators run Velloraq behind HTTPS in production.
- Operators keep `.env` files and cloud credentials private.
- Cloud credentials used by Velloraq are read-only and least privilege.
- PostgreSQL is not exposed directly to the public internet.
- Generated reports are treated as sensitive artifacts.

## Production Hardening Checklist

- Set `VELLORAQ_APP_ENV=production`.
- Set `VELLORAQ_OPEN_REGISTRATION=false`.
- Generate a unique `VELLORAQ_JWT_SECRET_KEY` with `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
- Set exact `VELLORAQ_ALLOWED_ORIGINS`; do not use `*`.
- Use HTTPS. Production cookies are Secure.
- Replace `POSTGRES_PASSWORD` and `VELLORAQ_FIRST_ADMIN_PASSWORD`.
- Remove bootstrap admin password from `.env` after the first admin is verified.
- Restrict `.env` permissions to the service administrator.
- Keep PostgreSQL on a private network or Docker network.
- Back up PostgreSQL and test restore.
- Mount cloud credentials as runtime secrets, not committed files.
- Keep API, worker, and database logs free of credentials.
- Review generated reports before sharing externally.
- Upgrade dependencies regularly and rerun tests.
