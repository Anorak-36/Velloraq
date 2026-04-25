# Configuration

Velloraq reads environment variables at process startup. The canonical prefix is `VELLORAQ_`.

## Profiles

- `.env.example`: local Docker development.
- `.env.local.example`: local workstation development.
- `.env.production.example`: production-style self-hosted deployment.

## Required Production Values

```env
VELLORAQ_APP_ENV=production
VELLORAQ_OPEN_REGISTRATION=false
VELLORAQ_ALLOWED_ORIGINS=https://velloraq.example.com
VELLORAQ_JWT_SECRET_KEY=<generated-secret>
POSTGRES_PASSWORD=<generated-postgres-password>
VELLORAQ_FIRST_ADMIN_PASSWORD=<generated-admin-password>
```

Generate secrets:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

## Security Validation

Production startup rejects:

- Placeholder-looking JWT secrets.
- JWT secrets shorter than 32 characters.
- `VELLORAQ_ALLOWED_ORIGINS=*`.

When `VELLORAQ_APP_ENV=production` and `VELLORAQ_OPEN_REGISTRATION` is not set, registration defaults to disabled.

## Legacy Variables

Legacy `SLSSEC_*` variables are accepted as a migration aid. Prefer `VELLORAQ_*` in all new documentation, scripts, and deployments.
