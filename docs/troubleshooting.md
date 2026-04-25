# Troubleshooting

## API Does Not Start In Production

Generate a real JWT secret:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Set:

```env
VELLORAQ_APP_ENV=production
VELLORAQ_JWT_SECRET_KEY=<generated-secret>
VELLORAQ_ALLOWED_ORIGINS=https://velloraq.example.com
```

## Older Compose Releases Cannot Find `.env`

Linux/macOS:

```bash
cp .env.example .env
docker compose config
```

Windows CMD:

```cmd
copy .env.example .env
docker compose config
```

Windows PowerShell:

```powershell
Copy-Item .env.example .env
docker compose config
```

## Report Not Available

```bash
docker compose ps
docker compose logs --tail 80 velloraq-worker
docker compose logs --tail 80 velloraq-api
```

Confirm the worker is running and the scan reached `succeeded` or `failed`.

## Source Path Rejected

Set allowed roots:

```env
VELLORAQ_ALLOWED_SOURCE_ROOTS=/workspace,/app/examples
```

Then launch scans only under those roots.

## Login Works Locally But Not In Production

Production cookies require HTTPS. Put the API behind a TLS reverse proxy and set:

```env
VELLORAQ_ALLOWED_ORIGINS=https://velloraq.example.com
```
