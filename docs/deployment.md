# Deployment

## Docker Compose

Run Compose from the repository root:

```bash
docker compose up --build
```

Services:

```text
velloraq-api      FastAPI API and dashboard
velloraq-worker   asynchronous scan worker
velloraq-db       PostgreSQL
```

## Frontend

The dashboard is embedded static frontend code in `velloraq/frontend/`.

`velloraq-api` serves both:

- REST API routes.
- Static dashboard HTML, CSS, and JavaScript.

There is no frontend build step in v0.1.0-alpha, and no separate `velloraq-frontend` service is required.

Dockerfiles:

```text
docker/backend.Dockerfile
docker/worker.Dockerfile
```

## Production Pattern

1. Copy `.env.production.example` to `.env`.
2. Replace all placeholder values.
3. Put the API behind HTTPS.
4. Keep PostgreSQL private.
5. Start the stack:

```bash
docker compose up -d --build
docker compose ps
docker compose logs --tail 80 velloraq-api velloraq-worker velloraq-db
```

## Backup

Create a PostgreSQL dump:

```bash
docker compose exec velloraq-db pg_dump -U velloraq velloraq > velloraq-backup.sql
```

Restore into a fresh database only after testing the procedure in a non-production environment.
