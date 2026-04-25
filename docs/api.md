# API

The FastAPI app is served by `velloraq.backend.api_server:app`.

## Health

```bash
curl http://localhost:8000/health
```

## Register

Registration works only when `VELLORAQ_OPEN_REGISTRATION=true`.

```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.local","password":"CorrectHorse123!"}'
```

## Login

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.local","password":"CorrectHorse123!"}'
```

Use the returned bearer token:

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8000/scans
```

## Create Scan

```bash
curl -X POST http://localhost:8000/scans \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"providers":["source"],"source_paths":["examples/vulnerable_lambda.py"]}'
```

## Results And Reports

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8000/scans/<scan-id>/results
curl -H "Authorization: Bearer <token>" http://localhost:8000/scans/<scan-id>/export/json
curl -H "Authorization: Bearer <token>" http://localhost:8000/scans/<scan-id>/report/html
curl -H "Authorization: Bearer <token>" -o report.html http://localhost:8000/scans/<scan-id>/report/download
```

Report and result endpoints require the scan owner or an admin user.
