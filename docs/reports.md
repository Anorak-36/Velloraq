# Reports

Velloraq produces:

- `latest.json`: structured scan result.
- `latest.html`: standalone escaped HTML report.
- `latest.siem.jsonl`: newline-delimited SIEM events.

## CLI Export

```bash
velloraq scan --provider source --source-path examples/vulnerable_lambda.py --format json --format html --format siem --output reports
```

## Dashboard

1. Select a completed scan.
2. Click `View HTML Report` to preview HTML in a sandboxed iframe.
3. Click `Download HTML Report` to download the report.
4. Click `View JSON` to open JSON output.

## API

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8000/scans/<scan-id>/export/json
curl -H "Authorization: Bearer <token>" -o report.html http://localhost:8000/scans/<scan-id>/report/download
```

Treat reports as sensitive because they can contain resource identifiers, file paths, and security findings.
