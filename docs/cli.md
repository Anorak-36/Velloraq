# CLI

The preferred command is `velloraq`.

## Source Scan

```bash
velloraq scan --provider source --source-path examples/vulnerable_lambda.py --format all --output reports
```

## Dependency Scan

```bash
velloraq scan --provider source --dependency-manifest examples/requirements-vulnerable.txt --format json --output reports
```

## Cloud Scans

AWS:

```bash
velloraq scan --provider aws --aws-profile velloraq-readonly --region us-east-1 --format all --output reports
```

Azure:

```bash
velloraq scan --provider azure --azure-subscription 00000000-0000-0000-0000-000000000000 --format html --output reports
```

GCP:

```bash
velloraq scan --provider gcp --gcp-project my-project --region us-central1 --format all --output reports
```

## CI Gate

```bash
velloraq scan --provider source --source-path . --format all --output reports --fail-on High
```

## Compatibility Alias

`slssec` remains available for migration:

```bash
slssec scan --provider source --source-path examples/vulnerable_lambda.py --format json --output reports
```
