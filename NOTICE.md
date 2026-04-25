# Velloraq Notice

Velloraq is released under the MIT License. See `LICENSE`.

This project depends on open-source software. The list below covers the primary runtime and development dependencies declared by the project. Transitive dependency notices remain governed by their respective packages.

| Dependency | Purpose | License family |
| --- | --- | --- |
| Python | Runtime | PSF License |
| FastAPI | API framework | MIT |
| Starlette | ASGI toolkit used by FastAPI | BSD-3-Clause |
| Uvicorn | ASGI server | BSD-3-Clause |
| SQLAlchemy | ORM and database toolkit | MIT |
| pg8000 | PostgreSQL driver | BSD-3-Clause |
| bcrypt | Password hashing | Apache-2.0 |
| PyJWT | JWT encoding and decoding | MIT |
| Pydantic | Data validation | MIT |
| boto3 / botocore | Optional AWS integration | Apache-2.0 |
| azure-identity | Optional Azure authentication | MIT |
| azure-mgmt-web | Optional Azure Functions inventory | MIT |
| azure-mgmt-storage | Optional Azure Storage inventory | MIT |
| azure-mgmt-authorization | Optional Azure RBAC inventory | MIT |
| azure-mgmt-resource | Optional Azure subscription/resource metadata | MIT |
| google-cloud-functions | Optional GCP Cloud Functions inventory | Apache-2.0 |
| google-cloud-storage | Optional GCP Cloud Storage inventory | Apache-2.0 |
| google-api-python-client | Optional GCP API access | Apache-2.0 |
| google-auth | Optional GCP authentication | Apache-2.0 |
| pytest | Development tests | MIT |
| ruff | Development linting | MIT |
| PostgreSQL container image | Docker database service | PostgreSQL License |

Optional integrations with AWS, Azure, Google Cloud, and NVD use those providers' public APIs. Velloraq does not require proprietary SaaS services to run local source scans or the self-hosted dashboard.
