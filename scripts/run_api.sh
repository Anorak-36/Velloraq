#!/usr/bin/env sh
set -eu
python -m velloraq.backend.database.init_db
uvicorn velloraq.backend.api_server:app --host "${VELLORAQ_HOST:-${SLSSEC_HOST:-127.0.0.1}}" --port "${VELLORAQ_PORT:-${SLSSEC_PORT:-8000}}"
