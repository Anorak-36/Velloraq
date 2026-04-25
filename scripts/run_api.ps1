$ErrorActionPreference = "Stop"
$hostName = if ($env:VELLORAQ_HOST) { $env:VELLORAQ_HOST } elseif ($env:SLSSEC_HOST) { $env:SLSSEC_HOST } else { "127.0.0.1" }
$port = if ($env:VELLORAQ_PORT) { $env:VELLORAQ_PORT } elseif ($env:SLSSEC_PORT) { $env:SLSSEC_PORT } else { "8000" }
python -m velloraq.backend.database.init_db
uvicorn velloraq.backend.api_server:app --host $hostName --port $port
