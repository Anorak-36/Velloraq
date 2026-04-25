"""Legacy module entrypoint for ``python -m serverless_security_scanner``."""

# SPDX-License-Identifier: MIT
from velloraq.cli.entrypoint import main

if __name__ == "__main__":
    raise SystemExit(main())
