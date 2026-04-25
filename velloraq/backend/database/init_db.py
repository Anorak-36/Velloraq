"""Command module for applying database migrations."""

# SPDX-License-Identifier: MIT
from __future__ import annotations

from velloraq.backend.database.migrate import run_migrations


def main() -> None:
    """Apply all pending migrations and print a short operator message."""

    run_migrations()
    print("Database migrations applied.")


if __name__ == "__main__":
    main()
