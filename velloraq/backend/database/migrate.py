"""Minimal migration runner for self-hosted deployments."""

# SPDX-License-Identifier: MIT
from __future__ import annotations

from pathlib import Path

from sqlalchemy import text

from velloraq.backend.database.session import Base, engine


MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


def run_migrations() -> None:
    """Apply SQL migrations on PostgreSQL or create tables for SQLite tests."""

    if engine.dialect.name != "postgresql":
        import velloraq.backend.models  # noqa: F401

        Base.metadata.create_all(bind=engine)
        return
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                "version VARCHAR(255) PRIMARY KEY, "
                "applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"
            )
        )
        applied = {
            row[0]
            for row in connection.execute(text("SELECT version FROM schema_migrations")).fetchall()
        }
        for migration in sorted(MIGRATIONS_DIR.glob("*.sql")):
            version = migration.name
            if version in applied:
                continue
            statements = _split_sql(migration.read_text(encoding="utf-8"))
            for statement in statements:
                connection.exec_driver_sql(statement)
            connection.execute(
                text("INSERT INTO schema_migrations(version) VALUES (:version)"),
                {"version": version},
            )


def _split_sql(sql: str) -> list[str]:
    """Split migration SQL on statement semicolons outside quoted strings."""

    statements: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    for char in sql:
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        if char == ";" and not in_single and not in_double:
            statement = "".join(current).strip()
            if statement:
                statements.append(statement)
            current = []
            continue
        current.append(char)
    tail = "".join(current).strip()
    if tail:
        statements.append(tail)
    return statements


if __name__ == "__main__":
    run_migrations()
