"""CLI helper for creating or rotating the first admin account."""

# SPDX-License-Identifier: MIT
from __future__ import annotations

import argparse
import getpass

from sqlalchemy import select

from velloraq.backend.auth.security import hash_password
from velloraq.backend.database.migrate import run_migrations
from velloraq.backend.database.session import SessionLocal
from velloraq.backend.models.entities import User


def create_admin(email: str, password: str) -> User:
    """Create an admin user or update an existing account with admin role."""

    run_migrations()
    with SessionLocal() as db:
        existing = db.execute(select(User).where(User.email == email.lower())).scalar_one_or_none()
        if existing:
            existing.password_hash = hash_password(password)
            existing.role = "admin"
            existing.is_active = True
            db.commit()
            db.refresh(existing)
            return existing
        user = User(email=email.lower(), password_hash=hash_password(password), role="admin")
        db.add(user)
        db.commit()
        db.refresh(user)
        return user


def main() -> None:
    """Parse admin creation arguments and execute the account update."""

    parser = argparse.ArgumentParser(description="Create or update the first admin user.")
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", help="Admin password. If omitted, prompt securely.")
    args = parser.parse_args()
    password = args.password or getpass.getpass("Admin password: ")
    create_admin(args.email, password)
    print(f"Admin user ready: {args.email.lower()}")


if __name__ == "__main__":
    main()
