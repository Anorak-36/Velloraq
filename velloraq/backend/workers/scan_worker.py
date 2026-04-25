# SPDX-License-Identifier: MIT
"""velloraq.backend.workers.scan_worker module for the Velloraq security platform."""

from __future__ import annotations

import signal
import time

from velloraq.backend.core.config import get_settings
from velloraq.backend.database.migrate import run_migrations
from velloraq.backend.database.session import SessionLocal
from velloraq.backend.services.scan_service import claim_next_scan, execute_scan


running = True


def _stop(*_args: object) -> None:
    """Internal helper used to keep the module implementation focused."""
    global running
    running = False


def run_worker() -> None:
    """Execute the run_worker operation for this module."""
    settings = get_settings()
    run_migrations()
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    print("Scan worker started.")
    while running:
        processed = 0
        with SessionLocal() as db:
            for _ in range(settings.scan_worker_batch_size):
                scan = claim_next_scan(db)
                if not scan:
                    break
                print(f"Running scan {scan.id}")
                execute_scan(db, scan)
                processed += 1
        if processed == 0:
            time.sleep(settings.scan_poll_interval_seconds)
    print("Scan worker stopped.")


if __name__ == "__main__":
    run_worker()
