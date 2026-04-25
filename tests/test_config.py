# SPDX-License-Identifier: MIT
from __future__ import annotations

import os
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch

from velloraq.backend.core.config import Settings


class SettingsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
        self.runtime_dir = self.root / ".test-runtime" / "settings-config"
        self.runtime_dir.mkdir(exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.runtime_dir, ignore_errors=True)

    def test_production_defaults_disable_open_registration(self) -> None:
        reports_dir = self.runtime_dir / "settings-open-registration"
        with patch.dict(
            os.environ,
            {
                "VELLORAQ_APP_ENV": "production",
                "VELLORAQ_JWT_SECRET_KEY": "realistic-test-secret-with-more-than-32-characters",
                "VELLORAQ_ALLOWED_ORIGINS": "https://velloraq.example.com",
                "VELLORAQ_REPORTS_DIR": str(reports_dir),
            },
            clear=True,
        ):
            settings = Settings()

        self.assertFalse(settings.create_open_registration)

    def test_production_rejects_placeholder_jwt_secret(self) -> None:
        with patch.dict(
            os.environ,
            {
                "VELLORAQ_APP_ENV": "production",
                "VELLORAQ_JWT_SECRET_KEY": "change-this-to-a-long-random-secret",
                "VELLORAQ_ALLOWED_ORIGINS": "https://velloraq.example.com",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "VELLORAQ_JWT_SECRET_KEY"):
                Settings()

    def test_production_rejects_wildcard_cors(self) -> None:
        reports_dir = self.runtime_dir / "settings-cors"
        with patch.dict(
            os.environ,
            {
                "VELLORAQ_APP_ENV": "production",
                "VELLORAQ_JWT_SECRET_KEY": "realistic-test-secret-with-more-than-32-characters",
                "VELLORAQ_ALLOWED_ORIGINS": "*",
                "VELLORAQ_REPORTS_DIR": str(reports_dir),
            },
            clear=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "VELLORAQ_ALLOWED_ORIGINS"):
                Settings()

    def test_environment_examples_are_safe_placeholders(self) -> None:
        root = Path(__file__).resolve().parents[1]
        production = (root / ".env.production.example").read_text(encoding="utf-8")

        self.assertIn("VELLORAQ_APP_ENV=production", production)
        self.assertIn("VELLORAQ_OPEN_REGISTRATION=false", production)
        self.assertIn("VELLORAQ_JWT_SECRET_KEY=change-this-to-a-long-random-secret", production)
        self.assertNotIn("AKIA", production)
        self.assertNotIn("-----BEGIN", production)


if __name__ == "__main__":
    unittest.main()
