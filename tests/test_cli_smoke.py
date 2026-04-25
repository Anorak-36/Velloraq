from __future__ import annotations

import shutil
import subprocess
import sys
import unittest
from pathlib import Path


class CliSmokeTests(unittest.TestCase):
    def test_source_scan_cli_still_generates_reports(self) -> None:
        root = Path(__file__).resolve().parents[1]
        output_dir = root / ".test-runtime" / "cli-smoke"
        shutil.rmtree(output_dir, ignore_errors=True)

        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "velloraq",
                    "scan",
                    "--provider",
                    "source",
                    "--source-path",
                    "examples/vulnerable_lambda.py",
                    "--disable-rule",
                    "DEP-*",
                    "--format",
                    "json",
                    "--format",
                    "html",
                    "--output",
                    str(output_dir),
                ],
                cwd=root,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertTrue((output_dir / "latest.json").exists())
            self.assertTrue((output_dir / "latest.html").exists())
            self.assertIn("Scan completed:", result.stdout)
        finally:
            shutil.rmtree(output_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
