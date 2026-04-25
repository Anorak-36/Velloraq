# SPDX-License-Identifier: MIT
from __future__ import annotations

import importlib.util
import json
import os
import socket
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path


SAAS_DEPS_AVAILABLE = all(
    importlib.util.find_spec(name) is not None for name in ("fastapi", "uvicorn", "sqlalchemy")
)


@unittest.skipUnless(SAAS_DEPS_AVAILABLE, "SaaS dependencies are not installed")
class ReportEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]
        cls.runtime_dir = cls.root / ".test-runtime"
        cls.runtime_dir.mkdir(exist_ok=True)
        cls.db_path = cls.runtime_dir / f"report-endpoints-{os.getpid()}.db"
        cls.log_path = cls.runtime_dir / f"report-endpoints-{os.getpid()}.log"
        db_path = cls.db_path.resolve().as_posix()
        cls.port = _free_port()
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.env = os.environ.copy()
        cls.env.update(
            {
                "VELLORAQ_DATABASE_URL": f"sqlite:///{db_path}",
                "VELLORAQ_JWT_SECRET_KEY": "test-report-endpoint-secret-with-more-than-32-chars",
                "VELLORAQ_ALLOWED_SOURCE_ROOTS": str(cls.root),
                "VELLORAQ_ALLOWED_ORIGINS": cls.base_url,
                "VELLORAQ_OPEN_REGISTRATION": "true",
            }
        )
        cls.log_file = cls.log_path.open("w", encoding="utf-8")
        cls.server = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "velloraq.backend.api_server:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(cls.port),
            ],
            cwd=cls.root,
            env=cls.env,
            stdout=cls.log_file,
            stderr=subprocess.STDOUT,
        )
        try:
            _wait_for_server(cls.base_url)
            cls.token, cls.cookie = cls._register_and_login()
            cls.scan_id = cls._create_completed_scan()
        except Exception:
            cls._stop_server()
            details = cls.log_path.read_text(encoding="utf-8") if cls.log_path.exists() else ""
            cls._cleanup_runtime()
            raise RuntimeError(f"Test API server did not become ready. Logs:\n{details}") from None

    @classmethod
    def tearDownClass(cls) -> None:
        cls._stop_server()
        cls._cleanup_runtime()

    @classmethod
    def _stop_server(cls) -> None:
        server = getattr(cls, "server", None)
        if not server:
            return
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
        log_file = getattr(cls, "log_file", None)
        if log_file:
            log_file.close()

    @classmethod
    def _cleanup_runtime(cls) -> None:
        for path in (getattr(cls, "db_path", None), getattr(cls, "log_path", None)):
            if path and Path(path).exists():
                Path(path).unlink(missing_ok=True)
        runtime_dir = getattr(cls, "runtime_dir", None)
        if runtime_dir and Path(runtime_dir).exists():
            try:
                Path(runtime_dir).rmdir()
            except OSError:
                pass

    def test_html_report_endpoint_returns_text_html(self) -> None:
        response = _request(
            f"{self.base_url}/scans/{self.scan_id}/report/html",
            headers={"Cookie": self.cookie},
        )

        self.assertEqual(response.status, 200)
        self.assertIn("text/html", response.headers.get("Content-Type", ""))
        self.assertIn("charset=utf-8", response.headers.get("Content-Type", "").lower())
        self.assertIn("Velloraq Report", response.body)

    def test_dashboard_index_loads(self) -> None:
        response = _request(f"{self.base_url}/")

        self.assertEqual(response.status, 200)
        self.assertIn("<title>Velloraq</title>", response.body)
        self.assertIn("report-frame", response.body)

    def test_scan_appears_in_history(self) -> None:
        scans = _request_json(f"{self.base_url}/scans", token=self.token)

        self.assertTrue(any(scan["id"] == self.scan_id for scan in scans))

    def test_html_report_endpoint_sets_browser_safety_headers(self) -> None:
        response = _request(
            f"{self.base_url}/scans/{self.scan_id}/report/html",
            headers={"Cookie": self.cookie},
        )

        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("Cache-Control"), "private, no-store")
        self.assertIn("default-src 'none'", response.headers.get("Content-Security-Policy", ""))

    def test_download_endpoint_returns_attachment(self) -> None:
        response = _request(
            f"{self.base_url}/scans/{self.scan_id}/report/download",
            headers={"Authorization": f"Bearer {self.token}"},
        )

        self.assertEqual(response.status, 200)
        self.assertIn("text/html", response.headers.get("Content-Type", ""))
        self.assertIn("charset=utf-8", response.headers.get("Content-Type", "").lower())
        self.assertEqual(
            response.headers.get("Content-Disposition"),
            f'attachment; filename="report_{self.scan_id}.html"',
        )
        self.assertIn("Velloraq Report", response.body)

    def test_missing_report_returns_404(self) -> None:
        scan = _request_json(
            f"{self.base_url}/scans",
            method="POST",
            token=self.token,
            payload={"providers": ["source"], "source_paths": ["examples/vulnerable_lambda.py"]},
        )

        with self.assertRaises(urllib.error.HTTPError) as error:
            _request(f"{self.base_url}/scans/{scan['id']}/report/html", token=self.token)

        self.assertEqual(error.exception.code, 404)
        self.assertIn("Report not available", error.exception.read().decode("utf-8"))

    def test_json_export_returns_raw_result(self) -> None:
        response = _request_json(
            f"{self.base_url}/scans/{self.scan_id}/export/json",
            token=self.token,
        )

        self.assertEqual(response["scanner"], "velloraq")
        self.assertIn("findings", response)

    def test_user_cannot_view_another_users_report(self) -> None:
        other_token, _ = self._register_and_login("report-other@example.local")

        with self.assertRaises(urllib.error.HTTPError) as error:
            _request(f"{self.base_url}/scans/{self.scan_id}/report/html", token=other_token)

        self.assertEqual(error.exception.code, 403)
        self.assertIn("Report access denied", error.exception.read().decode("utf-8"))

    def test_user_cannot_view_another_users_scan_result(self) -> None:
        other_token, _ = self._register_and_login("result-other@example.local")

        with self.assertRaises(urllib.error.HTTPError) as error:
            _request(f"{self.base_url}/scans/{self.scan_id}/results", token=other_token)

        self.assertEqual(error.exception.code, 404)

    @classmethod
    def _register_and_login(cls, email: str = "report-test@example.local") -> tuple[str, str]:
        payload = {"email": email, "password": "CorrectHorse123!"}
        _request_json(f"{cls.base_url}/auth/register", method="POST", payload=payload)
        login = _request_raw(f"{cls.base_url}/auth/login", method="POST", payload=payload)
        token = json.loads(login.body)["access_token"]
        cookie = login.headers.get("Set-Cookie", "").split(";", 1)[0]
        return token, cookie

    @classmethod
    def _create_completed_scan(cls) -> str:
        scan = _request_json(
            f"{cls.base_url}/scans",
            method="POST",
            token=cls.token,
            payload={
                "providers": ["source"],
                "source_paths": ["examples/vulnerable_lambda.py"],
                "disabled_rules": ["DEP-*"],
            },
        )
        subprocess.check_call(
            [
                sys.executable,
                "-c",
                (
                    "from velloraq.backend.database.session import SessionLocal; "
                    "from velloraq.backend.services.scan_service import claim_next_scan, execute_scan; "
                    "db=SessionLocal(); scan=claim_next_scan(db); "
                    "assert scan is not None; execute_scan(db, scan); db.close()"
                ),
            ],
            cwd=cls.root,
            env=cls.env,
        )
        return scan["id"]


class _Response:
    def __init__(self, status: int, headers, body: str) -> None:
        self.status = status
        self.headers = headers
        self.body = body


def _request_json(
    url: str,
    method: str = "GET",
    token: str | None = None,
    payload: dict | None = None,
) -> dict:
    return json.loads(_request(url, method=method, token=token, payload=payload).body)


def _request_raw(url: str, method: str = "GET", payload: dict | None = None) -> _Response:
    return _request(url, method=method, payload=payload)


def _request(
    url: str,
    method: str = "GET",
    token: str | None = None,
    payload: dict | None = None,
    headers: dict[str, str] | None = None,
) -> _Response:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request_headers = dict(headers or {})
    if payload is not None:
        request_headers["Content-Type"] = "application/json"
    if token:
        request_headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=body, headers=request_headers, method=method)
    with urllib.request.urlopen(request, timeout=20) as response:
        return _Response(
            response.status,
            response.headers,
            response.read().decode("utf-8"),
        )


def _wait_for_server(base_url: str) -> None:
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            _request(f"{base_url}/health")
            return
        except Exception:
            time.sleep(0.25)
    raise RuntimeError("Test API server did not become ready")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


if __name__ == "__main__":
    unittest.main()
