from __future__ import annotations

import io
import os
import time
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from tempdrop.config import MAX_REQUEST_BYTES, OBJECTS_DIR, DB_PATH
from tempdrop import database
from tempdrop.main import app


def create_client():
    return TestClient(app)


def upload_one(client: TestClient, content: bytes = b"hello TempDrop"):
    response = client.post(
        "/api/transfers",
        files=[("files", ("hello.txt", content, "text/plain"))],
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_health_reports_limits():
    with create_client() as client:
        response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["max_transfer_bytes"] == 100 * 1024 * 1024
    assert response.json()["transfer_ttl_seconds"] == 4 * 60 * 60
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


def test_upload_stores_encrypted_objects_and_downloads_zip():
    with create_client() as client:
        transfer = upload_one(client, b"hello TempDrop, this should be encrypted on disk")
        code = transfer["transfer_code"]
        pin = transfer["pin"]

        object_paths = list(OBJECTS_DIR.iterdir())
        assert len(object_paths) == 1
        assert b"hello TempDrop" not in object_paths[0].read_bytes()

        response = client.post(f"/api/transfers/{code}/download", json={"pin": pin})
        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith("application/zip")
        assert response.headers["content-disposition"].endswith(f'TempDrop_{code}.zip"')
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            assert archive.namelist() == ["hello.txt"]
            assert archive.read("hello.txt") == b"hello TempDrop, this should be encrypted on disk"


def test_wrong_pin_lockout_after_five_attempts():
    with create_client() as client:
        transfer = upload_one(client)
        code = transfer["transfer_code"]
        for _ in range(4):
            response = client.post(f"/api/transfers/{code}/download", json={"pin": "9999"})
            assert response.status_code == 404
        response = client.post(f"/api/transfers/{code}/download", json={"pin": "9999"})
        assert response.status_code == 429
        assert int(response.headers["retry-after"]) > 0
        valid_pin_response = client.post(f"/api/transfers/{code}/download", json={"pin": transfer["pin"]})
        assert valid_pin_response.status_code == 429


def test_expired_transfer_is_unavailable_and_deleted():
    with create_client() as client:
        transfer = upload_one(client)
        with database.connect() as conn:
            conn.execute("UPDATE transfers SET expires_at = ? WHERE transfer_code = ?", (int(time.time()) - 1, transfer["transfer_code"]))
        response = client.post(
            f"/api/transfers/{transfer['transfer_code']}/download",
            json={"pin": transfer["pin"]},
        )
        assert response.status_code == 404
        assert database.get_transfer(transfer["transfer_code"]) is None
        assert list(OBJECTS_DIR.iterdir()) == []


def test_corrupted_encrypted_object_fails_closed():
    with create_client() as client:
        transfer = upload_one(client, b"a file to corrupt")
        encrypted_path = next(OBJECTS_DIR.iterdir())
        content = bytearray(encrypted_path.read_bytes())
        content[20] ^= 0xFF
        encrypted_path.write_bytes(content)
        response = client.post(
            f"/api/transfers/{transfer['transfer_code']}/download",
            json={"pin": transfer["pin"]},
        )
        assert response.status_code == 500
        assert "integrity" in response.json()["detail"].lower()


def test_oversized_declared_body_is_rejected_before_parsing():
    with create_client() as client:
        response = client.post(
            "/api/transfers",
            content=b"x",
            headers={"Content-Length": str(MAX_REQUEST_BYTES + 1), "Content-Type": "multipart/form-data; boundary=not-used"},
        )
    assert response.status_code == 413


def test_cors_allows_configured_origin_only():
    with create_client() as client:
        good = client.options(
            "/api/transfers",
            headers={
                "Origin": "https://example.github.io",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        bad = client.options(
            "/api/transfers",
            headers={
                "Origin": "https://attacker.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
    assert good.headers.get("access-control-allow-origin") == "https://example.github.io"
    assert bad.headers.get("access-control-allow-origin") is None


def test_hourly_upload_limit_is_enforced():
    with create_client() as client:
        for _ in range(10):
            response = client.post(
                "/api/transfers",
                files=[("files", ("small.txt", b"x", "text/plain"))],
            )
            assert response.status_code == 201, response.text
        response = client.post(
            "/api/transfers",
            files=[("files", ("small.txt", b"x", "text/plain"))],
        )
    assert response.status_code == 429
    assert "hour" in response.json()["detail"].lower()


def test_transfer_stops_after_configured_download_count():
    with create_client() as client:
        transfer = upload_one(client, b"download-count")
        code, pin = transfer["transfer_code"], transfer["pin"]
        for _ in range(10):
            response = client.post(f"/api/transfers/{code}/download", json={"pin": pin})
            assert response.status_code == 200, response.text
        response = client.post(f"/api/transfers/{code}/download", json={"pin": pin})
    assert response.status_code == 404


def test_blocked_executable_extension_is_rejected():
    with create_client() as client:
        response = client.post(
            "/api/transfers",
            files=[("files", ("sample.exe", b"not a real executable", "application/octet-stream"))],
        )
    assert response.status_code == 415
    assert "blocked" in response.json()["detail"].lower()
    assert not list(OBJECTS_DIR.iterdir())
