"""TempDrop API: temporary, PIN-protected transfer creation and retrieval."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import threading
import time
import uuid
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask
from starlette.datastructures import UploadFile as StarletteUploadFile

from . import database
from .config import (
    ALLOWED_ORIGINS,
    BLOCKED_EXTENSIONS,
    APP_PORT,
    CLEANUP_INTERVAL_SECONDS,
    CODE_ALPHABET,
    FAILED_PIN_LIMIT,
    GENERAL_RATE_LIMIT,
    GENERAL_RATE_WINDOW_SECONDS,
    MAX_ACTIVE_TRANSFERS_PER_IP,
    MAX_CONCURRENT_UPLOADS,
    MAX_DOWNLOADS_PER_TRANSFER,
    MAX_FILES_PER_TRANSFER,
    MAX_GLOBAL_STORAGE_BYTES,
    MAX_JSON_REQUEST_BYTES,
    MAX_REQUEST_BYTES,
    MAX_TRANSFER_BYTES,
    OBJECTS_DIR,
    PIN_ATTEMPT_WINDOW_SECONDS,
    PIN_LOCKOUT_SECONDS,
    STAGING_DIR,
    TEMP_DIR,
    TRANSFER_TTL_SECONDS,
    UPLOADS_PER_HOUR_PER_IP,
    APP_HOST,
)
from .database import CapacityError
from .security import (
    PIN_RE,
    TRANSFER_CODE_RE,
    client_ip_hash,
    consume_rate_limit,
    create_pin_digest,
    sanitize_filename,
    verify_pin,
)
from .storage import (
    STORAGE_LOCK,
    StorageIntegrityError,
    UploadTooLarge,
    build_encrypted_zip,
    cleanup_storage,
    ensure_storage_dirs,
    iter_decrypted_zip,
    reconcile_orphans,
    remove_object_files,
    safe_unlink,
    write_encrypted_upload,
)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("tempdrop")
UPLOAD_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_UPLOADS)


class DownloadBody(BaseModel):
    pin: str = Field(max_length=20)


class BodyTooLarge(Exception):
    pass


class RequestSizeLimitMiddleware:
    """Reject oversized bodies as they stream in, before multipart parsing can spool them."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path == "/api/transfers":
            limit = MAX_REQUEST_BYTES
        elif path.startswith("/api/"):
            limit = MAX_JSON_REQUEST_BYTES
        else:
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        raw_length = headers.get(b"content-length")
        if raw_length:
            try:
                if int(raw_length) > limit:
                    await self._send_413(send)
                    return
            except ValueError:
                await self._send_400(send)
                return

        received = 0
        response_started = False

        async def tracked_send(message):
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise BodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, tracked_send)
        except BodyTooLarge:
            if not response_started:
                await self._send_413(send)

    @staticmethod
    async def _send_413(send):
        body = b'{"detail":"Request body exceeds the configured size limit."}'
        await send({"type": "http.response.start", "status": 413, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
            (b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff"),
        ]})
        await send({"type": "http.response.body", "body": body})

    @staticmethod
    async def _send_400(send):
        body = b'{"detail":"Invalid Content-Length header."}'
        await send({"type": "http.response.start", "status": 400, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
            (b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff"),
        ]})
        await send({"type": "http.response.body", "body": body})


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        async def secure_send(message):
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers", []))
                existing = {key.lower() for key, _ in headers}
                additions = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                    (b"cache-control", b"no-store"),
                    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"),
                ]
                # Cloudflare Tunnel forwards the original scheme; only trust that marker from loopback.
                client = scope.get("client")
                peer = client[0] if client else ""
                forwarded_proto = next((v.decode("latin1") for k, v in scope.get("headers", []) if k.lower() == b"x-forwarded-proto"), "")
                cf_visitor = next((v.decode("latin1") for k, v in scope.get("headers", []) if k.lower() == b"cf-visitor"), "")
                if scope.get("scheme") == "https" or (peer in {"127.0.0.1", "::1", "localhost"} and (forwarded_proto == "https" or '"scheme":"https"' in cf_visitor.replace(" ", ""))):
                    additions.append((b"strict-transport-security", b"max-age=31536000"))
                for key, value in additions:
                    if key not in existing:
                        headers.append((key, value))
                message["headers"] = headers
            await send(message)
        await self.app(scope, receive, secure_send)


def _cleanup_once() -> None:
    cleanup_storage(int(time.time()), database.delete_expired_records)


async def _cleanup_loop() -> None:
    while True:
        await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)
        try:
            await asyncio.to_thread(_cleanup_once)
        except Exception:
            logger.exception("cleanup_cycle_failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_storage_dirs()
    database.init_db()
    await asyncio.to_thread(_cleanup_once)
    await asyncio.to_thread(reconcile_orphans, database.referenced_storage_names())
    cleanup_task = asyncio.create_task(_cleanup_loop())
    try:
        yield
    finally:
        cleanup_task.cancel()
        with suppress(asyncio.CancelledError):
            await cleanup_task


app = FastAPI(
    title="TempDrop API",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
    max_age=600,
)
app.add_middleware(RequestSizeLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)


def _rate_limit(request: Request, scope: str, limit: int, seconds: int) -> str:
    ip_hash = client_ip_hash(request)
    retry = consume_rate_limit(ip_hash, scope, limit, seconds, int(time.time()))
    if retry is not None:
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please wait and try again.",
            headers={"Retry-After": str(retry)},
        )
    return ip_hash


def _new_transfer_code() -> str:
    # 12 chars from a 32-symbol alphabet (60 bits); the four-digit PIN is a second factor.
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(12))


def _new_pin() -> str:
    return f"{secrets.randbelow(10_000):04d}"


def _iso_utc(epoch_seconds: int) -> str:
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _unavailable() -> HTTPException:
    return HTTPException(
        status_code=404,
        detail="Transfer code or PIN is incorrect, expired, or unavailable.",
    )


@app.get("/api/health")
def health(request: Request):
    _rate_limit(request, "general", GENERAL_RATE_LIMIT, GENERAL_RATE_WINDOW_SECONDS)
    return {
        "status": "ok",
        "max_transfer_bytes": MAX_TRANSFER_BYTES,
        "transfer_ttl_seconds": TRANSFER_TTL_SECONDS,
        "max_files_per_transfer": MAX_FILES_PER_TRANSFER,
        "max_downloads_per_transfer": MAX_DOWNLOADS_PER_TRANSFER,
    }


@app.post("/api/transfers", status_code=201)
async def create_transfer(request: Request):
    ip_hash = _rate_limit(request, "general", GENERAL_RATE_LIMIT, GENERAL_RATE_WINDOW_SECONDS)
    upload_retry = consume_rate_limit(ip_hash, "upload-hour", UPLOADS_PER_HOUR_PER_IP, 3600, int(time.time()))
    if upload_retry is not None:
        raise HTTPException(
            status_code=429,
            detail="Upload limit reached for this hour. Please try again later.",
            headers={"Retry-After": str(upload_retry)},
        )

    await asyncio.to_thread(_cleanup_once)
    if database.count_active_transfers(ip_hash) >= MAX_ACTIVE_TRANSFERS_PER_IP:
        raise HTTPException(
            status_code=429,
            detail="Too many active transfers. Wait for one to expire before uploading again.",
        )
    if database.active_storage_bytes() >= MAX_GLOBAL_STORAGE_BYTES:
        raise HTTPException(status_code=507, detail="Temporary storage is full. Try again later.")

    if not UPLOAD_SLOTS.acquire(blocking=False):
        raise HTTPException(status_code=503, detail="The upload queue is busy. Please try again shortly.", headers={"Retry-After": "10"})

    staged_paths: list[Path] = []
    object_paths: list[Path] = []
    committed = False
    file_rows: list[dict[str, Any]] = []
    total_size = 0

    try:
        async with request.form(max_files=MAX_FILES_PER_TRANSFER, max_fields=4, max_part_size=16 * 1024) as form:
            if set(form.keys()) != {"files"}:
                raise HTTPException(status_code=400, detail="Send one or more files using the 'files' field only.")
            uploads = form.getlist("files")
            if not uploads:
                raise HTTPException(status_code=400, detail="Select at least one file.")
            if len(uploads) > MAX_FILES_PER_TRANSFER or any(not isinstance(upload, StarletteUploadFile) for upload in uploads):
                raise HTTPException(status_code=400, detail=f"A transfer may contain at most {MAX_FILES_PER_TRANSFER} files.")

            for upload in uploads:
                safe_name = sanitize_filename(upload.filename)
                extension = Path(safe_name).suffix.lower()
                if extension in BLOCKED_EXTENSIONS:
                    raise HTTPException(status_code=415, detail=f"Files ending in {extension} are blocked by this server.")
                storage_name = uuid.uuid4().hex
                staging_path = STAGING_DIR / f"{storage_name}.part"
                staged_paths.append(staging_path)
                try:
                    size, digest = await asyncio.to_thread(
                        write_encrypted_upload,
                        upload.file,
                        staging_path,
                        MAX_TRANSFER_BYTES - total_size,
                    )
                except UploadTooLarge as exc:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Total transfer size cannot exceed {MAX_TRANSFER_BYTES // (1024 * 1024)} MiB.",
                    ) from exc
                total_size += size
                file_rows.append({
                    "storage_name": storage_name,
                    "original_name": safe_name,
                    "size": size,
                    "sha256": digest,
                    "staging_path": staging_path,
                })

        if total_size > MAX_TRANSFER_BYTES:
            raise HTTPException(status_code=413, detail="Transfer size exceeds the configured limit.")

        # Stage encrypted objects first; rollback removes them if the DB transaction fails.
        with STORAGE_LOCK:
            for row in file_rows:
                final_path = OBJECTS_DIR / row["storage_name"]
                os.replace(row["staging_path"], final_path)
                object_paths.append(final_path)

            created_at = int(time.time())
            expires_at = created_at + TRANSFER_TTL_SECONDS
            transfer_code = _new_transfer_code()
            pin = _new_pin()
            database.create_transfer(
                transfer_code=transfer_code,
                pin_digest=create_pin_digest(transfer_code, pin),
                created_at=created_at,
                expires_at=expires_at,
                file_count=len(file_rows),
                total_size=total_size,
                upload_ip_hash=ip_hash,
                file_rows=file_rows,
                max_active_per_ip=MAX_ACTIVE_TRANSFERS_PER_IP,
                max_storage_bytes=MAX_GLOBAL_STORAGE_BYTES,
            )
            committed = True

        logger.info("transfer_created file_count=%d bytes=%d", len(file_rows), total_size)
        return JSONResponse(status_code=201, content={
            "transfer_code": transfer_code,
            "pin": pin,
            "file_count": len(file_rows),
            "total_size": total_size,
            "expires_at": _iso_utc(expires_at),
            "expires_in_seconds": TRANSFER_TTL_SECONDS,
            "max_downloads": MAX_DOWNLOADS_PER_TRANSFER,
        }, headers={"Cache-Control": "no-store"})

    except CapacityError as exc:
        status = 429 if "active transfers" in str(exc).lower() else 507
        raise HTTPException(status_code=status, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception:
        logger.exception("transfer_creation_failed")
        raise HTTPException(status_code=500, detail="Upload failed. No transfer was created.")
    finally:
        for path in staged_paths:
            safe_unlink(path)
        if not committed:
            for path in object_paths:
                safe_unlink(path)
        UPLOAD_SLOTS.release()


def _prepare_download(transfer_code: str, pin: str, ip_hash: str) -> tuple[Path, int]:
    """Perform access checks and build a verified encrypted ZIP under the storage lock."""
    now = int(time.time())
    code = transfer_code.strip().upper()
    if not TRANSFER_CODE_RE.fullmatch(code):
        raise _unavailable()

    with STORAGE_LOCK:
        transfer = database.get_transfer(code)
        if not transfer:
            raise _unavailable()
        if int(transfer["expires_at"]) <= now:
            remove_object_files(database.delete_transfer_record(code))
            raise _unavailable()

        attempt = database.get_pin_attempt(code, ip_hash)
        if attempt and int(attempt["blocked_until"]) > now:
            retry = int(attempt["blocked_until"]) - now
            raise HTTPException(
                status_code=429,
                detail="Too many incorrect PIN attempts. This transfer is temporarily locked for your connection.",
                headers={"Retry-After": str(max(1, retry))},
            )

        if not verify_pin(code, pin, transfer["pin_digest"]):
            failures, blocked_until = database.record_bad_pin(
                code, ip_hash, now, PIN_ATTEMPT_WINDOW_SECONDS, FAILED_PIN_LIMIT, PIN_LOCKOUT_SECONDS
            )
            logger.warning("pin_rejected")
            if blocked_until > now:
                raise HTTPException(
                    status_code=429,
                    detail="Too many incorrect PIN attempts. This transfer is temporarily locked for your connection.",
                    headers={"Retry-After": str(max(1, blocked_until - now))},
                )
            raise _unavailable()

        database.clear_pin_attempt(code, ip_hash)
        if int(transfer["download_count"]) >= MAX_DOWNLOADS_PER_TRANSFER:
            raise _unavailable()

        file_rows = database.get_transfer_files(code)
        try:
            archive_path, archive_size = build_encrypted_zip(file_rows, code)
        except StorageIntegrityError as exc:
            logger.error("stored_file_integrity_check_failed")
            raise HTTPException(status_code=500, detail="A stored file failed integrity verification. The transfer could not be downloaded.") from exc
        except Exception as exc:
            logger.exception("archive_preparation_failed")
            raise HTTPException(status_code=500, detail="Could not prepare this transfer for download.") from exc

        if not database.reserve_download(code, int(time.time()), MAX_DOWNLOADS_PER_TRANSFER):
            safe_unlink(archive_path)
            raise _unavailable()
        logger.info("transfer_download_prepared bytes=%d", archive_size)
        return archive_path, archive_size


@app.post("/api/transfers/{transfer_code}/download")
async def download_transfer(transfer_code: str, body: DownloadBody, request: Request):
    ip_hash = _rate_limit(request, "general", GENERAL_RATE_LIMIT, GENERAL_RATE_WINDOW_SECONDS)
    if len(transfer_code) > 32:
        raise _unavailable()
    try:
        archive_path, archive_size = await asyncio.to_thread(
            _prepare_download, transfer_code, body.pin, ip_hash
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("download_preparation_failed")
        raise HTTPException(status_code=500, detail="Could not prepare this transfer for download.")

    headers = {
        "Content-Disposition": f'attachment; filename="TempDrop_{transfer_code.strip().upper()}.zip"',
        "Content-Length": str(archive_size),
        "Cache-Control": "no-store, private",
        "Pragma": "no-cache",
        "X-Content-Type-Options": "nosniff",
    }
    return StreamingResponse(
        iter_decrypted_zip(archive_path),
        media_type="application/zip",
        headers=headers,
        background=BackgroundTask(safe_unlink, archive_path),
    )
