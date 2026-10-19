"""SQLite persistence. All queries are parameterized and use short-lived connections."""
from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from typing import Iterator

from .config import DB_PATH, DATA_DIR


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(DB_PATH), timeout=30, isolation_level="DEFERRED")
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS transfers (
                transfer_code TEXT PRIMARY KEY,
                pin_digest TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                file_count INTEGER NOT NULL,
                total_size INTEGER NOT NULL,
                upload_ip_hash TEXT NOT NULL,
                download_count INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transfer_code TEXT NOT NULL REFERENCES transfers(transfer_code) ON DELETE CASCADE,
                storage_name TEXT NOT NULL UNIQUE,
                original_name TEXT NOT NULL,
                size INTEGER NOT NULL,
                sha256 TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pin_attempts (
                transfer_code TEXT NOT NULL,
                ip_hash TEXT NOT NULL,
                window_started_at INTEGER NOT NULL,
                failures INTEGER NOT NULL DEFAULT 0,
                blocked_until INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (transfer_code, ip_hash)
            );

            CREATE TABLE IF NOT EXISTS rate_limits (
                bucket_key TEXT PRIMARY KEY,
                window_started_at INTEGER NOT NULL,
                hits INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_transfers_expiry ON transfers(expires_at);
            CREATE INDEX IF NOT EXISTS idx_transfers_uploader ON transfers(upload_ip_hash, expires_at);
            CREATE INDEX IF NOT EXISTS idx_files_transfer ON files(transfer_code);
            """
        )


def get_transfer(transfer_code: str):
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM transfers WHERE transfer_code = ?", (transfer_code,)
        ).fetchone()
        return dict(row) if row else None


def get_transfer_files(transfer_code: str) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT storage_name, original_name, size, sha256 FROM files "
            "WHERE transfer_code = ? ORDER BY id ASC",
            (transfer_code,),
        ).fetchall()
        return [dict(row) for row in rows]


def count_active_transfers(ip_hash: str, now: int | None = None) -> int:
    now = int(time.time()) if now is None else now
    with connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM transfers WHERE upload_ip_hash = ? AND expires_at > ?",
            (ip_hash, now),
        ).fetchone()
        return int(row["n"])


def active_storage_bytes(now: int | None = None) -> int:
    now = int(time.time()) if now is None else now
    with connect() as conn:
        row = conn.execute(
            "SELECT COALESCE(SUM(total_size), 0) AS n FROM transfers WHERE expires_at > ?",
            (now,),
        ).fetchone()
        return int(row["n"])


def create_transfer(
    *, transfer_code: str, pin_digest: str, created_at: int, expires_at: int,
    file_count: int, total_size: int, upload_ip_hash: str, file_rows: list[dict],
    max_active_per_ip: int, max_storage_bytes: int,
) -> None:
    """Atomically check capacity and persist a transfer and its file metadata."""
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        active = conn.execute(
            "SELECT COUNT(*) AS n FROM transfers WHERE upload_ip_hash = ? AND expires_at > ?",
            (upload_ip_hash, created_at),
        ).fetchone()["n"]
        if int(active) >= max_active_per_ip:
            raise CapacityError("Too many active transfers. Wait for one to expire before uploading again.")
        used = conn.execute(
            "SELECT COALESCE(SUM(total_size), 0) AS n FROM transfers WHERE expires_at > ?",
            (created_at,),
        ).fetchone()["n"]
        if int(used) + total_size > max_storage_bytes:
            raise CapacityError("Temporary storage is full. Try again after some transfers expire.")
        conn.execute(
            "INSERT INTO transfers (transfer_code, pin_digest, created_at, expires_at, file_count, total_size, upload_ip_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (transfer_code, pin_digest, created_at, expires_at, file_count, total_size, upload_ip_hash),
        )
        conn.executemany(
            "INSERT INTO files (transfer_code, storage_name, original_name, size, sha256) VALUES (?, ?, ?, ?, ?)",
            [
                (transfer_code, f["storage_name"], f["original_name"], f["size"], f["sha256"])
                for f in file_rows
            ],
        )


class CapacityError(RuntimeError):
    pass


def reserve_download(transfer_code: str, now: int, max_downloads: int) -> bool:
    """Atomically count a successful archive preparation only if the transfer is still valid."""
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        cursor = conn.execute(
            "UPDATE transfers SET download_count = download_count + 1 "
            "WHERE transfer_code = ? AND expires_at > ? AND download_count < ?",
            (transfer_code, now, max_downloads),
        )
        return cursor.rowcount == 1


def reset_download_count(transfer_code: str) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE transfers SET download_count = CASE WHEN download_count > 0 THEN download_count - 1 ELSE 0 END "
            "WHERE transfer_code = ?",
            (transfer_code,),
        )


def delete_transfer_record(transfer_code: str) -> list[str]:
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            "SELECT storage_name FROM files WHERE transfer_code = ?", (transfer_code,)
        ).fetchall()
        conn.execute("DELETE FROM transfers WHERE transfer_code = ?", (transfer_code,))
        conn.execute("DELETE FROM pin_attempts WHERE transfer_code = ?", (transfer_code,))
        return [row["storage_name"] for row in rows]


def delete_expired_records(now: int | None = None) -> list[str]:
    now = int(time.time()) if now is None else now
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        expired = conn.execute(
            "SELECT transfer_code FROM transfers WHERE expires_at <= ?", (now,)
        ).fetchall()
        codes = [row["transfer_code"] for row in expired]
        if not codes:
            conn.execute("DELETE FROM rate_limits WHERE window_started_at < ?", (now - 86400,))
            return []
        placeholders = ",".join("?" for _ in codes)
        files = conn.execute(
            f"SELECT storage_name FROM files WHERE transfer_code IN ({placeholders})", codes
        ).fetchall()
        conn.execute(f"DELETE FROM transfers WHERE transfer_code IN ({placeholders})", codes)
        conn.execute(f"DELETE FROM pin_attempts WHERE transfer_code IN ({placeholders})", codes)
        conn.execute("DELETE FROM rate_limits WHERE window_started_at < ?", (now - 86400,))
        return [row["storage_name"] for row in files]


def referenced_storage_names() -> set[str]:
    with connect() as conn:
        rows = conn.execute("SELECT storage_name FROM files").fetchall()
        return {row["storage_name"] for row in rows}


def get_pin_attempt(transfer_code: str, ip_hash: str):
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM pin_attempts WHERE transfer_code = ? AND ip_hash = ?",
            (transfer_code, ip_hash),
        ).fetchone()
        return dict(row) if row else None


def record_bad_pin(
    transfer_code: str, ip_hash: str, now: int, window_seconds: int,
    max_failures: int, lockout_seconds: int,
) -> tuple[int, int]:
    """Return (failures_in_window, blocked_until)."""
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM pin_attempts WHERE transfer_code = ? AND ip_hash = ?",
            (transfer_code, ip_hash),
        ).fetchone()
        if row is None or now - int(row["window_started_at"]) >= window_seconds:
            failures = 1
            window_start = now
            blocked_until = now + lockout_seconds if failures >= max_failures else 0
            conn.execute(
                "INSERT INTO pin_attempts (transfer_code, ip_hash, window_started_at, failures, blocked_until) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(transfer_code, ip_hash) DO UPDATE SET "
                "window_started_at=excluded.window_started_at, failures=excluded.failures, blocked_until=excluded.blocked_until",
                (transfer_code, ip_hash, window_start, failures, blocked_until),
            )
        else:
            failures = int(row["failures"]) + 1
            window_start = int(row["window_started_at"])
            blocked_until = int(row["blocked_until"])
            if failures >= max_failures:
                blocked_until = max(blocked_until, now + lockout_seconds)
            conn.execute(
                "UPDATE pin_attempts SET failures = ?, blocked_until = ? WHERE transfer_code = ? AND ip_hash = ?",
                (failures, blocked_until, transfer_code, ip_hash),
            )
        return failures, blocked_until


def clear_pin_attempt(transfer_code: str, ip_hash: str) -> None:
    with connect() as conn:
        conn.execute(
            "DELETE FROM pin_attempts WHERE transfer_code = ? AND ip_hash = ?",
            (transfer_code, ip_hash),
        )


def increment_rate_limit(bucket_key: str, now: int, window_seconds: int, limit: int) -> int | None:
    """Return retry-after seconds if limited, otherwise None. Fixed windows are DB-atomic."""
    window_start = now - (now % window_seconds)
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT window_started_at, hits FROM rate_limits WHERE bucket_key = ?", (bucket_key,)
        ).fetchone()
        if row and int(row["window_started_at"]) == window_start:
            hits = int(row["hits"])
            if hits >= limit:
                return max(1, window_start + window_seconds - now)
            conn.execute(
                "UPDATE rate_limits SET hits = hits + 1 WHERE bucket_key = ?", (bucket_key,)
            )
        else:
            conn.execute(
                "INSERT INTO rate_limits (bucket_key, window_started_at, hits) VALUES (?, ?, 1) "
                "ON CONFLICT(bucket_key) DO UPDATE SET window_started_at=excluded.window_started_at, hits=1",
                (bucket_key, window_start),
            )
    return None
