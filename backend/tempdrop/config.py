"""Configuration for TempDrop. Secrets are required; no insecure fallback is used."""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BACKEND_DIR / ".env")


def _required_hex_secret(name: str) -> bytes:
    value = os.getenv(name, "").strip()
    if len(value) != 64:
        raise RuntimeError(
            f"{name} must be exactly 64 hexadecimal characters (generate it with: "
            "py -c \"import secrets; print(secrets.token_hex(32))\")."
        )
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must contain only hexadecimal characters.") from exc
    if len(decoded) != 32:
        raise RuntimeError(f"{name} must decode to exactly 32 bytes.")
    return decoded


APP_SECRET_KEY = _required_hex_secret("APP_SECRET_KEY")
FILE_ENCRYPTION_KEY = _required_hex_secret("FILE_ENCRYPTION_KEY")

DATA_DIR = Path(os.getenv("TEMPDROP_DATA_DIR", str(BACKEND_DIR / "data"))).expanduser().resolve()
DB_PATH = DATA_DIR / "tempdrop.sqlite3"
OBJECTS_DIR = DATA_DIR / "objects"
STAGING_DIR = DATA_DIR / "staging"
TEMP_DIR = DATA_DIR / "tmp"

APP_HOST = os.getenv("APP_HOST", "127.0.0.1").strip()
if APP_HOST not in {"127.0.0.1", "localhost", "::1"}:
    raise RuntimeError("TempDrop must bind to loopback only. Use APP_HOST=127.0.0.1 behind a tunnel.")
APP_PORT = int(os.getenv("APP_PORT", "8000"))

ALLOWED_ORIGINS = [
    origin.strip().rstrip("/")
    for origin in os.getenv(
        "ALLOWED_ORIGINS",
        "http://127.0.0.1:5500,http://localhost:5500",
    ).split(",")
    if origin.strip()
]
TRUST_CLOUDFLARE_PROXY = os.getenv("TRUST_CLOUDFLARE_PROXY", "true").lower() in {"1", "true", "yes"}

MAX_TRANSFER_BYTES = int(os.getenv("MAX_TRANSFER_BYTES", str(100 * 1024 * 1024)))
TRANSFER_TTL_SECONDS = int(os.getenv("TRANSFER_TTL_SECONDS", str(4 * 60 * 60)))
MAX_FILES_PER_TRANSFER = int(os.getenv("MAX_FILES_PER_TRANSFER", "20"))
MAX_GLOBAL_STORAGE_BYTES = int(os.getenv("MAX_GLOBAL_STORAGE_BYTES", str(5 * 1024 * 1024 * 1024)))
MAX_ACTIVE_TRANSFERS_PER_IP = int(os.getenv("MAX_ACTIVE_TRANSFERS_PER_IP", "10"))
MAX_CONCURRENT_UPLOADS = int(os.getenv("MAX_CONCURRENT_UPLOADS", "3"))
UPLOADS_PER_HOUR_PER_IP = int(os.getenv("UPLOADS_PER_HOUR_PER_IP", "10"))
MAX_DOWNLOADS_PER_TRANSFER = int(os.getenv("MAX_DOWNLOADS_PER_TRANSFER", "10"))
GENERAL_RATE_LIMIT = int(os.getenv("GENERAL_RATE_LIMIT", "120"))
GENERAL_RATE_WINDOW_SECONDS = int(os.getenv("GENERAL_RATE_WINDOW_SECONDS", "60"))
FAILED_PIN_LIMIT = int(os.getenv("FAILED_PIN_LIMIT", "5"))
PIN_ATTEMPT_WINDOW_SECONDS = int(os.getenv("PIN_ATTEMPT_WINDOW_SECONDS", "900"))
PIN_LOCKOUT_SECONDS = int(os.getenv("PIN_LOCKOUT_SECONDS", "900"))
CLEANUP_INTERVAL_SECONDS = int(os.getenv("CLEANUP_INTERVAL_SECONDS", "60"))
MAX_REQUEST_BYTES = MAX_TRANSFER_BYTES + 2 * 1024 * 1024
MAX_JSON_REQUEST_BYTES = 64 * 1024
MAX_FILE_NAME_CHARS = 180
BLOCKED_EXTENSIONS = {
    (ext.strip().lower() if ext.strip().startswith(".") else f".{ext.strip().lower()}")
    for ext in os.getenv("BLOCKED_EXTENSIONS", ".exe,.com,.bat,.cmd,.msi,.msp,.scr,.pif,.lnk,.hta,.vbs,.vbe,.wsf,.wsh,.ps1,.psm1,.reg,.dll,.sys").split(",")
    if ext.strip()
}
CHUNK_SIZE = 1024 * 1024

CODE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"  # avoids ambiguous 0/O and 1/I
