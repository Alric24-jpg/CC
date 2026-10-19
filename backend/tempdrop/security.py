"""Small security helpers: PIN derivation, client identity, rate limits, input cleanup."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import unicodedata
from pathlib import PurePosixPath
from typing import Any

from fastapi import Request

from . import database
from .config import (
    APP_SECRET_KEY,
    ALLOWED_ORIGINS,
    TRUST_CLOUDFLARE_PROXY,
    MAX_FILE_NAME_CHARS,
)

PIN_RE = re.compile(r"^\d{4}$")
TRANSFER_CODE_RE = re.compile(r"^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{12}$")


def create_pin_digest(transfer_code: str, pin: str) -> str:
    """HMAC, rather than a plain hash, prevents offline PIN guessing from a DB-only leak."""
    message = f"tempdrop-pin-v1:{transfer_code}:{pin}".encode("utf-8")
    return hmac.new(APP_SECRET_KEY, message, hashlib.sha256).hexdigest()


def verify_pin(transfer_code: str, pin: str, expected_digest: str) -> bool:
    if not PIN_RE.fullmatch(pin):
        # Still perform a constant-time comparison for a fixed dummy string.
        hmac.compare_digest(create_pin_digest(transfer_code, "0000"), "0" * 64)
        return False
    return hmac.compare_digest(create_pin_digest(transfer_code, pin), expected_digest)


def hash_client_ip(ip: str) -> str:
    return hmac.new(APP_SECRET_KEY, f"tempdrop-ip-v1:{ip}".encode(), hashlib.sha256).hexdigest()


def get_client_ip(request: Request) -> str:
    """Trust CF-Connecting-IP only when the TCP peer is loopback (cloudflared origin)."""
    peer = request.client.host if request.client else "unknown"
    try:
        peer_is_loopback = ipaddress.ip_address(peer).is_loopback
    except ValueError:
        peer_is_loopback = False
    if TRUST_CLOUDFLARE_PROXY and peer_is_loopback:
        forwarded = request.headers.get("cf-connecting-ip", "").strip()
        try:
            return str(ipaddress.ip_address(forwarded))
        except ValueError:
            pass
    return peer


def client_ip_hash(request: Request) -> str:
    return hash_client_ip(get_client_ip(request))


def consume_rate_limit(ip_hash: str, scope: str, limit: int, window_seconds: int, now: int) -> int | None:
    key = hmac.new(
        APP_SECRET_KEY,
        f"tempdrop-rate-v1:{scope}:{ip_hash}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return database.increment_rate_limit(key, now, window_seconds, limit)


def sanitize_filename(raw_name: str | None) -> str:
    """Convert user filename to a single safe archive path component."""
    name = unicodedata.normalize("NFC", (raw_name or "").replace("\\", "/"))
    name = PurePosixPath(name).name
    name = "".join(ch for ch in name if unicodedata.category(ch) not in {"Cc", "Cf", "Cs"})
    name = name.strip().strip(" .")
    if name in {"", ".", ".."}:
        name = "file"
    # Windows reserved names are made harmless for recipients on Windows.
    stem = name.split(".", 1)[0].upper()
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
    if stem in reserved:
        name = f"_{name}"
    if len(name) > MAX_FILE_NAME_CHARS:
        suffix = ""
        if "." in name and not name.startswith("."):
            base, ext = name.rsplit(".", 1)
            suffix = "." + ext[:20]
            name = base[: max(1, MAX_FILE_NAME_CHARS - len(suffix))] + suffix
        else:
            name = name[:MAX_FILE_NAME_CHARS]
    return name or "file"


def unique_archive_names(file_rows: list[dict[str, Any]]) -> list[tuple[dict[str, Any], str]]:
    """Avoid duplicate ZIP entries overwriting each other in common extractors."""
    result: list[tuple[dict[str, Any], str]] = []
    used: set[str] = set()
    for row in file_rows:
        original = sanitize_filename(row.get("original_name"))
        candidate = original
        counter = 2
        while candidate.casefold() in used:
            if "." in original and not original.startswith("."):
                base, ext = original.rsplit(".", 1)
                candidate = f"{base} ({counter}).{ext}"
            else:
                candidate = f"{original} ({counter})"
            counter += 1
        used.add(candidate.casefold())
        result.append((row, candidate))
    return result
