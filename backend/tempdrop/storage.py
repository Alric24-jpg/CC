"""Encrypted disk storage and encrypted, streaming ZIP generation."""
from __future__ import annotations

import hashlib
import os
import threading
import uuid
import zipfile
from pathlib import Path
from typing import BinaryIO, Iterable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .config import (
    CHUNK_SIZE,
    FILE_ENCRYPTION_KEY,
    OBJECTS_DIR,
    STAGING_DIR,
    TEMP_DIR,
)
from .security import sanitize_filename, unique_archive_names

FILE_MAGIC = b"TDF1"
ZIP_MAGIC = b"TDZ1"
HEADER_SIZE = 4 + 12
TAG_SIZE = 16
STORAGE_LOCK = threading.RLock()


class UploadTooLarge(Exception):
    pass


class StorageIntegrityError(Exception):
    pass


def ensure_storage_dirs() -> None:
    OBJECTS_DIR.mkdir(parents=True, exist_ok=True)
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    TEMP_DIR.mkdir(parents=True, exist_ok=True)


def write_encrypted_upload(source: BinaryIO, destination: Path, max_bytes: int) -> tuple[int, str]:
    """Encrypt a spooled upload as AES-256-GCM while hashing the original bytes."""
    ensure_storage_dirs()
    nonce = os.urandom(12)
    encryptor = Cipher(algorithms.AES(FILE_ENCRYPTION_KEY), modes.GCM(nonce)).encryptor()
    digest = hashlib.sha256()
    total = 0
    source.seek(0)
    with destination.open("xb") as output:
        output.write(FILE_MAGIC + nonce)
        while True:
            remaining = max_bytes - total
            chunk = source.read(min(CHUNK_SIZE, remaining + 1))
            if not chunk:
                break
            if len(chunk) > remaining:
                raise UploadTooLarge
            total += len(chunk)
            digest.update(chunk)
            encrypted = encryptor.update(chunk)
            if encrypted:
                output.write(encrypted)
        tail = encryptor.finalize()
        if tail:
            output.write(tail)
        output.write(encryptor.tag)
    return total, digest.hexdigest()


def decrypt_file_to_writer(path: Path, output: BinaryIO, expected_sha256: str) -> None:
    """Authenticate/decrypt one stored file into a ZIP member writer."""
    try:
        with path.open("rb") as source:
            total_size = path.stat().st_size
            if total_size < HEADER_SIZE + TAG_SIZE:
                raise StorageIntegrityError("Encrypted object is too short.")
            header = source.read(HEADER_SIZE)
            if len(header) != HEADER_SIZE or header[:4] != FILE_MAGIC:
                raise StorageIntegrityError("Encrypted object header is invalid.")
            nonce = header[4:16]
            source.seek(total_size - TAG_SIZE)
            tag = source.read(TAG_SIZE)
            cipher_size = total_size - HEADER_SIZE - TAG_SIZE
            source.seek(HEADER_SIZE)
            decryptor = Cipher(algorithms.AES(FILE_ENCRYPTION_KEY), modes.GCM(nonce, tag)).decryptor()
            digest = hashlib.sha256()
            remaining = cipher_size
            while remaining:
                encrypted = source.read(min(CHUNK_SIZE, remaining))
                if not encrypted:
                    raise StorageIntegrityError("Encrypted object ended unexpectedly.")
                remaining -= len(encrypted)
                clear = decryptor.update(encrypted)
                if clear:
                    digest.update(clear)
                    output.write(clear)
            tail = decryptor.finalize()
            if tail:
                digest.update(tail)
                output.write(tail)
            if digest.hexdigest() != expected_sha256:
                raise StorageIntegrityError("Stored file hash does not match.")
    except InvalidTag as exc:
        raise StorageIntegrityError("Encrypted object authentication failed.") from exc
    except OSError as exc:
        raise StorageIntegrityError("Stored file is missing or unreadable.") from exc


class EncryptedZipWriter:
    """A non-seekable file object that encrypts ZIP bytes before they hit disk."""
    def __init__(self, destination: Path):
        self.path = destination
        self._file = destination.open("xb")
        self._nonce = os.urandom(12)
        self._encryptor = Cipher(algorithms.AES(FILE_ENCRYPTION_KEY), modes.GCM(self._nonce)).encryptor()
        self._plaintext_size = 0
        self._closed = False
        self._file.write(ZIP_MAGIC + self._nonce)

    def write(self, data: bytes) -> int:
        if self._closed:
            raise ValueError("write to closed encrypted ZIP writer")
        encrypted = self._encryptor.update(data)
        if encrypted:
            self._file.write(encrypted)
        self._plaintext_size += len(data)
        return len(data)

    def tell(self) -> int:
        return self._plaintext_size

    def flush(self) -> None:
        self._file.flush()

    def close(self) -> None:
        if self._closed:
            return
        try:
            tail = self._encryptor.finalize()
            if tail:
                self._file.write(tail)
            self._file.write(self._encryptor.tag)
            self._file.flush()
        finally:
            self._file.close()
            self._closed = True

    @property
    def plaintext_size(self) -> int:
        return self._plaintext_size


def build_encrypted_zip(file_rows: list[dict], transfer_code: str) -> tuple[Path, int]:
    """Build a standard ZIP archive but persist only the AES-GCM ciphertext to disk."""
    ensure_storage_dirs()
    archive_path = TEMP_DIR / f"archive-{uuid.uuid4().hex}.tdz"
    writer: EncryptedZipWriter | None = None
    try:
        writer = EncryptedZipWriter(archive_path)
        with zipfile.ZipFile(writer, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as archive:
            for row, archive_name in unique_archive_names(file_rows):
                object_path = OBJECTS_DIR / row["storage_name"]
                with archive.open(archive_name, mode="w", force_zip64=True) as member:
                    decrypt_file_to_writer(object_path, member, row["sha256"])
        writer.close()
        size = writer.plaintext_size
        # Authenticate the encrypted ZIP before sending any of it to a client.
        verify_encrypted_zip(archive_path)
        return archive_path, size
    except Exception:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass
        safe_unlink(archive_path)
        raise


def verify_encrypted_zip(path: Path) -> None:
    """Verify the archive GCM tag without writing a plaintext ZIP to disk."""
    try:
        with path.open("rb") as source:
            total_size = path.stat().st_size
            if total_size < HEADER_SIZE + TAG_SIZE:
                raise StorageIntegrityError("Encrypted archive is too short.")
            header = source.read(HEADER_SIZE)
            if len(header) != HEADER_SIZE or header[:4] != ZIP_MAGIC:
                raise StorageIntegrityError("Encrypted archive header is invalid.")
            nonce = header[4:16]
            source.seek(total_size - TAG_SIZE)
            tag = source.read(TAG_SIZE)
            remaining = total_size - HEADER_SIZE - TAG_SIZE
            source.seek(HEADER_SIZE)
            decryptor = Cipher(algorithms.AES(FILE_ENCRYPTION_KEY), modes.GCM(nonce, tag)).decryptor()
            while remaining:
                chunk = source.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise StorageIntegrityError("Encrypted archive ended unexpectedly.")
                remaining -= len(chunk)
                decryptor.update(chunk)
            decryptor.finalize()
    except InvalidTag as exc:
        raise StorageIntegrityError("Encrypted archive authentication failed.") from exc
    except OSError as exc:
        raise StorageIntegrityError("Encrypted archive is missing or unreadable.") from exc


def iter_decrypted_zip(path: Path) -> Iterable[bytes]:
    """Yield authenticated-structure ZIP bytes for HTTP streaming (no plaintext temp file)."""
    try:
        with path.open("rb") as source:
            total_size = path.stat().st_size
            if total_size < HEADER_SIZE + TAG_SIZE:
                raise StorageIntegrityError("Encrypted archive is too short.")
            header = source.read(HEADER_SIZE)
            if len(header) != HEADER_SIZE or header[:4] != ZIP_MAGIC:
                raise StorageIntegrityError("Encrypted archive header is invalid.")
            nonce = header[4:16]
            source.seek(total_size - TAG_SIZE)
            tag = source.read(TAG_SIZE)
            remaining = total_size - HEADER_SIZE - TAG_SIZE
            source.seek(HEADER_SIZE)
            decryptor = Cipher(algorithms.AES(FILE_ENCRYPTION_KEY), modes.GCM(nonce, tag)).decryptor()
            while remaining:
                encrypted = source.read(min(CHUNK_SIZE, remaining))
                if not encrypted:
                    raise StorageIntegrityError("Encrypted archive ended unexpectedly.")
                remaining -= len(encrypted)
                clear = decryptor.update(encrypted)
                if clear:
                    yield clear
            tail = decryptor.finalize()
            if tail:
                yield tail
    except InvalidTag as exc:
        raise StorageIntegrityError("Encrypted archive authentication failed.") from exc


def safe_unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        # A cleanup pass will retry on the next cycle/startup.
        pass


def remove_object_files(storage_names: Iterable[str]) -> None:
    for storage_name in storage_names:
        # Only generated UUID hex names can be present in this column.
        if storage_name and all(ch in "0123456789abcdef" for ch in storage_name) and len(storage_name) == 32:
            safe_unlink(OBJECTS_DIR / storage_name)


def cleanup_storage(now: int, delete_expired_records) -> None:
    """Delete expired objects and old abandoned temporary files."""
    ensure_storage_dirs()
    with STORAGE_LOCK:
        expired_names = delete_expired_records(now)
        remove_object_files(expired_names)
        for directory in (STAGING_DIR, TEMP_DIR):
            for path in directory.iterdir():
                try:
                    if path.is_file() and now - int(path.stat().st_mtime) > 86400:
                        safe_unlink(path)
                except OSError:
                    continue


def reconcile_orphans(referenced_names: set[str]) -> None:
    """On startup, remove files left behind if a prior process stopped mid-upload."""
    ensure_storage_dirs()
    with STORAGE_LOCK:
        for path in OBJECTS_DIR.iterdir():
            if path.is_file() and path.name not in referenced_names:
                safe_unlink(path)
        for directory in (STAGING_DIR, TEMP_DIR):
            for path in directory.iterdir():
                if path.is_file():
                    safe_unlink(path)
