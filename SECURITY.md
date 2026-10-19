# Security notes and deployment checklist

TempDrop deliberately combines a transfer code with a short PIN. A four-digit PIN is **not a strong standalone credential**; do not remove the transfer code or rate limits.

## Implemented controls

- Bind the API to loopback only; expose it through an HTTPS tunnel, not a raw forwarded port.
- Allow only exact frontend origins in CORS. Requests do not use cookies or browser credentials.
- Enforce upload request size at the ASGI receive layer before multipart parsing, then separately enforce actual total file bytes and file count.
- Sanitize original filenames, apply a configurable blocklist to common active Windows executable/script extensions, and use random UUID object names. File contents are never served from the public frontend directory.
- Encrypt persisted objects and temporary archives using AES-256-GCM with a separately configured 256-bit key. Verify GCM authentication tags and SHA-256 hashes before a download is sent.
- Store PIN HMAC digests, not PINs. The HMAC key is not stored in SQLite.
- Apply general request limits, hourly upload limits, maximum active transfers, global storage quota, PIN-attempt lockout, and a transfer download cap.
- Run expiry cleanup every minute; also clean expired transfers on startup and before an upload.
- Use parameterized SQL, safe generated storage paths, conservative response headers, `no-store`, and attachment-only ZIP downloads.
- Do not log PINs, raw IP addresses, original filenames, or transfer codes.

## Before any public deployment

- Generate unique values for both keys and keep `backend/.env` out of version control/backups that are accessible to others.
- Use a stable HTTPS tunnel hostname and confirm the frontend CSP and `ALLOWED_ORIGINS` are correct.
- Keep the Windows host patched, use a dedicated non-administrator Windows account where feasible, protect disk access, and enable Windows disk encryption (such as BitLocker) if supported.
- Limit access to the `backend/data/` directory. The application key is needed to decrypt stored files, so an attacker controlling the Windows account or the running process may be able to read transfers.
- Keep the host awake and connected only while you intend to offer file transfers. Monitor disk usage and logs.
- Consider putting the API behind Cloudflare WAF/rate limiting or access policy, but do not configure an identity gate that prevents the intended recipient from reaching it.
- Test with harmless sample files first. Never use files containing sensitive personal, financial, health, or credential data for a class demo.

## Known limitations (do not present these as solved)

- **No malware scanning.** A filename-extension blocklist rejects some common active Windows executable/script types, but it can be bypassed by renaming and does not inspect content for malware. Other file types are packaged in an attachment-only ZIP and are not executed by the server; recipients should only open files from a trusted sender.
- **Temporary multipart buffering.** The web framework may briefly spool incoming multipart data to a temporary file before the application encrypts it. The final stored object is encrypted, and form temporary files are closed at request end, but this is not equivalent to end-to-end encryption or guaranteed forensic erasure from storage media.
- **Not end-to-end encrypted.** The server can decrypt files to verify their hashes and create the download ZIP. HTTPS protects the network hop to the tunnel provider; the host application receives plaintext in memory while processing a transfer.
- **No user accounts or sender ownership.** Possession of the transfer code and PIN grants download access. There is no way to recover a lost PIN or prove the identity of a sender.
- **Single-machine availability.** If the Windows PC sleeps, shuts down, loses internet, or the tunnel stops, transfers cannot be uploaded or retrieved. Files are not backed by a cloud object store.
- **Filesystem/database are on one host.** AES-GCM protects saved contents from casual disk inspection without the encryption key, but a compromised live host or exposed `.env` can defeat this protection.
- **No formal security audit.** Rate limits are application-level and the project has not been load-tested or penetration-tested. A determined distributed attacker may still create denial-of-service pressure. Do not market this implementation as production-grade or suitable for regulated data.

## Incident response

If a key is exposed, stop the service and tunnel immediately. Rotate the keys, understanding that changing `FILE_ENCRYPTION_KEY` makes existing transfers unreadable unless you first perform a safe decrypt/re-encrypt migration. Remove the exposed key from repository history where possible, but assume it remains compromised. Review the host and tunnel access logs before bringing the service back online.
