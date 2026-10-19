# TempDrop

**TempDrop** is a temporary file-transfer service with a GitHub Pages frontend and a Python API running on a Windows PC. A sender uploads files, then shares a 12-character transfer code and a four-digit PIN with a recipient. The recipient enters both values and downloads a ZIP archive. Transfers expire after four hours.

> This is a security-conscious college/project implementation, not a professionally audited public file-sharing service. Read [SECURITY.md](SECURITY.md) before making it publicly accessible.

## Features implemented

- **100 MiB maximum per transfer**, enforced by the server while reading the upload stream (not just by browser JavaScript).
- Four-hour expiration, checked on access and deleted by a cleanup loop that runs every 60 seconds.
- Cryptographically random 12-character transfer code plus a random four-digit PIN. The transfer code is required because a four-digit PIN alone has only 10,000 possibilities.
- PINs are not stored in plaintext. The database stores an HMAC-SHA-256 digest made with a separate server secret.
- Five incorrect PIN attempts per transfer/client in a 15-minute window trigger a 15-minute lockout. General request and per-hour upload rate limits are also applied.
- Maximum 20 files per transfer, 3 concurrent uploads, 10 active transfers per client, 10 successful downloads per transfer by default, and a configurable 5 GiB active-storage quota.
- AES-256-GCM encryption for stored files **and** the temporary ZIP archive. The ZIP is decrypted as it streams to the recipient; no plaintext ZIP is saved to disk.
- SHA-256 integrity checks for original file contents and authenticated-encryption verification.
- Safe filename handling, a configurable server-side blocklist for common Windows executable/script extensions, server-generated object filenames, parameterized SQL, strict CORS allowlist, request size limits, security headers, no cookies, and no API docs exposed by default.
- Logs omit PINs, original filenames, transfer codes, and raw client IP addresses.
- Automatic removal of expired transfer metadata and objects, plus startup cleanup of orphaned data from interrupted uploads.

## Project structure

```text
TempDrop/
├── README.md
├── SECURITY.md
├── .gitignore
├── docs/                         # publish this folder with GitHub Pages
│   ├── index.html
│   ├── styles.css
│   ├── app.js
│   └── config.js                 # set the backend HTTPS URL here
└── backend/
    ├── .env.example              # copy to .env; never commit .env
    ├── requirements.txt
    ├── setup_windows.ps1
    ├── run_windows.bat
    ├── pytest.ini
    ├── tempdrop/
    │   ├── __init__.py
    │   ├── config.py
    │   ├── database.py
    │   ├── main.py
    │   ├── security.py
    │   └── storage.py
    └── tests/
        ├── conftest.py
        ├── test_api.py
        └── test_security.py
```

The backend writes its SQLite database and encrypted objects to `backend/data/`. That folder is intentionally ignored by Git and must never be published as part of the website.

---

## 1. Install on Windows

Use **Python 3.11 or newer**. From the `backend` folder, you can either run the setup helper (it creates the venv, installs dependencies, and generates two fresh secrets) or run the manual commands below.

```powershell
cd backend
.\setup_windows.ps1
```

If script execution is blocked, use `Set-ExecutionPolicy -Scope Process Bypass` in that PowerShell window, then run the script again. The script will not overwrite an existing `.env`.

Manual setup:

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

If PowerShell blocks virtual-environment activation, either use `Set-ExecutionPolicy -Scope Process Bypass` for that PowerShell window or skip activation and call `.venv\Scripts\python.exe` directly.

### Generate two different secrets

Run this command **twice** from the `backend` folder:

```powershell
py -c "import secrets; print(secrets.token_hex(32))"
```

Edit `backend/.env` and replace both placeholders:

- `APP_SECRET_KEY`: protects PIN digests, rate-limit buckets, and client identifiers.
- `FILE_ENCRYPTION_KEY`: encrypts file contents and temporary ZIP archives with AES-256-GCM.

Use two different values. Keep `.env` private and back it up securely if you need to preserve existing transfers after a machine migration. **If `FILE_ENCRYPTION_KEY` is lost, existing encrypted files cannot be recovered.** If either key is changed, active transfers may stop working; key rotation needs a planned migration.

### Configure the web origin

In `backend/.env`, update `ALLOWED_ORIGINS` to the exact origin that will host the frontend. For example:

```dotenv
ALLOWED_ORIGINS=http://127.0.0.1:5500,http://localhost:5500,https://your-github-username.github.io
```

Use your actual GitHub username. The origin does not include the repository path. Do not use `*`.

Keep these settings as-is unless you understand the implications:

```dotenv
APP_HOST=127.0.0.1
APP_PORT=8000
TRUST_CLOUDFLARE_PROXY=true
MAX_TRANSFER_BYTES=104857600
TRANSFER_TTL_SECONDS=14400
```

The server intentionally refuses to bind to a non-loopback address. Use a tunnel rather than exposing port 8000 directly to the internet.

## 2. Run locally first

From `backend/` with the virtual environment active:

```powershell
python -c "from tempdrop.config import APP_HOST, APP_PORT; import uvicorn; uvicorn.run('tempdrop.main:app', host=APP_HOST, port=APP_PORT, workers=1)"
```

Or double-click `backend/run_windows.bat` after setup. Keep the terminal open while using TempDrop.

Check the API at <http://127.0.0.1:8000/api/health>. It should return a JSON status and the configured limits. API documentation endpoints are disabled by default.

Open a second PowerShell window at the repository root and serve the frontend locally:

```powershell
py -m http.server 5500 --directory docs
```

Browse to <http://127.0.0.1:5500>. Try uploading a small text file, copy its transfer code and PIN, switch to **Receive files**, and download it. The download is a ZIP. Stop either server with `Ctrl+C`.

## 3. Run the tests

From `backend/`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The tests exercise encryption at rest, successful upload/download, PIN lockout, expiry deletion, corrupted-file rejection, request-size rejection, CORS, and filename sanitization. Tests use a throwaway data directory and test-only keys; they do not use your real `backend/data/` folder.

## 4. Publish the frontend on GitHub Pages

1. Create a GitHub repository and push this project. The `.gitignore` excludes `backend/.env`, runtime data, and the virtual environment. **Before pushing, check that `.env` and any real files are not staged.**
2. In GitHub, open **Settings → Pages**.
3. Under the build/deployment source, choose **Deploy from a branch**, select your default branch (usually `main`), and select the `/docs` folder as the publishing source.
4. Save and wait for GitHub Pages to publish. Your site will have an origin similar to `https://your-github-username.github.io` or `https://your-github-username.github.io/repository-name/`.
5. Update `ALLOWED_ORIGINS` in `backend/.env` to the exact origin shown by GitHub Pages, then restart the backend.

GitHub Pages only hosts the static browser interface. It cannot run Python or store your uploaded files; the Windows API is a separate service.

## 5. Let another person reach the Windows API

A receiver outside your home/network cannot connect to `127.0.0.1` on your machine. For internet-wide use, publish the API through an HTTPS tunnel. This design avoids opening an inbound router port.

### Option A — quick test tunnel

Install `cloudflared` from Cloudflare's official documentation. With the backend running, open another terminal and run:

```powershell
cloudflared tunnel --url http://127.0.0.1:8000
```

Cloudflare prints a temporary HTTPS URL ending in `trycloudflare.com`. Copy it. The URL may change when you restart the quick tunnel, so this is best for testing.

### Option B — stable named tunnel

For a stable endpoint, use a Cloudflare account and a domain managed through Cloudflare:

1. In the Cloudflare dashboard, open **Networking → Tunnels** and create a tunnel.
2. Add a published application route, for example `api.yourdomain.com` → `http://127.0.0.1:8000`.
3. Install/run `cloudflared` on the Windows PC using the tunnel instructions shown in the Cloudflare dashboard.
4. Keep the backend process and tunnel running. Do not expose port 8000 directly through your router.

Cloudflare's official guide: <https://developers.cloudflare.com/tunnel/get-started/>. Quick Tunnels are also covered there.

### Connect the frontend to the tunnel

Suppose the tunnel URL is `https://api.yourdomain.com`.

1. Edit `docs/config.js`:

   ```js
   window.TEMPDROP_CONFIG = {
     API_BASE_URL: "https://api.yourdomain.com"
   };
   ```

2. Edit the Content Security Policy meta tag near the top of `docs/index.html`. Replace `https://YOUR-API-HOST.example.com` with the exact API origin, e.g. `https://api.yourdomain.com`. For a quick tunnel, use that exact `https://<name>.trycloudflare.com` URL.
3. Ensure `ALLOWED_ORIGINS` in `backend/.env` contains the **GitHub Pages site origin**, not the API tunnel URL.
4. Commit and push the `docs/` changes. Restart the backend after changing `.env`.
5. Keep the Windows PC powered on, connected to the internet, and running both the API and tunnel. The files physically reside on this PC, not in GitHub Pages or Cloudflare storage.

Use HTTPS only for a public deployment. The frontend includes a guard to warn if a secure GitHub Pages page is configured with a plaintext API URL.

## 6. How the flow works

1. The sender's browser posts selected files to `POST /api/transfers`.
2. The server enforces the request-body cap, limits file count/total size, encrypts files with AES-256-GCM, records file hashes and metadata in SQLite, and returns the transfer code and PIN once.
3. The sender shares both values with the recipient. Send the PIN separately from the transfer code where possible.
4. The recipient posts the code and PIN to `POST /api/transfers/{code}/download`.
5. The API applies rate limits and PIN lockout, verifies the HMAC PIN digest, verifies stored file integrity, creates an encrypted temporary ZIP, verifies its authentication tag, then decrypts the ZIP as it streams over HTTPS.
6. The temporary encrypted ZIP is removed after the response, and the original encrypted files plus metadata are removed when the transfer expires.

## Configuration defaults

| Setting | Default | Purpose |
|---|---:|---|
| `MAX_TRANSFER_BYTES` | 104,857,600 | 100 MiB per transfer |
| `TRANSFER_TTL_SECONDS` | 14,400 | 4 hours |
| `MAX_FILES_PER_TRANSFER` | 20 | Avoid multipart/file-count abuse |
| `BLOCKED_EXTENSIONS` | common Windows executables/scripts | Extension blocklist; configurable in `.env` |
| `MAX_GLOBAL_STORAGE_BYTES` | 5 GiB | Cap active temporary data |
| `MAX_ACTIVE_TRANSFERS_PER_IP` | 10 | Limit active transfers from one client |
| `MAX_CONCURRENT_UPLOADS` | 3 | Bound simultaneous in-flight uploads and temporary disk pressure |
| `UPLOADS_PER_HOUR_PER_IP` | 10 | Upload rate limit |
| `MAX_DOWNLOADS_PER_TRANSFER` | 10 | Successful downloads before the transfer is unavailable |
| `FAILED_PIN_LIMIT` | 5 | Wrong PIN attempts before lockout |
| `PIN_ATTEMPT_WINDOW_SECONDS` | 900 | PIN-attempt window |
| `PIN_LOCKOUT_SECONDS` | 900 | 15-minute lockout |
| `CLEANUP_INTERVAL_SECONDS` | 60 | Expiry cleanup cadence |

The `100 MB` cap is implemented as **100 MiB** (100 × 1024 × 1024 bytes). Change it to decimal 100,000,000 bytes if your assignment interprets MB strictly in SI units.

The `BLOCKED_EXTENSIONS` setting checks the final filename extension against a blocklist of common Windows executable/script types. This is a basic safety guard, **not malware scanning**; files can be renamed, and arbitrary contents are not deeply inspected. Modify the list for your own transfer requirements.

## Troubleshooting

- **`APP_SECRET_KEY must be exactly 64...`**: update both secret values in `backend/.env`; do not leave the sample placeholders.
- **Frontend says it cannot connect**: confirm uvicorn is running, test `/api/health`, and confirm `docs/config.js` has the correct API URL.
- **CORS error in the browser**: `ALLOWED_ORIGINS` must match the frontend origin exactly. Restart the API after changing `.env`.
- **GitHub Pages loads but uploads fail**: GitHub Pages is just the frontend. The API URL must be a reachable HTTPS tunnel URL and the Windows PC must be online.
- **The tunnel URL changed**: update `docs/config.js` and the CSP allowlist, publish those changes, and update the API origin only if the frontend origin changed.
- **Files disappear after four hours**: this is expected. The cleanup loop checks each minute, so deletion is normally within about one cleanup interval after expiry.
- **Downloads fail after changing encryption key**: restore the original `FILE_ENCRYPTION_KEY`; changing it makes existing encrypted objects unreadable.

## License

For educational/project use. Add a license file if you plan to redistribute or deploy it for others.
