$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

if (Test-Path -LiteralPath ".env") {
    throw "backend/.env already exists. To avoid overwriting secrets, setup stopped. Keep your existing .env and run pip install -r requirements.txt manually if needed."
}

Write-Host "[1/4] Creating Python virtual environment..." -ForegroundColor Cyan
py -m venv .venv
$Python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $Python)) {
    throw "Could not create .venv. Install Python 3.11+ and ensure the 'py' launcher is available."
}

Write-Host "[2/4] Installing dependencies..." -ForegroundColor Cyan
& $Python -m pip install --upgrade pip
& $Python -m pip install -r requirements.txt

Write-Host "[3/4] Generating separate cryptographic secrets..." -ForegroundColor Cyan
$AppSecret = (& $Python -c "import secrets; print(secrets.token_hex(32))").Trim()
$FileSecret = (& $Python -c "import secrets; print(secrets.token_hex(32))").Trim()
if ($AppSecret -eq $FileSecret -or $AppSecret.Length -ne 64 -or $FileSecret.Length -ne 64) {
    throw "Secret generation failed; delete the incomplete .venv if necessary and try again."
}

Write-Host "[4/4] Creating backend/.env from the example..." -ForegroundColor Cyan
$EnvText = Get-Content -LiteralPath ".env.example" -Raw
$EnvText = $EnvText.Replace("REPLACE_WITH_A_UNIQUE_64_CHARACTER_HEX_SECRET", $AppSecret)
$EnvText = $EnvText.Replace("REPLACE_WITH_A_DIFFERENT_UNIQUE_64_CHARACTER_HEX_SECRET", $FileSecret)
Set-Content -LiteralPath ".env" -Value $EnvText -Encoding ascii

Write-Host "Setup complete." -ForegroundColor Green
Write-Host "Next: edit .env and replace YOUR-GITHUB-USERNAME with your GitHub Pages username."
Write-Host "Then run .\run_windows.bat, or follow README.md to run tests and publish the frontend."
Write-Host "Keep .env private. Losing FILE_ENCRYPTION_KEY makes stored files unreadable." -ForegroundColor Yellow
