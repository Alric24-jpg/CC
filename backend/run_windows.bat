@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Virtual environment not found. Follow README.md to create it first.
  pause
  exit /b 1
)
if not exist ".env" (
  echo Missing backend\.env. Copy .env.example to .env and generate both secrets first.
  pause
  exit /b 1
)
.venv\Scripts\python.exe -c "from tempdrop.config import APP_HOST, APP_PORT; import uvicorn; uvicorn.run('tempdrop.main:app', host=APP_HOST, port=APP_PORT, workers=1)"
