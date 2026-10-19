from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

# Set a throwaway test key and isolated data path before importing the app.
TEST_DATA_DIR = Path(tempfile.mkdtemp(prefix="tempdrop-test-data-"))
os.environ["TEMPDROP_DATA_DIR"] = str(TEST_DATA_DIR)
os.environ["APP_SECRET_KEY"] = "11" * 32
os.environ["FILE_ENCRYPTION_KEY"] = "22" * 32
os.environ["ALLOWED_ORIGINS"] = "http://127.0.0.1:5500,http://localhost:5500,https://example.github.io"
os.environ["TRUST_CLOUDFLARE_PROXY"] = "false"
os.environ["FAILED_PIN_LIMIT"] = "5"
os.environ["PIN_ATTEMPT_WINDOW_SECONDS"] = "900"
os.environ["PIN_LOCKOUT_SECONDS"] = "900"

import pytest


@pytest.fixture(autouse=True)
def clean_test_data():
    if TEST_DATA_DIR.exists():
        shutil.rmtree(TEST_DATA_DIR)
    TEST_DATA_DIR.mkdir(parents=True)
    yield
    # Keep the empty root so a later fixture can re-create the SQLite database.
    if TEST_DATA_DIR.exists():
        shutil.rmtree(TEST_DATA_DIR)
