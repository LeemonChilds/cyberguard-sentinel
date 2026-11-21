"""
CYBERGUARD SENTINEL — Centralized Configuration
Tagline: DETECT. ANALYZE. PROTECT.

Mengelola seluruh konstanta sistem, path direktori, batasan keamanan,
dan parameter operasi secara terpusat. Mode bawaan diatur ke LIVE (Real-Time).
"""

from __future__ import annotations

import os
from pathlib import Path
from dotenv import load_dotenv

# Muat variabel lingkungan dari file .env jika tersedia
load_dotenv()

# ==========================================================
# 1. IDENTITAS APLIKASI
# ==========================================================
APP_NAME: str = os.getenv("APP_NAME", "CYBERGUARD SENTINEL")
APP_TAGLINE: str = "DETECT. ANALYZE. PROTECT."
APP_VERSION: str = os.getenv("APP_VERSION", "1.0.0")

# Mode operasi resmi: "LIVE" (default utama) atau "DEMO" (cadangan offline)
VALID_MODES: tuple[str, ...] = ("LIVE", "DEMO")
DEFAULT_MODE: str = os.getenv("DEFAULT_MODE", "LIVE").upper()
if DEFAULT_MODE not in VALID_MODES:
    DEFAULT_MODE = "LIVE"

# ==========================================================
# 2. DIREKTORI PROYEK (CROSS-PLATFORM SAFE)
# ==========================================================
BASE_DIR: Path = Path(__file__).resolve().parent
DATA_DIR: Path = BASE_DIR / "data"
REPORTS_DIR: Path = BASE_DIR / "reports"
ASSETS_DIR: Path = BASE_DIR / "assets"
LOGS_DIR: Path = BASE_DIR / "logs"

# Pastikan direktori operasional selalu tersedia
for _directory in (DATA_DIR, REPORTS_DIR, ASSETS_DIR, LOGS_DIR):
    _directory.mkdir(parents=True, exist_ok=True)

DEMO_DATASET_PATH: Path = DATA_DIR / "sample_events.json"

# ==========================================================
# 3. KONFIGURASI DATABASE SQLITE
# ==========================================================
DEFAULT_DB_PATH: Path = DATA_DIR / "cyberguard_sentinel.db"
DATABASE_URL: str = os.getenv(
    "DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH.as_posix()}"
)

# ==========================================================
# 4. BATASAN KEAMANAN & ETIKA DEFENSIF
# ==========================================================
# Port Scanner Guardrails
DEFAULT_SCAN_TARGET: str = os.getenv("DEFAULT_SCAN_TARGET", "127.0.0.1")
MAX_PORTS_PER_SCAN: int = int(os.getenv("MAX_PORTS_PER_SCAN", "100"))
SCAN_TIMEOUT_SECONDS: float = float(os.getenv("SCAN_TIMEOUT_SECONDS", "0.5"))
MIN_PORT_NUMBER: int = 1
MAX_PORT_NUMBER: int = 65535

# Phishing Analyzer HTTP Guardrails
HTTP_REQUEST_TIMEOUT: int = int(os.getenv("HTTP_REQUEST_TIMEOUT", "5"))
MAX_HTTP_REDIRECTS: int = int(os.getenv("MAX_HTTP_REDIRECTS", "3"))
ALLOWED_URL_SCHEMES: tuple[str, ...] = ("http", "https")

# ==========================================================
# 5. STANDAR RISK SCORING & INCIDENT TAXONOMY
# ==========================================================
RISK_LEVELS: dict[str, tuple[int, int]] = {
    "LOW": (0, 29),
    "MEDIUM": (30, 59),
    "HIGH": (60, 79),
    "CRITICAL": (80, 100),
}

INCIDENT_CATEGORIES: tuple[str, ...] = (
    "PHISHING",
    "NETWORK ANOMALY",
    "FILE MODIFICATION",
    "AUTHENTICATION ANOMALY",
    "PORT EXPOSURE",
)

INCIDENT_STATUSES: tuple[str, ...] = (
    "OPEN",
    "INVESTIGATING",
    "CONTAINED",
    "RESOLVED",
)

FILE_INTEGRITY_STATUSES: tuple[str, ...] = (
    "UNCHANGED",
    "MODIFIED",
    "NEW FILE",
    "DELETED FILE",
)

# ==========================================================
# 6. KONFIGURASI LOGGING
# ==========================================================
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FILE_PATH: Path = BASE_DIR / os.getenv(
    "LOG_FILE_PATH", "logs/cyberguard_sentinel.log"
)