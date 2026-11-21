"""
CYBERGUARD SENTINEL — Database Connection Manager (TiDB Cloud + Auto-Fallback SQLite)

Mengelola koneksi database SQLAlchemy:
1. Membaca konfigurasi TiDB dari file .env secara otomatis.
2. Membersihkan parameter query SSL pada URL TiDB Cloud dan mengonversinya menjadi SSLContext pymysql.
3. Menggunakan connection pooling (pool_pre_ping, pool_recycle) agar tahan terhadap timeout serverless.
4. Menyediakan auto-fallback aman ke SQLite lokal jika koneksi internet/TiDB tidak tersedia.
5. Menyediakan auto-sync kolom baru (ALTER TABLE ADD COLUMN) agar tabel lama di TiDB selaras dengan models.py.
6. Menyediakan fungsi standar check_database_health() dan init_database() untuk app.py dan seluruh modul.
"""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import ssl
import time
from typing import Any, Dict, Generator, List, Optional, Tuple
from urllib.parse import quote_plus, urlencode, urlsplit, urlunsplit
from dotenv import load_dotenv
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from core.logger import get_logger
from database.models import Base

logger = get_logger("cyberguard.database")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = PROJECT_ROOT / ".env"
load_dotenv(dotenv_path=ENV_PATH, override=False)

DEFAULT_SQLITE_DIR = PROJECT_ROOT / "data"
DEFAULT_SQLITE_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_SQLITE_URL = f"sqlite:///{(DEFAULT_SQLITE_DIR / 'cyberguard.db').as_posix()}"


def _resolve_raw_db_url_from_env() -> str:
    """Membaca URL koneksi TiDB dari berbagai kemungkinan nama variabel di .env."""
    for env_key in (
        "DATABASE_URL",
        "TIDB_URL",
        "TIDB_DATABASE_URL",
        "DB_URL",
        "SQLALCHEMY_DATABASE_URI",
    ):
        val = (os.getenv(env_key) or "").strip().strip('"').strip("'")
        if val:
            return val

    # Dukungan apabila konfigurasi di .env dipecah per komponen
    host = (os.getenv("TIDB_HOST") or os.getenv("DB_HOST") or "").strip()
    user = (os.getenv("TIDB_USER") or os.getenv("DB_USER") or "").strip()
    password = (os.getenv("TIDB_PASSWORD") or os.getenv("DB_PASSWORD") or "").strip()
    port = (os.getenv("TIDB_PORT") or os.getenv("DB_PORT") or "4000").strip()
    db_name = (os.getenv("TIDB_DATABASE") or os.getenv("TIDB_DB") or os.getenv("DB_NAME") or "test").strip()

    if host and user:
        safe_user = quote_plus(user)
        safe_pass = quote_plus(password)
        return f"mysql+pymysql://{safe_user}:{safe_pass}@{host}:{port}/{db_name}"

    return DEFAULT_SQLITE_URL


def _prepare_sqlalchemy_url_and_args(raw_url: str) -> Tuple[str, Dict[str, Any], bool]:
    """
    Menormalisasi URL koneksi SQLAlchemy dan menyusun argumen SSL untuk TiDB Cloud.
    Mengembalikan tuple: (normalized_url, engine_kwargs, is_tidb_or_mysql)
    """
    url = raw_url.strip()

    if url.startswith("tidb://"):
        url = "mysql+pymysql://" + url[len("tidb://") :]
    elif url.startswith("mysql://"):
        url = "mysql+pymysql://" + url[len("mysql://") :]

    if url.startswith("mysql+pymysql://"):
        parts = urlsplit(url)
        # Hapus parameter query SSL dari URL karena pymysql mewajibkannya lewat connect_args
        clean_query_pairs = []
        if parts.query:
            for item in parts.query.split("&"):
                key = item.split("=", 1)[0].lower()
                if key not in {"ssl_verify_cert", "ssl_verify_identity", "ssl_ca", "ssl", "ssl_mode"}:
                    clean_query_pairs.append(item)
        clean_query = "&".join(clean_query_pairs) if clean_query_pairs else urlencode({"charset": "utf8mb4"})
        normalized_url = urlunsplit((parts.scheme, parts.netloc, parts.path or "/test", clean_query, parts.fragment))

        ssl_ca_path = (os.getenv("TIDB_SSL_CA") or os.getenv("SSL_CA") or "").strip()
        ssl_ctx = ssl.create_default_context()
        if ssl_ca_path and Path(ssl_ca_path).is_file():
            ssl_ctx.load_verify_locations(cafile=ssl_ca_path)

        engine_kwargs: Dict[str, Any] = {
            "pool_pre_ping": True,
            "pool_recycle": 300,
            "pool_size": 5,
            "max_overflow": 10,
            "connect_args": {
                "ssl": ssl_ctx,
                "connect_timeout": 10,
            },
        }
        return normalized_url, engine_kwargs, True

    # Fallback ke SQLite lokal
    sqlite_kwargs: Dict[str, Any] = {
        "connect_args": {"check_same_thread": False} if url.startswith("sqlite") else {},
    }
    return url, sqlite_kwargs, False


_ACTIVE_BACKEND_INFO: Dict[str, Any] = {
    "backend": "Initializing",
    "connected": False,
    "host": "-",
    "database": "-",
    "error": None,
}


def _create_resilient_engine() -> Engine:
    """Membuat SQLAlchemy Engine ke TiDB Cloud dengan auto-fallback ke SQLite jika offline."""
    raw_url = _resolve_raw_db_url_from_env()
    normalized_url, engine_kwargs, is_remote_mysql = _prepare_sqlalchemy_url_and_args(raw_url)

    if is_remote_mysql:
        parts = urlsplit(normalized_url)
        host_display = parts.hostname or "tidbcloud"
        db_display = (parts.path or "/test").lstrip("/") or "test"
        try:
            candidate_engine = create_engine(normalized_url, **engine_kwargs)
            with candidate_engine.connect() as conn:
                conn.execute(text("SELECT 1"))

            _ACTIVE_BACKEND_INFO.update(
                {
                    "backend": "TiDB Cloud (MySQL-Compatible)",
                    "connected": True,
                    "host": host_display,
                    "database": db_display,
                    "error": None,
                }
            )
            logger.info("Berhasil terhubung ke TiDB Cloud (%s / %s).", host_display, db_display)
            return candidate_engine
        except Exception as exc:
            logger.warning("Koneksi ke TiDB Cloud gagal (%s). Beralih otomatis ke SQLite lokal.", exc)
            _ACTIVE_BACKEND_INFO.update(
                {
                    "backend": "SQLite Local (Fallback Mode)",
                    "connected": True,
                    "host": "localhost (cyberguard.db)",
                    "database": "cyberguard.db",
                    "error": str(exc),
                }
            )
            return create_engine(DEFAULT_SQLITE_URL, connect_args={"check_same_thread": False})

    _ACTIVE_BACKEND_INFO.update(
        {
            "backend": "SQLite Local",
            "connected": True,
            "host": "localhost (cyberguard.db)",
            "database": "cyberguard.db",
            "error": None,
        }
    )
    return create_engine(normalized_url, **engine_kwargs)


engine: Engine = _create_resilient_engine()
SessionLocal: sessionmaker[Session] = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


def get_engine() -> Engine:
    return engine


def get_session_factory() -> sessionmaker[Session]:
    return SessionLocal


def get_database_status() -> Dict[str, Any]:
    """Mengembalikan informasi status database aktif (TiDB Cloud atau SQLite Fallback)."""
    return dict(_ACTIVE_BACKEND_INFO)


def check_database_health(custom_engine: Optional[Engine] = None) -> Dict[str, Any]:
    """
    Memeriksa kesehatan koneksi database aktif (TiDB Cloud / SQLite)
    dengan menjalankan kueri SELECT 1 dan menghitung latensi respons.
    """
    target_engine = custom_engine or engine
    start_time = time.perf_counter()
    try:
        with target_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        _ACTIVE_BACKEND_INFO["connected"] = True
        _ACTIVE_BACKEND_INFO["error"] = None

        backend_name = _ACTIVE_BACKEND_INFO.get("backend", target_engine.dialect.name)
        db_name = _ACTIVE_BACKEND_INFO.get("database", "-")
        host_name = _ACTIVE_BACKEND_INFO.get("host", "-")

        return {
            "status": "healthy",
            "healthy": True,
            "connected": True,
            "ok": True,
            "backend": backend_name,
            "dialect": target_engine.dialect.name,
            "host": host_name,
            "database": db_name,
            "latency_ms": latency_ms,
            "message": f"Terhubung ke {backend_name} ({db_name}) dalam {latency_ms} ms",
            "error": None,
        }
    except Exception as exc:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        _ACTIVE_BACKEND_INFO["connected"] = False
        _ACTIVE_BACKEND_INFO["error"] = str(exc)
        logger.error("Pemeriksaan kesehatan database gagal: %s", exc)

        return {
            "status": "unhealthy",
            "healthy": False,
            "connected": False,
            "ok": False,
            "backend": _ACTIVE_BACKEND_INFO.get("backend", target_engine.dialect.name),
            "dialect": target_engine.dialect.name,
            "host": _ACTIVE_BACKEND_INFO.get("host", "-"),
            "database": _ACTIVE_BACKEND_INFO.get("database", "-"),
            "latency_ms": latency_ms,
            "message": f"Koneksi database bermasalah: {exc}",
            "error": str(exc),
        }


def _sync_missing_columns(target_engine: Engine) -> List[str]:
    """
    Memeriksa tabel yang sudah ada di database (TiDB / SQLite) dan menambahkan
    kolom baru dari database/models.py yang belum tersedia menggunakan ALTER TABLE.
    """
    added_columns: List[str] = []
    inspector = inspect(target_engine)
    existing_tables = set(inspector.get_table_names())
    preparer = target_engine.dialect.identifier_preparer

    for table_name, table in Base.metadata.tables.items():
        if table_name not in existing_tables:
            continue

        existing_cols = {col["name"].lower() for col in inspector.get_columns(table_name)}
        quoted_table = preparer.quote(table_name)

        for column in table.columns:
            if column.name.lower() in existing_cols:
                continue

            col_type_sql = column.type.compile(dialect=target_engine.dialect)
            default_clause = ""
            if column.default is not None and getattr(column.default, "is_scalar", False):
                val = column.default.arg
                if isinstance(val, bool):
                    default_clause = f" DEFAULT {1 if val else 0}"
                elif isinstance(val, (int, float)):
                    default_clause = f" DEFAULT {val}"
                elif isinstance(val, str):
                    escaped = val.replace("'", "''")
                    default_clause = f" DEFAULT '{escaped}'"

            null_clause = "NULL" if (column.nullable or default_clause == "") else "NOT NULL"
            quoted_col = preparer.quote(column.name)
            alter_sql = f"ALTER TABLE {quoted_table} ADD COLUMN {quoted_col} {col_type_sql}{default_clause} {null_clause}"

            try:
                with target_engine.begin() as conn:
                    conn.execute(text(alter_sql))
                added_columns.append(f"{table_name}.{column.name}")
                logger.info("Kolom baru berhasil ditambahkan ke database: %s.%s", table_name, column.name)
            except Exception as alter_exc:
                logger.warning("Gagal menambahkan kolom %s.%s: %s", table_name, column.name, alter_exc)

    return added_columns


def init_db(custom_engine: Optional[Engine] = None) -> None:
    """Membuat tabel baru dan menyinkronkan kolom yang kurang pada database aktif."""
    target_engine = custom_engine or engine
    Base.metadata.create_all(bind=target_engine)
    _sync_missing_columns(target_engine)
    logger.info("Skema tabel database berhasil diverifikasi/disinkronkan pada %s.", _ACTIVE_BACKEND_INFO["backend"])


def init_database(custom_engine: Optional[Engine] = None) -> bool:
    """Inisialisasi & sinkronisasi tabel database (kompatibel dengan pemanggilan dari app.py)."""
    init_db(custom_engine=custom_engine)
    return True


@contextmanager
def get_db_session(session_factory: Optional[sessionmaker] = None) -> Generator[Session, None, None]:
    """Context manager transaksi database yang aman dengan auto-commit dan rollback."""
    factory = session_factory or SessionLocal
    session: Session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Generator[Session, None, None]:
    """Generator sesi database standar."""
    with get_db_session() as session:
        yield session


# Pastikan tabel dan kolom otomatis tersinkronisasi saat modul diimpor
try:
    init_db(engine)
except Exception as init_exc:
    logger.error("Gagal inisialisasi awal tabel database: %s", init_exc)