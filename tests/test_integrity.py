"""
CYBERGUARD SENTINEL — Unit & Integration Tests for Module 03 (File Integrity Monitor)
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import pytest
from sqlalchemy.orm import sessionmaker
from core.database import create_db_engine, init_database
from core.validators import ValidationError
from modules.file_integrity import FileIntegrityMonitor


@pytest.fixture
def isolated_fim() -> FileIntegrityMonitor:
    """Menyediakan instance FileIntegrityMonitor dengan database SQLite in-memory."""
    test_engine = create_db_engine("sqlite:///:memory:")
    init_database(custom_engine=test_engine)
    test_session_factory = sessionmaker(
        bind=test_engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )
    return FileIntegrityMonitor(session_factory=test_session_factory)


def test_sha256_computation_accuracy(tmp_path: Path) -> None:
    """Memastikan hasil komputasi SHA-256 chunked sesuai dengan referensi hashlib standar."""
    payload = b"cyberguard-sentinel-sha256-verification"
    sample_file = tmp_path / "hello.txt"
    sample_file.write_bytes(payload)

    expected_hash = hashlib.sha256(payload).hexdigest()
    assert FileIntegrityMonitor.compute_sha256(sample_file) == expected_hash


def test_detects_all_four_integrity_statuses(
    isolated_fim: FileIntegrityMonitor, tmp_path: Path
) -> None:
    """
    Memverifikasi deteksi lengkap untuk UNCHANGED, MODIFIED, NEW FILE, dan DELETED FILE.
    """
    file_unchanged = tmp_path / "tetap.txt"
    file_modified = tmp_path / "diubah.txt"
    file_deleted = tmp_path / "dihapus.txt"

    file_unchanged.write_text("konten asli 1", encoding="utf-8")
    file_modified.write_text("konten asli 2", encoding="utf-8")
    file_deleted.write_text("konten asli 3", encoding="utf-8")

    # 1. Buat baseline awal
    count = isolated_fim.create_or_update_baseline(str(tmp_path))
    assert count == 3

    # 2. Lakukan perubahan pada direktori uji
    file_modified.write_text("konten telah disusupi!", encoding="utf-8")
    file_deleted.unlink()
    file_new = tmp_path / "file_baru.txt"
    file_new.write_text("file tambahan", encoding="utf-8")

    # 3. Jalankan audit integritas
    report = isolated_fim.verify_integrity(str(tmp_path), save_changes_to_db=True)

    assert report.unchanged_count == 1
    assert report.modified_count == 1
    assert report.new_file_count == 1
    assert report.deleted_file_count == 1
    assert report.overall_risk_score >= 80
    assert report.severity == "CRITICAL"


def test_verify_without_baseline_raises_validation_error(
    isolated_fim: FileIntegrityMonitor, tmp_path: Path
) -> None:
    """Audit tanpa baseline terlebih dahulu harus ditolak dengan pesan yang jelas."""
    orphan_file = tmp_path / "tanpa_baseline.txt"
    orphan_file.write_text("data", encoding="utf-8")

    with pytest.raises(ValidationError):
        isolated_fim.verify_integrity(str(orphan_file))


def test_restricted_windows_system_directory_blocked(
    isolated_fim: FileIntegrityMonitor,
) -> None:
    """Direktori sistem Windows harus diblokir oleh validator keamanan."""
    with pytest.raises(ValidationError):
        isolated_fim.create_or_update_baseline("C:\\Windows\\System32")