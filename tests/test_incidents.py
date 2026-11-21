"""
CYBERGUARD SENTINEL — Unit & Integration Tests for Module 06 (Security Incident Analyzer)
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import sessionmaker
from core.database import create_db_engine, init_database
from core.validators import ValidationError
from modules.incident_analyzer import SecurityIncidentAnalyzer
from modules.phishing_detector import PhishingDetector
from services.incident_service import IncidentService


@pytest.fixture
def isolated_env():
    """Menyediakan environment SQLite in-memory terisolasi beserta service dan detector."""
    test_engine = create_db_engine("sqlite:///:memory:")
    init_database(custom_engine=test_engine)
    session_factory = sessionmaker(
        bind=test_engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )
    return {
        "session_factory": session_factory,
        "incident_service": IncidentService(session_factory=session_factory),
        "phishing_detector": PhishingDetector(session_factory=session_factory),
    }


def test_incident_lifecycle_creation_and_status_updates(isolated_env) -> None:
    """Memverifikasi pembuatan tiket insiden dan transisi status hingga RESOLVED."""
    service: IncidentService = isolated_env["incident_service"]

    created = service.create_manual_incident(
        title="Anomali Port SMB Terbuka pada Server Lab",
        category="PORT EXPOSURE",
        severity="HIGH",
        is_demo=False,
    )
    assert created.status == "OPEN"
    assert "port terbuka" in created.mitigation_notes.lower()
    assert "firewall" in created.mitigation_notes.lower()

    updated = service.change_incident_status(
        incident_id=created.id,
        new_status="CONTAINED",
        additional_notes="Port 445 diblokir via Windows Firewall.",
    )
    assert updated.status == "CONTAINED"
    assert "445" in updated.mitigation_notes
    assert "Windows Firewall" in updated.mitigation_notes

    resolved = service.change_incident_status(
        incident_id=created.id,
        new_status="RESOLVED",
    )
    assert resolved.status == "RESOLVED"


def test_auto_correlation_from_phishing_events(isolated_env) -> None:
    """
    Pengujian Integrasi: URL phishing menghasilkan SecurityEvent, lalu
    IncidentService mengkorelasikannya secara otomatis menjadi SecurityIncident.
    """
    detector: PhishingDetector = isolated_env["phishing_detector"]
    service: IncidentService = isolated_env["incident_service"]

    # Deteksi 2 URL berisiko tinggi
    detector.analyze_url("http://192.168.1.99@login-verify-bank.tk/auth", save_to_db=True, is_demo=False)
    detector.analyze_url("http://secure-update-account.xyz/password", save_to_db=True, is_demo=False)

    # Jalankan korelasi otomatis
    tickets = service.run_auto_correlation(is_demo=False)
    assert len(tickets) == 1
    assert tickets[0].category == "PHISHING"
    assert tickets[0].correlated_events_count == 2

    # Jalankan ulang korelasi tidak boleh menggandakan tiket untuk event yang sudah tertaut
    second_run = service.run_auto_correlation(is_demo=False)
    assert len(second_run) == 0


def test_invalid_category_and_status_rejected() -> None:
    """Kategori dan status di luar daftar resmi harus ditolak."""
    with pytest.raises(ValidationError):
        SecurityIncidentAnalyzer.validate_category("MALWARE_ATTACK_UNKNOWN")

    with pytest.raises(ValidationError):
        SecurityIncidentAnalyzer.validate_status("IGNORED")