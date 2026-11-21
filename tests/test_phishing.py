"""
CYBERGUARD SENTINEL — Unit & Integration Tests for Module 01 (Phishing Detection Engine)
dan Centralized Risk Scoring Engine.
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import sessionmaker
from core.database import create_db_engine, init_database
from core.risk_engine import RiskIndicator, classify_severity, evaluate_risk
from core.validators import ValidationError
from modules.phishing_detector import PhishingDetector


@pytest.fixture
def isolated_detector() -> PhishingDetector:
    """Menyediakan instance PhishingDetector dengan database SQLite in-memory terisolasi."""
    test_engine = create_db_engine("sqlite:///:memory:")
    init_database(custom_engine=test_engine)
    test_session_factory = sessionmaker(
        bind=test_engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )
    return PhishingDetector(session_factory=test_session_factory)


def test_risk_engine_deduplication_and_bounds() -> None:
    """Memastikan Risk Engine mencegah penghitungan ganda dan membatasi skor 0-100."""
    indicators = [
        RiskIndicator(code="IND-1", weight=60, description="Indikator A"),
        RiskIndicator(code="IND-1", weight=60, description="Duplikat Indikator A"),
        RiskIndicator(code="IND-2", weight=55, description="Indikator B"),
    ]
    result = evaluate_risk(indicators)
    assert result.score == 100
    assert result.severity == "CRITICAL"
    assert len(result.indicators) == 2


def test_severity_classification_boundaries() -> None:
    """Memverifikasi batas klasifikasi tingkat keparahan resmi."""
    assert classify_severity(0) == "LOW"
    assert classify_severity(29) == "LOW"
    assert classify_severity(30) == "MEDIUM"
    assert classify_severity(59) == "MEDIUM"
    assert classify_severity(60) == "HIGH"
    assert classify_severity(79) == "HIGH"
    assert classify_severity(80) == "CRITICAL"
    assert classify_severity(100) == "CRITICAL"


def test_safe_url_classification(isolated_detector: PhishingDetector) -> None:
    """URL HTTPS bersih harus terklasifikasi sebagai SAFE."""
    res = isolated_detector.analyze_url("https://www.python.org/downloads/", save_to_db=True)
    assert res.classification == "SAFE"
    assert res.risk_score < 30
    assert res.scheme == "https"


def test_high_risk_phishing_url_detection(isolated_detector: PhishingDetector) -> None:
    """URL dengan IP host, HTTP, simbol @, dan kata kunci login harus terdeteksi HIGH RISK."""
    malicious_sample = "http://192.168.10.25@verify-account-login-update.tk/signin"
    res = isolated_detector.analyze_url(malicious_sample, save_to_db=True)
    assert res.classification == "HIGH RISK"
    assert res.risk_score >= 60
    assert len(res.reasons) >= 3


def test_invalid_url_schemes_rejected(isolated_detector: PhishingDetector) -> None:
    """Skema berbahaya seperti javascript: atau file:// wajib ditolak oleh validator."""
    with pytest.raises(ValidationError):
        isolated_detector.analyze_url("javascript:alert(1)", save_to_db=False)

    with pytest.raises(ValidationError):
        isolated_detector.analyze_url("file:///C:/Windows/System32", save_to_db=False)

    with pytest.raises(ValidationError):
        isolated_detector.analyze_url("", save_to_db=False)


def test_database_persistence_and_history_retrieval(isolated_detector: PhishingDetector) -> None:
    """Memastikan hasil analisis tersimpan ke PhishingHistory sesuai flag is_demo."""
    isolated_detector.analyze_url("https://example.com", save_to_db=True, is_demo=False)
    isolated_detector.analyze_url("http://suspicious-login-check.xyz", save_to_db=True, is_demo=True)

    live_history = isolated_detector.get_recent_history(is_demo=False)
    demo_history = isolated_detector.get_recent_history(is_demo=True)

    assert len(live_history) == 1
    assert live_history[0]["Domain"] == "example.com"
    assert len(demo_history) == 1
    assert demo_history[0]["Classification" if "Classification" in demo_history[0] else "Klasifikasi"] in (
        "SUSPICIOUS",
        "HIGH RISK",
    )