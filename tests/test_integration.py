"""
CYBERGUARD SENTINEL — End-to-End System Integration Tests (Phase 9)
"""

from __future__ import annotations

from pathlib import Path
import pytest
from sqlalchemy.orm import sessionmaker
import config
from core.database import create_db_engine, init_database
from core.security_engine import SecurityEngine
from services.monitoring_service import MonitoringService
from services.report_service import ReportService


@pytest.fixture
def full_system_env():
    """Menyediakan lingkungan sistem lengkap dengan SQLite in-memory terisolasi."""
    test_engine = create_db_engine("sqlite:///:memory:")
    init_database(custom_engine=test_engine)
    session_factory = sessionmaker(
        bind=test_engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )
    return {
        "engine": SecurityEngine(session_factory=session_factory),
        "monitoring": MonitoringService(session_factory=session_factory),
        "reports": ReportService(session_factory=session_factory),
    }


def test_default_mode_is_live_realtime() -> None:
    """Memastikan konfigurasi default aplikasi aktif pada LIVE MODE."""
    assert config.DEFAULT_MODE == "LIVE"


def test_end_to_end_live_workflow_and_report_generation(
    full_system_env, tmp_path: Path
) -> None:
    """
    Menguji alur integrasi lengkap LIVE MODE:
    Phishing + File Integrity + System Sweep -> Incident Correlation -> Report Export.
    """
    sec_engine: SecurityEngine = full_system_env["engine"]
    monitoring_svc: MonitoringService = full_system_env["monitoring"]
    report_svc: ReportService = full_system_env["reports"]

    # 1. Deteksi URL phishing berisiko tinggi (LIVE)
    phish_res = sec_engine.phishing.analyze_url(
        "http://192.168.1.88@verify-login-account.tk/reset",
        save_to_db=True,
        is_demo=False,
    )
    assert phish_res.classification == "HIGH RISK"

    # 2. Deteksi modifikasi file pada direktori sementara (LIVE)
    sample_doc = tmp_path / "dokumen_penting.txt"
    sample_doc.write_text("versi asli", encoding="utf-8")
    sec_engine.integrity.create_or_update_baseline(str(tmp_path))

    sample_doc.write_text("versi dimodifikasi peretas!", encoding="utf-8")
    fim_res = sec_engine.integrity.verify_integrity(str(tmp_path), save_changes_to_db=True, is_demo=False)
    assert fim_res.modified_count == 1

    # 3. Jalankan Real-Time System Sweep & Auto-Correlation
    sweep_summary = sec_engine.run_system_sweep(is_demo=False)
    assert sweep_summary.local_ip != ""
    assert sweep_summary.new_correlated_incidents >= 2

    # 4. Verifikasi agregasi metrik dashboard & ekspor laporan
    metrics = monitoring_svc.get_dashboard_metrics(is_demo=False)
    assert metrics["events_total"] >= 2
    assert metrics["incidents_total"] >= 2

    md_report, _ = report_svc.export_markdown(is_demo=False, save_file=False)
    json_report, _ = report_svc.export_json(is_demo=False, save_file=False)
    csv_report, _ = report_svc.export_events_csv(is_demo=False, save_file=False)

    assert "LIVE" in md_report
    assert "PHISHING" in json_report
    assert "PHISHING_URL_DETECTED" in csv_report


def test_offline_demo_mode_isolation(full_system_env) -> None:
    """Memastikan dataset DEMO dimuat secara terpisah tanpa mencemari data LIVE."""
    monitoring_svc: MonitoringService = full_system_env["monitoring"]

    demo_metrics = monitoring_svc.get_dashboard_metrics(is_demo=True)
    live_metrics = monitoring_svc.get_dashboard_metrics(is_demo=False)

    assert demo_metrics["events_total"] >= 4
    assert live_metrics["events_total"] == 0