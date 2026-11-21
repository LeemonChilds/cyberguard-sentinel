"""
CYBERGUARD SENTINEL — Unit & Integration Tests for Module 02 (Network Monitoring Engine)
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import sessionmaker
from core.database import create_db_engine, init_database
from modules.network_monitor import NetworkMonitor


@pytest.fixture
def isolated_net_monitor() -> NetworkMonitor:
    """Menyediakan instance NetworkMonitor dengan database SQLite in-memory."""
    test_engine = create_db_engine("sqlite:///:memory:")
    init_database(custom_engine=test_engine)
    test_session_factory = sessionmaker(
        bind=test_engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )
    return NetworkMonitor(session_factory=test_session_factory)


def test_local_interfaces_detection() -> None:
    """Sistem lokal minimal harus memiliki antarmuka loopback 127.0.0.1."""
    interfaces = NetworkMonitor.get_local_interfaces()
    assert len(interfaces) >= 1
    ips = [i.ipv4_address for i in interfaces]
    assert "127.0.0.1" in ips


def test_live_network_snapshot_capture_and_persistence(
    isolated_net_monitor: NetworkMonitor,
) -> None:
    """Memastikan snapshot jaringan LIVE berhasil diambil dan tersimpan ke SQLite."""
    report = isolated_net_monitor.capture_snapshot(save_to_db=True, is_demo=False)
    assert report.is_demo is False
    assert report.primary_local_ip != ""
    assert 0 <= report.risk_score <= 100

    history = isolated_net_monitor.get_snapshot_history(is_demo=False)
    assert len(history) == 1
    assert history[0]["IP Lokal"] == report.primary_local_ip


def test_demo_network_snapshot_offline_isolation(
    isolated_net_monitor: NetworkMonitor,
) -> None:
    """Memastikan DEMO mode menghasilkan data simulasi terpisah tanpa bercampur dengan LIVE."""
    demo_report = isolated_net_monitor.capture_snapshot(save_to_db=True, is_demo=True)
    assert demo_report.is_demo is True
    assert demo_report.hostname == "DEMO-WORKSTATION-SOC"
    assert demo_report.risk_score == 35
    assert demo_report.severity == "MEDIUM"

    assert len(isolated_net_monitor.get_snapshot_history(is_demo=True)) == 1
    assert len(isolated_net_monitor.get_snapshot_history(is_demo=False)) == 0