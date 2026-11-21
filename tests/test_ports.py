"""
CYBERGUARD SENTINEL — Unit & Security Guardrail Tests for Module 05 (Port Security Scanner)
"""

from __future__ import annotations

import socket
import pytest
from sqlalchemy.orm import sessionmaker
from core.database import create_db_engine, init_database
from core.validators import ValidationError
from modules.port_scanner import PortScanner


@pytest.fixture
def isolated_scanner() -> PortScanner:
    """Menyediakan instance PortScanner dengan database SQLite in-memory."""
    test_engine = create_db_engine("sqlite:///:memory:")
    init_database(custom_engine=test_engine)
    test_session_factory = sessionmaker(
        bind=test_engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )
    return PortScanner(session_factory=test_session_factory)


def test_detects_real_open_and_closed_ports_on_localhost(
    isolated_scanner: PortScanner,
) -> None:
    """
    Membuka soket TCP sementara di 127.0.0.1 dan memastikan PortScanner mendeteksinya sebagai OPEN.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        ephemeral_port = listener.getsockname()[1]

        # Pindai rentang 2 port: ephemeral_port (OPEN) dan tetangganya (CLOSED)
        start_p = ephemeral_port
        end_p = min(65535, ephemeral_port + 1)
        if start_p == end_p:
            start_p = ephemeral_port - 1

        report = isolated_scanner.scan_ports(
            target_host="127.0.0.1",
            start_port=start_p,
            end_port=end_p,
            save_to_db=True,
            is_demo=False,
        )

        open_port_numbers = [p.port for p in report.open_ports]
        assert ephemeral_port in open_port_numbers
        assert report.closed_ports_count >= 1
        assert len(isolated_scanner.get_scan_history(is_demo=False)) == 1


def test_public_ip_scanning_strictly_blocked(isolated_scanner: PortScanner) -> None:
    """Pemindaian ke alamat IP publik seperti 8.8.8.8 wajib ditolak."""
    with pytest.raises(ValidationError):
        isolated_scanner.scan_ports(
            target_host="8.8.8.8",
            start_port=80,
            end_port=85,
            explicit_authorization=True,
            save_to_db=False,
        )


def test_private_ip_requires_explicit_authorization(
    isolated_scanner: PortScanner,
) -> None:
    """Pemindaian IP privat selain 127.0.0.1 harus ditolak jika kotak otorisasi tidak dicentang."""
    with pytest.raises(ValidationError):
        isolated_scanner.scan_ports(
            target_host="192.168.1.1",
            start_port=80,
            end_port=82,
            explicit_authorization=False,
            save_to_db=False,
        )


def test_excessive_port_range_rejected(isolated_scanner: PortScanner) -> None:
    """Rentang lebih dari 100 port per sekali pemindaian wajib ditolak."""
    with pytest.raises(ValidationError):
        isolated_scanner.scan_ports(
            target_host="127.0.0.1",
            start_port=1,
            end_port=250,
            save_to_db=False,
        )