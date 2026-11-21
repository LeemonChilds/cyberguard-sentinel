"""
CYBERGUARD SENTINEL — Unit & Security Compliance Tests for Module 04 (Password Security Analyzer)
"""

from __future__ import annotations

import logging
import pytest
from core.validators import ValidationError
from modules.password_analyzer import PasswordAnalyzer


def test_weak_common_password_classification() -> None:
    """Kata sandi kamus umum seperti 'password123' wajib terklasifikasi WEAK."""
    analyzer = PasswordAnalyzer()
    result = analyzer.analyze_password("password123")
    assert result.classification == "WEAK"
    assert result.strength_score < 40
    assert any("kamus" in f.lower() for f in result.findings)


def test_strong_passphrase_classification() -> None:
    """Kata sandi panjang dengan 4 jenis karakter acak wajib terklasifikasi VERY STRONG."""
    analyzer = PasswordAnalyzer()
    result = analyzer.analyze_password("Kopi!Pagi#Bali94$Aman")
    assert result.classification == "VERY STRONG"
    assert result.strength_score >= 80
    assert result.has_uppercase is True
    assert result.has_lowercase is True
    assert result.has_digits is True
    assert result.has_symbols is True
    assert result.entropy_bits > 80


def test_sequential_and_repeated_characters_penalized() -> None:
    """Urutan beruntun seperti 'abcd' atau pengulangan '1111' harus dikenakan penalti."""
    analyzer = PasswordAnalyzer()
    res_seq = analyzer.analyze_password("Abcd1234!@#")
    assert any("beruntun" in f.lower() for f in res_seq.findings)

    res_rep = analyzer.analyze_password("Xyz9999!@#Qwe")
    assert any("pengulangan" in f.lower() for f in res_rep.findings)


def test_empty_and_oversized_password_rejected() -> None:
    """Kata sandi kosong atau di atas 128 karakter harus ditolak oleh validator."""
    analyzer = PasswordAnalyzer()
    with pytest.raises(ValidationError):
        analyzer.analyze_password("")

    with pytest.raises(ValidationError):
        analyzer.analyze_password("A" * 129)


def test_zero_storage_and_no_password_in_logs(caplog: pytest.LogCaptureFixture) -> None:
    """
    Memastikan hasil objek dan catatan log TIDAK PERNAH mengandung string kata sandi asli.
    """
    secret_sample = "RahasiaSuperSangatUnik!2026#"
    analyzer = PasswordAnalyzer()

    with caplog.at_level(logging.INFO):
        result = analyzer.analyze_password(secret_sample)

    # Pastikan hasil struct tidak menyimpan atribut password apa pun
    assert not hasattr(result, "password")
    assert secret_sample not in str(result)

    # Pastikan seluruh rekaman log bersih dari string password
    for record in caplog.records:
        assert secret_sample not in record.getMessage()