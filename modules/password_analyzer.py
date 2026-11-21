"""
CYBERGUARD SENTINEL — Password Security Analyzer Engine (Module 04)

Menganalisis kekuatan kata sandi secara lokal:
- Analisis panjang & entropi informasi (bits)
- Keragaman karakter (huruf kecil, huruf besar, angka, simbol)
- Deteksi kata sandi umum, pola berurutan, dan pola papan ketik (keyboard walk)
- Prinsip Zero-Storage: Tidak pernah menyimpan, mencatat, atau mengirim kata sandi
"""

from __future__ import annotations

from dataclasses import dataclass, field
import math
import re
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import sessionmaker
from core.database import get_db_session
from core.logger import get_logger
from database.models import SecurityEvent

logger = get_logger("cyberguard.password")

COMMON_WEAK_PASSWORDS = {
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "password",
    "password1",
    "password123",
    "passw0rd",
    "qwerty",
    "qwerty123",
    "qwertyuiop",
    "admin",
    "admin123",
    "administrator",
    "welcome",
    "iloveyou",
    "letmein",
    "monkey",
    "dragon",
    "abc123",
    "abc12345",
    "111111",
    "000000",
    "rahasia",
    "rahasia123",
    "indonesia",
    "indonesia123",
    "bismillah",
    "sayang",
    "aku123",
    "user123",
    "guest",
    "sekolah",
    "siswa123",
    "guru123",
}

SEQUENTIAL_PATTERNS = (
    "0123",
    "1234",
    "2345",
    "3456",
    "4567",
    "5678",
    "6789",
    "7890",
    "abcd",
    "bcde",
    "cdef",
    "defg",
    "efgh",
    "qwer",
    "wert",
    "erty",
    "asdf",
    "sdfg",
    "zxcv",
    "xcvb",
)


@dataclass
class PasswordAnalysisResult:
    length: int
    score: int  # 0 (sangat lemah) - 100 (sangat kuat)
    risk_score: int  # 0 (aman) - 100 (risiko kritis)
    strength: str  # VERY WEAK | WEAK | MODERATE | STRONG | VERY STRONG
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    entropy_bits: float
    crack_time_display: str
    has_lowercase: bool
    has_uppercase: bool
    has_digits: bool
    has_symbols: bool
    lowercase_count: int
    uppercase_count: int
    digit_count: int
    symbol_count: int
    is_common_password: bool
    criteria_checks: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    # Alias kompatibilitas mundur agar kode UI/pengujian lama tetap berjalan tanpa AttributeError
    @property
    def strength_label(self) -> str:
        return self.strength

    @property
    def strength_score(self) -> int:
        return self.score

    @property
    def entropy(self) -> float:
        return self.entropy_bits

    @property
    def crack_time(self) -> str:
        return self.crack_time_display

    @property
    def feedback(self) -> List[str]:
        return self.findings

    @property
    def is_common(self) -> bool:
        return self.is_common_password


class PasswordAnalyzer:
    """Mesin analisis kekuatan kata sandi lokal dengan jaminan Zero-Storage."""

    def __init__(self, session_factory: Optional[sessionmaker] = None) -> None:
        self.session_factory = session_factory

    @staticmethod
    def _estimate_crack_time(entropy_bits: float) -> str:
        """Memperkirakan waktu brute-force offline (asumsi 10 miliar tebakan/detik GPU modern)."""
        if entropy_bits <= 0:
            return "Instan (kurang dari 1 detik)"
        guesses = 2 ** min(entropy_bits, 128.0)
        seconds = guesses / 1e10
        if seconds < 1:
            return "Instan (kurang dari 1 detik)"
        if seconds < 60:
            return f"{int(seconds)} detik"
        minutes = seconds / 60
        if minutes < 60:
            return f"{int(minutes)} menit"
        hours = minutes / 60
        if hours < 24:
            return f"{int(hours)} jam"
        days = hours / 24
        if days < 365:
            return f"{int(days)} hari"
        years = days / 365.25
        if years < 1_000:
            return f"{int(years)} tahun"
        if years < 1_000_000:
            return f"{years / 1_000:.1f} ribu tahun"
        if years < 1_000_000_000:
            return f"{years / 1_000_000:.1f} juta tahun"
        return "Miliaran tahun (sangat sulit diretas brute-force)"

    def analyze(
        self,
        password: str,
        save_metadata_to_db: bool = True,
        is_demo: bool = False,
    ) -> PasswordAnalysisResult:
        """
        Mengevaluasi kekuatan kata sandi secara lokal tanpa menyimpan atau mencatat isi kata sandi.
        """
        if not isinstance(password, str) or len(password) == 0:
            raise ValueError("Kata sandi tidak boleh kosong.")

        candidate = password
        try:
            length = len(candidate)
            lowered = candidate.lower()

            lowercase_count = sum(1 for ch in candidate if ch.islower())
            uppercase_count = sum(1 for ch in candidate if ch.isupper())
            digit_count = sum(1 for ch in candidate if ch.isdigit())
            symbol_count = sum(1 for ch in candidate if not ch.isalnum())

            has_lowercase = lowercase_count > 0
            has_uppercase = uppercase_count > 0
            has_digits = digit_count > 0
            has_symbols = symbol_count > 0

            pool_size = 0
            if has_lowercase:
                pool_size += 26
            if has_uppercase:
                pool_size += 26
            if has_digits:
                pool_size += 10
            if has_symbols:
                pool_size += 32

            entropy_bits = round(length * math.log2(pool_size), 1) if pool_size > 0 else 0.0
            crack_time_display = self._estimate_crack_time(entropy_bits)

            findings: List[str] = []
            recommendations: List[str] = []
            score = 0

            # 1. Penilaian Panjang
            if length >= 16:
                score += 35
            elif length >= 12:
                score += 28
            elif length >= 8:
                score += 16
                findings.append("Panjang kata sandi masih di batas minimum (8-11 karakter).")
                recommendations.append("Perpanjang kata sandi menjadi minimal 12 hingga 16 karakter.")
            else:
                score += 5
                findings.append(f"Kata sandi terlalu pendek ({length} karakter); sangat rentan terhadap serangan brute-force.")
                recommendations.append("Gunakan minimal 12 karakter atau susun passphrase 3-4 kata acak.")

            # 2. Penilaian Keragaman Karakter
            diversity_count = sum([has_lowercase, has_uppercase, has_digits, has_symbols])
            score += diversity_count * 10  # Maksimal +40 poin

            if not has_uppercase:
                findings.append("Tidak mengandung huruf kapital (A-Z).")
                recommendations.append("Tambahkan kombinasi huruf kapital di tengah atau akhir kata.")
            if not has_lowercase:
                findings.append("Tidak mengandung huruf kecil (a-z).")
                recommendations.append("Kombinasikan huruf kecil agar ruang pencarian karakter lebih luas.")
            if not has_digits:
                findings.append("Tidak mengandung angka (0-9).")
                recommendations.append("Sisipkan angka acak (hindari tanggal lahir atau urutan 123).")
            if not has_symbols:
                findings.append("Tidak mengandung simbol khusus (!@#$%^&*).")
                recommendations.append("Tambahkan karakter simbol khusus seperti '@', '#', '!', atau '_'.")

            # 3. Bonus Entropi
            if entropy_bits >= 75:
                score += 25
            elif entropy_bits >= 55:
                score += 18
            elif entropy_bits >= 40:
                score += 10

            # 4. Deteksi Kata Sandi Umum & Pola Lemah
            is_common = lowered in COMMON_WEAK_PASSWORDS
            if is_common:
                score = min(score, 10)
                findings.append("Kata sandi termasuk dalam daftar kata sandi paling umum dan langsung tertebak oleh kamus peretas.")
                recommendations.append("Segera ganti kata sandi ini; jangan pernah memakai kata sandi populer.")

            has_sequence = any(seq in lowered for seq in SEQUENTIAL_PATTERNS)
            if has_sequence:
                score -= 15
                findings.append("Terdeteksi pola karakter/angka berurutan atau urutan tombol keyboard (misalnya '1234' atau 'qwer').")
                recommendations.append("Hindari urutan angka atau huruf yang berdekatan di keyboard.")

            if re.search(r"(.)\1{2,}", candidate):
                score -= 12
                findings.append("Terdeteksi pengulangan karakter identik 3 kali atau lebih secara beruntun.")
                recommendations.append("Hindari pengulangan karakter yang sama secara berurutan.")

            if re.search(r"(19\d{2}|20[0-2]\d)", candidate):
                score -= 8
                findings.append("Terdeteksi pola tahun kalender (seperti 199x atau 202x) yang mudah ditebak.")
                recommendations.append("Ganti angka tahun dengan kombinasi angka acak yang tidak terkait identitas pribadi.")

            score = max(0, min(100, score))
            risk_score = 100 - score

            if score >= 85:
                strength = "VERY STRONG"
                severity = "LOW"
            elif score >= 68:
                strength = "STRONG"
                severity = "LOW"
            elif score >= 45:
                strength = "MODERATE"
                severity = "MEDIUM"
            elif score >= 25:
                strength = "WEAK"
                severity = "HIGH"
            else:
                strength = "VERY WEAK"
                severity = "CRITICAL"

            if not findings:
                findings.append("Tidak ditemukan kelemahan pola umum; komposisi karakter dan panjang sudah kuat.")
            if not recommendations:
                recommendations.append("Pertahankan kata sandi unik ini untuk satu akun saja dan aktifkan Autentikasi Dua Faktor (2FA).")

            criteria_checks = [
                {"Kriteria Keamanan": "Panjang Minimal 12 Karakter", "Status": "✅ Terpenuhi" if length >= 12 else "❌ Belum", "Detail": f"{length} karakter"},
                {"Kriteria Keamanan": "Huruf Kecil (a-z)", "Status": "✅ Ada" if has_lowercase else "❌ Tidak Ada", "Detail": f"{lowercase_count} karakter"},
                {"Kriteria Keamanan": "Huruf Kapital (A-Z)", "Status": "✅ Ada" if has_uppercase else "❌ Tidak Ada", "Detail": f"{uppercase_count} karakter"},
                {"Kriteria Keamanan": "Angka (0-9)", "Status": "✅ Ada" if has_digits else "❌ Tidak Ada", "Detail": f"{digit_count} karakter"},
                {"Kriteria Keamanan": "Simbol Khusus (!@#$...)", "Status": "✅ Ada" if has_symbols else "❌ Tidak Ada", "Detail": f"{symbol_count} karakter"},
                {"Kriteria Keamanan": "Bebas Kata Sandi Umum & Pola Urut", "Status": "✅ Aman" if (not is_common and not has_sequence) else "⚠️ Terdeteksi Pola Lemah", "Detail": "Pemeriksaan kamus & urutan lokal"},
            ]

            result = PasswordAnalysisResult(
                length=length,
                score=score,
                risk_score=risk_score,
                strength=strength,
                severity=severity,
                entropy_bits=entropy_bits,
                crack_time_display=crack_time_display,
                has_lowercase=has_lowercase,
                has_uppercase=has_uppercase,
                has_digits=has_digits,
                has_symbols=has_symbols,
                lowercase_count=lowercase_count,
                uppercase_count=uppercase_count,
                digit_count=digit_count,
                symbol_count=symbol_count,
                is_common_password=is_common,
                criteria_checks=criteria_checks,
                findings=findings,
                recommendations=recommendations,
            )

            if save_metadata_to_db:
                self._record_anonymized_audit(result, is_demo=is_demo)

            return result
        finally:
            del candidate

    def analyze_password(
        self,
        password: str,
        save_metadata_to_db: bool = True,
        is_demo: bool = False,
    ) -> PasswordAnalysisResult:
        return self.analyze(password=password, save_metadata_to_db=save_metadata_to_db, is_demo=is_demo)

    def _record_anonymized_audit(self, result: PasswordAnalysisResult, is_demo: bool = False) -> None:
        """Mencatat metadata statistik tanpa pernah menyimpan isi kata sandi."""
        try:
            with get_db_session(self.session_factory) as session:
                session.add(
                    SecurityEvent(
                        source_module="PASSWORD_ANALYZER",
                        event_type=f"PASSWORD_AUDIT_{result.strength.replace(' ', '_')}",
                        severity=result.severity,
                        risk_score=result.risk_score,
                        description=(
                            f"Audit kekuatan kata sandi lokal selesai -> Klasifikasi: {result.strength} "
                            f"(Skor: {result.score}/100, Panjang: {result.length} karakter, Entropi: {result.entropy_bits} bits)."
                        ),
                        is_demo=is_demo,
                    )
                )
        except Exception as exc:
            logger.debug("Pencatatan metadata audit password dilewati: %s", exc)