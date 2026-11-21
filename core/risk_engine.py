"""
CYBERGUARD SENTINEL — Centralized Risk Scoring Engine

Mengelola kalkulasi skor risiko terstandarisasi (0-100) berdasarkan indikator
heuristik terdokumentasi, mencegah penghitungan ganda (double-counting),
dan memetakan skor ke tingkat keparahan resmi (LOW, MEDIUM, HIGH, CRITICAL).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import config


@dataclass(frozen=True)
class RiskIndicator:
    """Representasi satu indikator temuan keamanan yang dapat diaudit."""

    code: str
    weight: int
    description: str


@dataclass
class RiskAssessmentResult:
    """Hasil evaluasi risiko terpusat beserta rincian alasan."""

    score: int
    severity: str
    indicators: list[RiskIndicator] = field(default_factory=list)
    disclaimer: str = (
        "Skor risiko merupakan indikator heuristik berdasarkan karakteristik teknis, "
        "bukan bukti mutlak terjadinya serangan."
    )

    @property
    def reasons(self) -> list[str]:
        """Mengembalikan daftar penjelasan teknis untuk setiap indikator aktif."""
        return [f"[{ind.code}] (+{ind.weight} poin) {ind.description}" for ind in self.indicators]


def classify_severity(score: int) -> str:
    """Memetakan skor numerik (0-100) ke kategori tingkat keparahan resmi."""
    bounded_score = max(0, min(100, int(score)))
    for level_name, (low, high) in config.RISK_LEVELS.items():
        if low <= bounded_score <= high:
            return level_name
    return "LOW"


def evaluate_risk(indicators: list[RiskIndicator]) -> RiskAssessmentResult:
    """
    Menghitung total skor risiko dari daftar indikator.
    - Melakukan deduplikasi berdasarkan `code` agar kejadian yang sama tidak dihitung ganda.
    - Membatasi skor akhir dalam rentang 0 hingga 100.
    """
    unique_indicators: dict[str, RiskIndicator] = {}
    for indicator in indicators:
        if indicator.weight < 0:
            continue
        if indicator.code not in unique_indicators:
            unique_indicators[indicator.code] = indicator

    deduplicated_list = list(unique_indicators.values())
    raw_total = sum(ind.weight for ind in deduplicated_list)
    final_score = max(0, min(100, raw_total))
    severity = classify_severity(final_score)

    return RiskAssessmentResult(
        score=final_score,
        severity=severity,
        indicators=deduplicated_list,
    )