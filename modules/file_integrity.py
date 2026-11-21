"""
CYBERGUARD SENTINEL — Module 03: File Integrity Monitor (SHA-256)

Mendeteksi perubahan, penambahan, dan penghapusan file secara kriptografis
menggunakan perbandingan sidik jari SHA-256 terhadap baseline tersimpan.
Status Resmi: UNCHANGED, MODIFIED, NEW FILE, DELETED FILE.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from sqlalchemy import desc, select
from sqlalchemy.orm import sessionmaker
import config
from core.database import get_db_session
from core.logger import get_logger
from core.risk_engine import RiskIndicator, evaluate_risk
from core.validators import ValidationError, validate_local_path
from database.models import FileBaseline, FileChange, SecurityEvent

logger = get_logger("cyberguard.integrity")

MAX_FILES_PER_DIRECTORY: int = 500
HASH_CHUNK_SIZE: int = 65536  # 64 KB


@dataclass
class FileIntegrityItem:
    """Detail hasil audit integritas untuk satu file."""

    file_path: str
    status: str  # UNCHANGED, MODIFIED, NEW FILE, DELETED FILE
    old_hash: Optional[str]
    new_hash: Optional[str]
    file_size: int
    risk_score: int


@dataclass
class IntegrityAuditReport:
    """Ringkasan hasil pemindaian integritas pada target file atau folder."""

    target_path: str
    total_scanned: int
    unchanged_count: int
    modified_count: int
    new_file_count: int
    deleted_file_count: int
    overall_risk_score: int
    severity: str
    items: list[FileIntegrityItem] = field(default_factory=list)


class FileIntegrityMonitor:
    """Mesin pemantau integritas file berbasis hash SHA-256."""

    def __init__(self, session_factory: Optional[sessionmaker] = None) -> None:
        self._session_factory = session_factory

    @staticmethod
    def compute_sha256(file_path: Path) -> str:
        """Menghitung hash SHA-256 dari sebuah file secara efisien menggunakan chunk 64KB."""
        sha256_hash = hashlib.sha256()
        with file_path.open("rb") as f:
            while True:
                chunk = f.read(HASH_CHUNK_SIZE)
                if not chunk:
                    break
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    @staticmethod
    def _collect_target_files(resolved_path: Path) -> list[Path]:
        """Mengumpulkan daftar file valid dari sebuah file tunggal atau direktori."""
        if resolved_path.is_file():
            return [resolved_path]

        collected: list[Path] = []
        for item in sorted(resolved_path.rglob("*")):
            if item.is_file():
                collected.append(item)
                if len(collected) >= MAX_FILES_PER_DIRECTORY:
                    logger.warning(
                        "Batas pemindaian tercapai (%d file) pada direktori: %s",
                        MAX_FILES_PER_DIRECTORY,
                        resolved_path,
                    )
                    break
        return collected

    def create_or_update_baseline(self, raw_target_path: str) -> int:
        """
        Menghitung ulang dan menyimpan baseline SHA-256 resmi untuk file atau folder target.
        Mengembalikan jumlah file yang berhasil direkam ke baseline.
        """
        resolved_target = validate_local_path(raw_target_path, must_exist=True)
        files = self._collect_target_files(resolved_target)

        if not files:
            raise ValidationError("Direktori target kosong; tidak ada file untuk dijadikan baseline.")

        recorded_count = 0
        with get_db_session(self._session_factory) as session:
            # Jika target adalah direktori, arsipkan baseline lama di dalam folder tersebut
            # yang file fisiknya sudah tidak ada agar baseline bersih
            if resolved_target.is_dir():
                prefix_str = str(resolved_target)
                existing_baselines = session.scalars(
                    select(FileBaseline).where(FileBaseline.status == "ACTIVE")
                ).all()
                current_paths_set = {str(f) for f in files}
                for b in existing_baselines:
                    b_path = Path(b.target_path)
                    if (
                        resolved_target in b_path.parents
                        and b.target_path not in current_paths_set
                    ):
                        b.status = "ARCHIVED"

            for file_item in files:
                file_hash = self.compute_sha256(file_item)
                file_size = file_item.stat().st_size
                path_str = str(file_item)

                existing = session.scalar(
                    select(FileBaseline).where(FileBaseline.target_path == path_str)
                )
                if existing:
                    existing.sha256_hash = file_hash
                    existing.file_size = file_size
                    existing.status = "ACTIVE"
                else:
                    new_baseline = FileBaseline(
                        target_path=path_str,
                        sha256_hash=file_hash,
                        file_size=file_size,
                        status="ACTIVE",
                    )
                    session.add(new_baseline)
                recorded_count += 1

        logger.info(
            "Baseline SHA-256 diperbarui | target=%s | total_files=%d",
            resolved_target,
            recorded_count,
        )
        return recorded_count

    def verify_integrity(
        self,
        raw_target_path: str,
        save_changes_to_db: bool = True,
        is_demo: bool = False,
    ) -> IntegrityAuditReport:
        """
        Membandingkan kondisi file terkini dengan baseline SHA-256 yang tersimpan.
        """
        resolved_target = validate_local_path(raw_target_path, must_exist=True)
        current_files = self._collect_target_files(resolved_target)
        current_map: dict[str, Path] = {str(f): f for f in current_files}

        items: list[FileIntegrityItem] = []
        indicators: list[RiskIndicator] = []

        with get_db_session(self._session_factory) as session:
            all_active_baselines = session.scalars(
                select(FileBaseline).where(FileBaseline.status == "ACTIVE")
            ).all()

            # Filter baseline yang relevan dengan target_path
            relevant_baselines: dict[str, FileBaseline] = {}
            for b in all_active_baselines:
                b_path = Path(b.target_path)
                if resolved_target.is_file() and b_path == resolved_target:
                    relevant_baselines[b.target_path] = b
                elif resolved_target.is_dir() and resolved_target in b_path.parents:
                    relevant_baselines[b.target_path] = b

            if not relevant_baselines:
                raise ValidationError(
                    "Belum ada baseline SHA-256 untuk target ini. Silakan klik 'Buat / Perbarui Baseline' terlebih dahulu."
                )

            # 1. Periksa setiap file yang saat ini ada di disk
            for path_str, file_obj in current_map.items():
                current_hash = self.compute_sha256(file_obj)
                current_size = file_obj.stat().st_size

                if path_str in relevant_baselines:
                    baseline = relevant_baselines[path_str]
                    if current_hash == baseline.sha256_hash:
                        items.append(
                            FileIntegrityItem(
                                file_path=path_str,
                                status="UNCHANGED",
                                old_hash=baseline.sha256_hash,
                                new_hash=current_hash,
                                file_size=current_size,
                                risk_score=0,
                            )
                        )
                    else:
                        items.append(
                            FileIntegrityItem(
                                file_path=path_str,
                                status="MODIFIED",
                                old_hash=baseline.sha256_hash,
                                new_hash=current_hash,
                                file_size=current_size,
                                risk_score=75,
                            )
                        )
                        indicators.append(
                            RiskIndicator(
                                code="FIM-MODIFIED",
                                weight=75,
                                description=f"Hash SHA-256 berubah pada file: {file_obj.name}",
                            )
                        )
                        if save_changes_to_db:
                            session.add(
                                FileChange(
                                    baseline_id=baseline.id,
                                    file_path=path_str,
                                    change_type="MODIFIED",
                                    old_hash=baseline.sha256_hash,
                                    new_hash=current_hash,
                                    risk_score=75,
                                )
                            )
                            session.add(
                                SecurityEvent(
                                    event_type="FILE_INTEGRITY_MODIFIED",
                                    source_module="FILE_INTEGRITY_MONITOR",
                                    severity="HIGH",
                                    risk_score=75,
                                    description=f"Modifikasi tidak terotorisasi terdeteksi pada '{file_obj.name}'.",
                                    is_demo=is_demo,
                                )
                            )
                else:
                    # File baru yang tidak ada saat baseline dibuat
                    items.append(
                        FileIntegrityItem(
                            file_path=path_str,
                            status="NEW FILE",
                            old_hash=None,
                            new_hash=current_hash,
                            file_size=current_size,
                            risk_score=45,
                        )
                    )
                    indicators.append(
                        RiskIndicator(
                            code="FIM-NEW-FILE",
                            weight=45,
                            description=f"File baru tidak terdaftar ditemukan: {file_obj.name}",
                        )
                    )
                    if save_changes_to_db:
                        session.add(
                            FileChange(
                                baseline_id=None,
                                file_path=path_str,
                                change_type="NEW FILE",
                                old_hash=None,
                                new_hash=current_hash,
                                risk_score=45,
                            )
                        )
                        session.add(
                            SecurityEvent(
                                event_type="FILE_INTEGRITY_NEW_FILE",
                                source_module="FILE_INTEGRITY_MONITOR",
                                severity="MEDIUM",
                                risk_score=45,
                                description=f"File baru terdeteksi di direktori terpantau: '{file_obj.name}'.",
                                is_demo=is_demo,
                            )
                        )

            # 2. Periksa file yang ada di baseline tetapi hilang dari disk (DELETED FILE)
            for path_str, baseline in relevant_baselines.items():
                if path_str not in current_map:
                    deleted_name = Path(path_str).name
                    items.append(
                        FileIntegrityItem(
                            file_path=path_str,
                            status="DELETED FILE",
                            old_hash=baseline.sha256_hash,
                            new_hash=None,
                            file_size=0,
                            risk_score=70,
                        )
                    )
                    indicators.append(
                        RiskIndicator(
                            code="FIM-DELETED-FILE",
                            weight=70,
                            description=f"File baseline hilang/dihapus: {deleted_name}",
                        )
                    )
                    if save_changes_to_db:
                        session.add(
                            FileChange(
                                baseline_id=baseline.id,
                                file_path=path_str,
                                change_type="DELETED FILE",
                                old_hash=baseline.sha256_hash,
                                new_hash=None,
                                risk_score=70,
                            )
                        )
                        session.add(
                            SecurityEvent(
                                event_type="FILE_INTEGRITY_DELETED",
                                source_module="FILE_INTEGRITY_MONITOR",
                                severity="HIGH",
                                risk_score=70,
                                description=f"File baseline dihapus dari direktori terpantau: '{deleted_name}'.",
                                is_demo=is_demo,
                            )
                        )

        risk_eval = evaluate_risk(indicators)

        unchanged_cnt = sum(1 for i in items if i.status == "UNCHANGED")
        modified_cnt = sum(1 for i in items if i.status == "MODIFIED")
        new_cnt = sum(1 for i in items if i.status == "NEW FILE")
        deleted_cnt = sum(1 for i in items if i.status == "DELETED FILE")

        logger.info(
            "Audit integritas selesai | target=%s | unchanged=%d | modified=%d | new=%d | deleted=%d",
            resolved_target,
            unchanged_cnt,
            modified_cnt,
            new_cnt,
            deleted_cnt,
        )

        return IntegrityAuditReport(
            target_path=str(resolved_target),
            total_scanned=len(items),
            unchanged_count=unchanged_cnt,
            modified_count=modified_cnt,
            new_file_count=new_cnt,
            deleted_file_count=deleted_cnt,
            overall_risk_score=risk_eval.score,
            severity=risk_eval.severity,
            items=items,
        )

    def get_active_baselines(self, limit: int = 30) -> list[dict]:
        """Mengambil daftar baseline SHA-256 aktif dari database."""
        with get_db_session(self._session_factory) as session:
            stmt = (
                select(FileBaseline)
                .where(FileBaseline.status == "ACTIVE")
                .order_by(desc(FileBaseline.updated_at))
                .limit(limit)
            )
            rows = session.scalars(stmt).all()
            return [
                {
                    "File": Path(r.target_path).name,
                    "SHA-256 Fingerprint": r.sha256_hash,
                    "Ukuran (Bytes)": r.file_size,
                    "Diperbarui (UTC)": r.updated_at.strftime("%Y-%m-%d %H:%M:%S")
                    if r.updated_at
                    else "-",
                    "Path Lengkap": r.target_path,
                }
                for r in rows
            ]

    def get_recent_changes(self, limit: int = 20) -> list[dict]:
        """Mengambil riwayat deteksi perubahan file dari database."""
        with get_db_session(self._session_factory) as session:
            stmt = (
                select(FileChange)
                .order_by(desc(FileChange.detected_at), desc(FileChange.id))
                .limit(limit)
            )
            rows = session.scalars(stmt).all()
            return [
                {
                    "Waktu Deteksi (UTC)": r.detected_at.strftime("%Y-%m-%d %H:%M:%S")
                    if r.detected_at
                    else "-",
                    "Status": r.change_type,
                    "Nama File": Path(r.file_path).name,
                    "Hash Lama (Prefix)": (r.old_hash[:16] + "...") if r.old_hash else "-",
                    "Hash Baru (Prefix)": (r.new_hash[:16] + "...") if r.new_hash else "-",
                    "Skor Risiko": r.risk_score,
                }
                for r in rows
            ]

    @staticmethod
    def prepare_demo_sandbox() -> Path:
        """
        Menyiapkan folder sandbox aman di dalam data/integrity_sandbox
        untuk demonstrasi pengujian integritas file tanpa menyentuh file pribadi pengguna.
        """
        sandbox_dir = config.DATA_DIR / "integrity_sandbox"
        sandbox_dir.mkdir(parents=True, exist_ok=True)

        doc_a = sandbox_dir / "kebijakan_keamanan.txt"
        doc_b = sandbox_dir / "konfigurasi_server.json"

        doc_a.write_text(
            "DOKUMEN RESMI KEBIJAKAN KEAMANAN SEKOLAH\nVersi: 1.0\nStatus: Terverifikasi.\n",
            encoding="utf-8",
        )
        doc_b.write_text(
            '{\n  "server": "localhost",\n  "firewall": "ENABLED",\n  "audit": true\n}\n',
            encoding="utf-8",
        )
        return sandbox_dir
    