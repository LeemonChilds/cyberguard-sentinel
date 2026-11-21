"""
CYBERGUARD SENTINEL — Module 06: Security Incident Analyzer

Mengelola siklus hidup insiden keamanan SOC:
- Pembuatan & kategorisasi insiden (PHISHING, NETWORK ANOMALY, FILE MODIFICATION,
  AUTHENTICATION ANOMALY, PORT EXPOSURE).
- Manajemen status (OPEN, INVESTIGATING, CONTAINED, RESOLVED).
- Korelasi otomatis SecurityEvent menjadi tiket SecurityIncident terstruktur.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from sqlalchemy import desc, select
from sqlalchemy.orm import sessionmaker
import config
from core.database import get_db_session
from core.logger import get_logger
from core.risk_engine import classify_severity
from core.validators import ValidationError, sanitize_text_input
from database.models import SecurityEvent, SecurityIncident

logger = get_logger("cyberguard.incidents")


@dataclass
class IncidentRecordDTO:
    """Data Transfer Object ringkas untuk menampilkan informasi insiden di layanan & UI."""

    id: int
    title: str
    category: str
    severity: str
    status: str
    mitigation_notes: str
    correlated_events_count: int
    is_demo: bool
    created_at: str
    updated_at: str


class SecurityIncidentAnalyzer:
    """Mesin analisis, korelasi, dan manajemen siklus hidup insiden keamanan."""

    DEFAULT_MITIGATION_PLAYBOOKS: dict[str, str] = {
        "PHISHING": (
            "1. Blokir domain/URL mencurigakan pada DNS/Web Filter lokal.\n"
            "2. Peringatkan pengguna agar tidak memasukkan kredensial pada tautan tersebut.\n"
            "3. Lakukan reset kata sandi segera jika pengguna terlanjur berinteraksi dengan situs."
        ),
        "NETWORK ANOMALY": (
            "1. Identifikasi proses lokal (PID) yang membuka koneksi mencurigakan.\n"
            "2. Putuskan koneksi jaringan tidak sah dan periksa aturan Windows Defender Firewall.\n"
            "3. Lakukan pemindaian integritas file pada direktori kerja terkait."
        ),
        "FILE MODIFICATION": (
            "1. Bandingkan isi file yang berubah dengan salinan cadangan (backup) resmi.\n"
            "2. Investigasi proses atau akun yang melakukan perubahan di luar jadwal pemeliharaan.\n"
            "3. Pulihkan file asli dan perbarui baseline SHA-256 setelah diverifikasi aman."
        ),
        "AUTHENTICATION ANOMALY": (
            "1. Periksa log percobaan login gagal berulang dan sumber alamat IP.\n"
            "2. Terapkan kebijakan kata sandi kuat (minimal 12 karakter kompleks) dan aktifkan MFA.\n"
            "3. Nonaktifkan sementara akun yang terindikasi mengalami serangan brute-force."
        ),
        "PORT EXPOSURE": (
            "1. Identifikasi layanan yang mendengarkan pada port terbuka melalui netstat/Resource Monitor.\n"
            "2. Tutup layanan yang tidak diperlukan atau ikat layanan hanya ke 127.0.0.1.\n"
            "3. Terapkan aturan blokir koneksi masuk pada Windows Defender Firewall."
        ),
    }

    EVENT_TO_CATEGORY_MAP: dict[str, str] = {
        "PHISHING_URL_DETECTED": "PHISHING",
        "NETWORK_ANOMALY_DETECTED": "NETWORK ANOMALY",
        "FILE_INTEGRITY_MODIFIED": "FILE MODIFICATION",
        "FILE_INTEGRITY_NEW_FILE": "FILE MODIFICATION",
        "FILE_INTEGRITY_DELETED": "FILE MODIFICATION",
        "PORT_EXPOSURE_DETECTED": "PORT EXPOSURE",
    }

    def __init__(self, session_factory: Optional[sessionmaker] = None) -> None:
        self._session_factory = session_factory

    @classmethod
    def validate_category(cls, category: str) -> str:
        """Memastikan kategori insiden termasuk dalam daftar resmi."""
        if not category or not isinstance(category, str):
            raise ValidationError("Kategori insiden tidak boleh kosong.")
        upper_cat = category.strip().upper()
        if upper_cat not in config.INCIDENT_CATEGORIES:
            raise ValidationError(
                f"Kategori '{category}' tidak valid. Pilihan resmi: {config.INCIDENT_CATEGORIES}"
            )
        return upper_cat

    @classmethod
    def validate_status(cls, status: str) -> str:
        """Memastikan status insiden termasuk dalam siklus hidup resmi."""
        if not status or not isinstance(status, str):
            raise ValidationError("Status insiden tidak boleh kosong.")
        upper_status = status.strip().upper()
        if upper_status not in config.INCIDENT_STATUSES:
            raise ValidationError(
                f"Status '{status}' tidak valid. Pilihan resmi: {config.INCIDENT_STATUSES}"
            )
        return upper_status

    @classmethod
    def validate_severity(cls, severity: str) -> str:
        """Memastikan tingkat keparahan termasuk dalam standar LOW/MEDIUM/HIGH/CRITICAL."""
        if not severity or not isinstance(severity, str):
            raise ValidationError("Severity insiden tidak boleh kosong.")
        upper_sev = severity.strip().upper()
        if upper_sev not in config.RISK_LEVELS:
            raise ValidationError(
                f"Severity '{severity}' tidak valid. Pilihan resmi: {tuple(config.RISK_LEVELS.keys())}"
            )
        return upper_sev

    def get_recommended_mitigation(self, category: str) -> str:
        """Mengembalikan playbook langkah mitigasi standar berdasarkan kategori."""
        valid_cat = self.validate_category(category)
        return self.DEFAULT_MITIGATION_PLAYBOOKS.get(
            valid_cat,
            "Lakukan isolasi komponen terdampak, dokumentasikan bukti log, dan terapkan pembaruan keamanan.",
        )

    def create_incident(
        self,
        title: str,
        category: str,
        severity: str,
        mitigation_notes: Optional[str] = None,
        is_demo: bool = False,
        event_ids_to_link: Optional[list[int]] = None,
    ) -> IncidentRecordDTO:
        """Membuat tiket insiden keamanan baru dan menautkan SecurityEvent terkait jika ada."""
        clean_title = sanitize_text_input(title, max_length=200)
        if len(clean_title) < 5:
            raise ValidationError("Judul insiden minimal terdiri dari 5 karakter.")

        valid_category = self.validate_category(category)
        valid_severity = self.validate_severity(severity)

        clean_notes = sanitize_text_input(mitigation_notes or "", max_length=2000)
        if not clean_notes:
            clean_notes = self.get_recommended_mitigation(valid_category)

        with get_db_session(self._session_factory) as session:
            incident = SecurityIncident(
                title=clean_title,
                category=valid_category,
                severity=valid_severity,
                status="OPEN",
                mitigation_notes=clean_notes,
                is_demo=is_demo,
            )
            session.add(incident)
            session.flush()  # Dapatkan incident.id sebelum commit

            linked_count = 0
            if event_ids_to_link:
                stmt = select(SecurityEvent).where(SecurityEvent.id.in_(event_ids_to_link))
                events = session.scalars(stmt).all()
                for ev in events:
                    ev.incident_id = incident.id
                    linked_count += 1

            logger.info(
                "Insiden keamanan dibuat | id=%d | category=%s | severity=%s | linked_events=%d | demo=%s",
                incident.id,
                incident.category,
                incident.severity,
                linked_count,
                is_demo,
            )

            return IncidentRecordDTO(
                id=incident.id,
                title=incident.title,
                category=incident.category,
                severity=incident.severity,
                status=incident.status,
                mitigation_notes=incident.mitigation_notes or "",
                correlated_events_count=linked_count,
                is_demo=incident.is_demo,
                created_at=incident.created_at.strftime("%Y-%m-%d %H:%M:%S")
                if incident.created_at
                else "-",
                updated_at=incident.updated_at.strftime("%Y-%m-%d %H:%M:%S")
                if incident.updated_at
                else "-",
            )

    def update_incident_status(
        self,
        incident_id: int,
        new_status: str,
        additional_notes: Optional[str] = None,
    ) -> IncidentRecordDTO:
        """Memperbarui status siklus hidup insiden dan menambahkan catatan investigasi."""
        valid_status = self.validate_status(new_status)
        clean_extra = sanitize_text_input(additional_notes or "", max_length=1500)

        with get_db_session(self._session_factory) as session:
            incident = session.scalar(
                select(SecurityIncident).where(SecurityIncident.id == incident_id)
            )
            if not incident:
                raise ValidationError(f"Insiden dengan ID #{incident_id} tidak ditemukan.")

            old_status = incident.status
            incident.status = valid_status

            if clean_extra:
                existing_notes = incident.mitigation_notes or ""
                separator = "\n\n" if existing_notes else ""
                incident.mitigation_notes = (
                    f"{existing_notes}{separator}[Update -> {valid_status}]: {clean_extra}"
                )

            session.flush()
            events_count = len(incident.events)

            logger.info(
                "Status insiden diperbarui | id=%d | %s -> %s",
                incident.id,
                old_status,
                valid_status,
            )

            return IncidentRecordDTO(
                id=incident.id,
                title=incident.title,
                category=incident.category,
                severity=incident.severity,
                status=incident.status,
                mitigation_notes=incident.mitigation_notes or "",
                correlated_events_count=events_count,
                is_demo=incident.is_demo,
                created_at=incident.created_at.strftime("%Y-%m-%d %H:%M:%S")
                if incident.created_at
                else "-",
                updated_at=incident.updated_at.strftime("%Y-%m-%d %H:%M:%S")
                if incident.updated_at
                else "-",
            )

    def correlate_unlinked_events(self, is_demo: bool = False) -> list[IncidentRecordDTO]:
        """
        Mengkorelasikan seluruh SecurityEvent yang belum tertaut ke insiden (incident_id IS NULL)
        berdasarkan kategori ancaman, lalu membuat tiket SecurityIncident terpadu.
        """
        created_incidents: list[IncidentRecordDTO] = []

        with get_db_session(self._session_factory) as session:
            stmt = (
                select(SecurityEvent)
                .where(
                    SecurityEvent.is_demo == is_demo,
                    SecurityEvent.incident_id.is_(None),
                )
                .order_by(SecurityEvent.created_at)
            )
            unlinked_events = session.scalars(stmt).all()

            if not unlinked_events:
                return []

            # Kelompokkan event berdasarkan kategori insiden
            grouped: dict[str, list[SecurityEvent]] = {}
            for ev in unlinked_events:
                mapped_cat = self.EVENT_TO_CATEGORY_MAP.get(
                    ev.event_type, "NETWORK ANOMALY"
                )
                grouped.setdefault(mapped_cat, []).append(ev)

            for category, ev_list in grouped.items():
                max_score = max(e.risk_score for e in ev_list)
                overall_sev = classify_severity(max_score)
                title = (
                    f"Korelasi Otomatis: {len(ev_list)} Kejadian {category} Terdeteksi"
                )
                playbook = self.get_recommended_mitigation(category)

                incident = SecurityIncident(
                    title=title,
                    category=category,
                    severity=overall_sev,
                    status="OPEN",
                    mitigation_notes=playbook,
                    is_demo=is_demo,
                )
                session.add(incident)
                session.flush()

                for ev in ev_list:
                    ev.incident_id = incident.id

                created_incidents.append(
                    IncidentRecordDTO(
                        id=incident.id,
                        title=incident.title,
                        category=incident.category,
                        severity=incident.severity,
                        status=incident.status,
                        mitigation_notes=incident.mitigation_notes or "",
                        correlated_events_count=len(ev_list),
                        is_demo=incident.is_demo,
                        created_at=incident.created_at.strftime("%Y-%m-%d %H:%M:%S")
                        if incident.created_at
                        else "-",
                        updated_at=incident.updated_at.strftime("%Y-%m-%d %H:%M:%S")
                        if incident.updated_at
                        else "-",
                    )
                )

        logger.info(
            "Korelasi otomatis selesai | mode_demo=%s | insiden_baru=%d",
            is_demo,
            len(created_incidents),
        )
        return created_incidents

    def list_incidents(
        self,
        is_demo: bool = False,
        status_filter: Optional[str] = None,
    ) -> list[IncidentRecordDTO]:
        """Mengambil daftar insiden keamanan dari database."""
        with get_db_session(self._session_factory) as session:
            stmt = select(SecurityIncident).where(SecurityIncident.is_demo == is_demo)
            if status_filter and status_filter != "SEMUA":
                valid_st = self.validate_status(status_filter)
                stmt = stmt.where(SecurityIncident.status == valid_st)

            stmt = stmt.order_by(desc(SecurityIncident.updated_at), desc(SecurityIncident.id))
            rows = session.scalars(stmt).all()

            return [
                IncidentRecordDTO(
                    id=r.id,
                    title=r.title,
                    category=r.category,
                    severity=r.severity,
                    status=r.status,
                    mitigation_notes=r.mitigation_notes or "",
                    correlated_events_count=len(r.events),
                    is_demo=r.is_demo,
                    created_at=r.created_at.strftime("%Y-%m-%d %H:%M:%S")
                    if r.created_at
                    else "-",
                    updated_at=r.updated_at.strftime("%Y-%m-%d %H:%M:%S")
                    if r.updated_at
                    else "-",
                )
                for r in rows
            ]

    def get_recent_security_events(self, is_demo: bool = False, limit: int = 25) -> list[dict]:
        """Mengambil timeline kejadian keamanan lintas modul."""
        with get_db_session(self._session_factory) as session:
            stmt = (
                select(SecurityEvent)
                .where(SecurityEvent.is_demo == is_demo)
                .order_by(desc(SecurityEvent.created_at), desc(SecurityEvent.id))
                .limit(limit)
            )
            events = session.scalars(stmt).all()
            return [
                {
                    "Event ID": e.id,
                    "Waktu (UTC)": e.created_at.strftime("%Y-%m-%d %H:%M:%S")
                    if e.created_at
                    else "-",
                    "Modul Sumber": e.source_module,
                    "Tipe Kejadian": e.event_type,
                    "Severity": e.severity,
                    "Skor": e.risk_score,
                    "Tiket Insiden": f"INC-{e.incident_id}" if e.incident_id else "Belum Tertaut",
                    "Deskripsi": e.description,
                }
                for e in events
            ]