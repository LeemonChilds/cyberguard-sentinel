"""
CYBERGUARD SENTINEL — Security Incident Service Layer

Menangani siklus hidup insiden keamanan (OPEN, INVESTIGATING, CONTAINED, RESOLVED),
korelasi event otomatis, dan penilaian kesimpulan kondisi keamanan perangkat
(Device Security Posture) secara mandiri tanpa ketergantungan sirkular.
"""

from __future__ import annotations

from datetime import datetime
import json
from typing import Any, Dict, List, Optional
import uuid
from sqlalchemy import desc, select
from sqlalchemy.orm import sessionmaker
from core.database import get_db_session
from core.logger import get_logger
from database.models import SecurityEvent, SecurityIncident
from services.monitoring_service import MonitoringService

logger = get_logger("cyberguard.incident_service")

VALID_INCIDENT_CATEGORIES = [
    "PHISHING",
    "NETWORK ANOMALY",
    "FILE MODIFICATION",
    "AUTHENTICATION ANOMALY",
    "PORT EXPOSURE",
]

VALID_INCIDENT_STATUSES = [
    "OPEN",
    "INVESTIGATING",
    "CONTAINED",
    "RESOLVED",
]

VALID_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class IncidentService:
    """Layanan terpadu pengelolaan siklus hidup insiden keamanan dan evaluasi perangkat."""

    def __init__(self, session_factory: Optional[sessionmaker] = None) -> None:
        self._session_factory = session_factory
        self._monitoring = MonitoringService(session_factory=session_factory)

    def get_device_posture(self, is_demo: bool = False) -> Dict[str, Any]:
        """Mengambil kesimpulan kondisi keamanan perangkat secara menyeluruh."""
        return self._monitoring.get_device_posture_assessment(is_demo=is_demo)

    def _fetch_all_incidents(self, is_demo: bool = False) -> List[Dict[str, Any]]:
        """Membaca seluruh rekaman insiden dari database dan memformatnya menjadi dictionary aman."""
        with get_db_session(self._session_factory) as session:
            rows = list(
                session.scalars(
                    select(SecurityIncident)
                    .where(SecurityIncident.is_demo == is_demo)
                    .order_by(desc(SecurityIncident.created_at), desc(SecurityIncident.id))
                ).all()
            )

            results: List[Dict[str, Any]] = []
            for r in rows:
                try:
                    timeline = json.loads(r.timeline_json) if r.timeline_json else []
                except Exception:
                    timeline = []

                linked_events_count = len(r.events) if getattr(r, "events", None) else int(r.correlated_events_count or 0)
                created_str = r.created_at.strftime("%Y-%m-%d %H:%M:%S") if r.created_at else "-"

                results.append(
                    {
                        "id": r.id,
                        "incident_code": r.incident_code or f"INC-{r.id:04d}",
                        "title": r.title,
                        "category": r.category or "NETWORK ANOMALY",
                        "severity": (r.severity or "MEDIUM").upper(),
                        "risk_score": int(r.risk_score or 0),
                        "status": (r.status or "OPEN").upper(),
                        "target": r.target or "-",
                        "description": r.description or "",
                        "mitigation_notes": r.mitigation_notes or r.mitigation or "",
                        "recommended_mitigation": r.recommended_mitigation or self._suggest_mitigation(r.category or ""),
                        "correlated_events_count": linked_events_count,
                        "timeline": timeline,
                        "created_at": created_str,
                    }
                )
            return results

    def get_status_summary(self, is_demo: bool = False) -> Dict[str, Any]:
        """Menghitung ringkasan jumlah insiden per status dan tingkat keparahan."""
        all_incidents = self._fetch_all_incidents(is_demo=is_demo)
        summary = {
            "total": len(all_incidents),
            "OPEN": 0,
            "INVESTIGATING": 0,
            "CONTAINED": 0,
            "RESOLVED": 0,
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }
        for inc in all_incidents:
            status_key = str(inc.get("status", "OPEN")).upper()
            sev_key = str(inc.get("severity", "LOW")).upper()
            if status_key in summary:
                summary[status_key] += 1
            if sev_key in summary:
                summary[sev_key] += 1

        return summary

    def list_incidents(
        self,
        status_filter: Optional[str] = None,
        category_filter: Optional[str] = None,
        is_demo: bool = False,
    ) -> List[Dict[str, Any]]:
        """Mengembalikan daftar insiden terfilter untuk tabel dan detail dashboard."""
        all_rows = self._fetch_all_incidents(is_demo=is_demo)
        filtered: List[Dict[str, Any]] = []

        for row in all_rows:
            if status_filter and status_filter != "SEMUA" and row["status"] != status_filter.upper():
                continue
            if category_filter and category_filter != "SEMUA" and row["category"].upper() != category_filter.upper():
                continue
            filtered.append(row)

        return filtered

    def create_incident(
        self,
        title: str,
        category: str,
        severity: str,
        risk_score: int,
        description: str,
        target: Optional[str] = None,
        mitigation_notes: str = "",
        is_demo: bool = False,
    ) -> str:
        """Membuat insiden keamanan baru beserta entri timeline awal di database."""
        clean_title = (title or "").strip()
        if len(clean_title) < 4:
            raise ValueError("Judul insiden minimal terdiri dari 4 karakter.")

        clean_desc = (description or "").strip()
        if len(clean_desc) < 10:
            raise ValueError("Deskripsi insiden minimal terdiri dari 10 karakter.")

        cat_upper = (category or "NETWORK ANOMALY").upper()
        if cat_upper not in VALID_INCIDENT_CATEGORIES:
            cat_upper = "NETWORK ANOMALY"

        sev_upper = (severity or "MEDIUM").upper()
        if sev_upper not in VALID_SEVERITIES:
            sev_upper = "MEDIUM"

        bounded_score = max(0, min(100, int(risk_score)))
        incident_code = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        default_mitigation = self._suggest_mitigation(cat_upper)
        initial_timeline = [
            {
                "timestamp": now_str,
                "status": "OPEN",
                "note": f"Insiden dibuat ({cat_upper} | Severity: {sev_upper}).",
            }
        ]

        with get_db_session(self._session_factory) as session:
            inc = SecurityIncident(
                incident_code=incident_code,
                title=clean_title[:255],
                category=cat_upper,
                severity=sev_upper,
                risk_score=bounded_score,
                status="OPEN",
                source_module="INCIDENT_CENTER",
                target=(target or "").strip()[:512] or None,
                correlated_events_count=0,
                description=clean_desc,
                recommended_mitigation=default_mitigation,
                mitigation_notes=(mitigation_notes or default_mitigation).strip(),
                timeline_json=json.dumps(initial_timeline, ensure_ascii=False),
                is_demo=is_demo,
            )
            session.add(inc)

            ev = SecurityEvent(
                source_module="INCIDENT_CENTER",
                event_type="INCIDENT_CREATED",
                severity=sev_upper,
                risk_score=bounded_score,
                description=f"[{incident_code}] {clean_title} ({cat_upper})",
                target=(target or "").strip()[:512] or None,
                is_demo=is_demo,
            )
            session.add(ev)

        logger.info("Insiden baru berhasil dibuat: %s (%s)", incident_code, clean_title)
        return incident_code

    def update_incident_status(
        self,
        incident_id: int,
        new_status: str,
        mitigation_notes: Optional[str] = None,
    ) -> bool:
        """Memperbarui status investigasi insiden dan mencatat riwayatnya ke timeline."""
        status_upper = (new_status or "").upper()
        if status_upper not in VALID_INCIDENT_STATUSES:
            raise ValueError(f"Status insiden tidak valid: {new_status}")

        with get_db_session(self._session_factory) as session:
            inc = session.get(SecurityIncident, int(incident_id))
            if not inc:
                return False

            old_status = inc.status
            inc.status = status_upper
            if mitigation_notes is not None and mitigation_notes.strip():
                inc.mitigation_notes = mitigation_notes.strip()

            if status_upper == "RESOLVED" and inc.resolved_at is None:
                inc.resolved_at = datetime.utcnow()

            try:
                timeline = json.loads(inc.timeline_json) if inc.timeline_json else []
            except Exception:
                timeline = []

            timeline.append(
                {
                    "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "status": status_upper,
                    "note": (
                        f"Status diperbarui dari {old_status} ke {status_upper}. "
                        f"Catatan: {(mitigation_notes or '').strip() or '-'}"
                    ),
                }
            )
            inc.timeline_json = json.dumps(timeline, ensure_ascii=False)

        logger.info("Insiden ID=%s diperbarui ke status %s.", incident_id, status_upper)
        return True

    def correlate_unlinked_events(self, is_demo: bool = False) -> int:
        """
        Mengkorelasikan SecurityEvent berisiko (MEDIUM/HIGH/CRITICAL) yang belum tertaut
        ke insiden mana pun menjadi insiden terkelompok berdasarkan modul sumbernya.
        """
        with get_db_session(self._session_factory) as session:
            unlinked = list(
                session.scalars(
                    select(SecurityEvent)
                    .where(
                        SecurityEvent.is_demo == is_demo,
                        SecurityEvent.incident_id.is_(None),
                        SecurityEvent.severity.in_(["MEDIUM", "HIGH", "CRITICAL"]),
                    )
                    .order_by(desc(SecurityEvent.created_at))
                    .limit(50)
                ).all()
            )

            if not unlinked:
                return 0

            grouped: Dict[str, List[SecurityEvent]] = {}
            for ev in unlinked:
                mod = (ev.source_module or "GENERAL").upper()
                grouped.setdefault(mod, []).append(ev)

            created_incidents = 0
            for mod_name, ev_list in grouped.items():
                category = self._map_module_to_category(mod_name)
                max_score = max(int(e.risk_score or 0) for e in ev_list)
                top_sev = "CRITICAL" if max_score >= 80 else ("HIGH" if max_score >= 60 else "MEDIUM")
                incident_code = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"
                mitigation = self._suggest_mitigation(category)

                timeline = [
                    {
                        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "status": "OPEN",
                        "note": f"Dibuat otomatis dari korelasi {len(ev_list)} event modul {mod_name}.",
                    }
                ]

                inc = SecurityIncident(
                    incident_code=incident_code,
                    title=f"Korelasi Anomali {mod_name.replace('_', ' ').title()} ({len(ev_list)} Event)",
                    category=category,
                    severity=top_sev,
                    risk_score=max_score,
                    status="OPEN",
                    source_module=mod_name,
                    correlated_events_count=len(ev_list),
                    description=(
                        f"Ditemukan {len(ev_list)} event keamanan berisiko dari modul {mod_name}. "
                        f"Contoh temuan: {ev_list[0].description}"
                    ),
                    recommended_mitigation=mitigation,
                    mitigation_notes=mitigation,
                    timeline_json=json.dumps(timeline, ensure_ascii=False),
                    is_demo=is_demo,
                )
                session.add(inc)
                session.flush()

                for ev in ev_list:
                    ev.incident_id = inc.id

                created_incidents += 1

            return created_incidents

    @staticmethod
    def _map_module_to_category(module_name: str) -> str:
        mod = module_name.upper()
        if "PHISHING" in mod:
            return "PHISHING"
        if "FILE" in mod or "INTEGRITY" in mod:
            return "FILE MODIFICATION"
        if "PORT" in mod:
            return "PORT EXPOSURE"
        if "PASSWORD" in mod or "AUTH" in mod:
            return "AUTHENTICATION ANOMALY"
        return "NETWORK ANOMALY"

    @staticmethod
    def _suggest_mitigation(category: str) -> str:
        mapping = {
            "PHISHING": "Blokir domain/URL terkait, jangan masukkan kredensial, dan verifikasi keaslian pengirim.",
            "NETWORK ANOMALY": "Periksa proses pemilik koneksi aktif, tutup aplikasi mencurigakan, dan aktifkan firewall.",
            "FILE MODIFICATION": "Bandingkan hash SHA-256 dengan cadangan resmi dan pulihkan file apabila terindikasi perubahan tidak sah.",
            "AUTHENTICATION ANOMALY": "Perbarui kata sandi dengan kombinasi panjang minimal 12 karakter unik dan aktifkan 2FA.",
            "PORT EXPOSURE": "Hentikan layanan lokal yang tidak diperlukan dan tutup port melalui aturan Windows Defender Firewall.",
        }
        return mapping.get(category, "Lakukan investigasi log lokal dan isolasi sumber anomali.")