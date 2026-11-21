"""
CYBERGUARD SENTINEL — Monitoring & Analytics Service Layer

Menyediakan agregasi metrik keamanan dari TiDB Cloud / SQLite untuk dashboard overview,
penilaian kesimpulan kondisi keamanan perangkat (Device Posture Assessment),
distribusi severity grafik Plotly, dan pemuat dataset offline DEMO MODE.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from sqlalchemy import desc, func, select
from sqlalchemy.orm import sessionmaker
import config
from core.database import check_database_health, get_db_session
from core.logger import get_logger
from database.models import (
    FileBaseline,
    FileChange,
    NetworkSnapshot,
    PhishingHistory,
    ScanHistory,
    SecurityEvent,
    SecurityIncident,
)

logger = get_logger("cyberguard.monitoring_service")


class MonitoringService:
    """Layanan terpadu pengambilan metrik, analitik dashboard, dan postur keamanan perangkat."""

    def __init__(self, session_factory: Optional[sessionmaker] = None) -> None:
        self._session_factory = session_factory

    def ensure_demo_dataset_loaded(self) -> int:
        """
        Memuat dataset simulasi offline dari data/sample_events.json ke database
        (dengan flag is_demo=True) hanya jika tabel event demo masih kosong.
        """
        with get_db_session(self._session_factory) as session:
            existing_demo_count = session.scalar(
                select(func.count(SecurityEvent.id)).where(SecurityEvent.is_demo == True)  # noqa: E712
            ) or 0

            if existing_demo_count > 0:
                return 0

            if not config.DEMO_DATASET_PATH.exists():
                return 0

            raw_data = json.loads(config.DEMO_DATASET_PATH.read_text(encoding="utf-8"))
            demo_events = raw_data.get("demo_events", [])

            inserted = 0
            for item in demo_events:
                ev = SecurityEvent(
                    event_type=item["event_type"],
                    source_module=item["source_module"],
                    severity=item["severity"],
                    risk_score=int(item["risk_score"]),
                    description=item["description"],
                    target=item.get("target"),
                    is_demo=True,
                )
                session.add(ev)
                inserted += 1

            logger.info("Dataset simulasi offline DEMO dimuat (%d events).", inserted)
            return inserted

    def get_dashboard_metrics(self, is_demo: bool = False) -> Dict[str, Any]:
        """Mengembalikan ringkasan metrik nyata dari seluruh modul berdasarkan mode operasi."""
        if is_demo:
            self.ensure_demo_dataset_loaded()

        db_health = check_database_health()
        is_db_online = (
            bool(db_health.get("healthy", False))
            if isinstance(db_health, dict)
            else bool(db_health)
        )

        metrics: Dict[str, Any] = {
            "db_online": is_db_online,
            "db_health": db_health if isinstance(db_health, dict) else {"healthy": is_db_online},
            "events_total": 0,
            "incidents_open": 0,
            "incidents_total": 0,
            "phishing_total": 0,
            "network_total": 0,
            "baselines_total": 0,
            "scans_total": 0,
            "avg_risk_score": 0.0,
            "severity_distribution": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "module_distribution": {},
            "recent_events": [],
        }

        with get_db_session(self._session_factory) as session:
            metrics["events_total"] = session.scalar(
                select(func.count(SecurityEvent.id)).where(SecurityEvent.is_demo == is_demo)
            ) or 0
            metrics["incidents_total"] = session.scalar(
                select(func.count(SecurityIncident.id)).where(SecurityIncident.is_demo == is_demo)
            ) or 0
            metrics["incidents_open"] = session.scalar(
                select(func.count(SecurityIncident.id)).where(
                    SecurityIncident.is_demo == is_demo,
                    SecurityIncident.status.in_(["OPEN", "INVESTIGATING"]),
                )
            ) or 0
            metrics["phishing_total"] = session.scalar(
                select(func.count(PhishingHistory.id)).where(PhishingHistory.is_demo == is_demo)
            ) or 0
            metrics["network_total"] = session.scalar(
                select(func.count(NetworkSnapshot.id)).where(NetworkSnapshot.is_demo == is_demo)
            ) or 0
            metrics["baselines_total"] = session.scalar(
                select(func.count(FileBaseline.id)).where(FileBaseline.status == "ACTIVE")
            ) or 0
            metrics["scans_total"] = session.scalar(
                select(func.count(ScanHistory.id)).where(ScanHistory.is_demo == is_demo)
            ) or 0

            avg_score = session.scalar(
                select(func.avg(SecurityEvent.risk_score)).where(SecurityEvent.is_demo == is_demo)
            )
            metrics["avg_risk_score"] = round(float(avg_score), 1) if avg_score is not None else 0.0

            severity_rows = session.execute(
                select(SecurityEvent.severity, func.count(SecurityEvent.id))
                .where(SecurityEvent.is_demo == is_demo)
                .group_by(SecurityEvent.severity)
            ).all()
            for severity_label, count_val in severity_rows:
                if severity_label in metrics["severity_distribution"]:
                    metrics["severity_distribution"][severity_label] = int(count_val or 0)

            module_rows = session.execute(
                select(SecurityEvent.source_module, func.count(SecurityEvent.id))
                .where(SecurityEvent.is_demo == is_demo)
                .group_by(SecurityEvent.source_module)
            ).all()
            for source_mod, count_val in module_rows:
                if source_mod:
                    mod_name = source_mod.replace("_", " ").title()
                    metrics["module_distribution"][mod_name] = int(count_val or 0)

            recent_event_rows = session.scalars(
                select(SecurityEvent)
                .where(SecurityEvent.is_demo == is_demo)
                .order_by(desc(SecurityEvent.created_at), desc(SecurityEvent.id))
                .limit(10)
            ).all()

            metrics["recent_events"] = [
                {
                    "Waktu (UTC)": e.created_at.strftime("%Y-%m-%d %H:%M:%S") if e.created_at else "-",
                    "Modul": e.source_module,
                    "Tipe Event": e.event_type,
                    "Severity": e.severity,
                    "Skor": e.risk_score,
                    "Deskripsi": e.description,
                }
                for e in recent_event_rows
            ]

        return metrics

    def get_device_posture_assessment(self, is_demo: bool = False) -> Dict[str, Any]:
        """
        Menganalisis data gabungan dari seluruh modul keamanan di database untuk
        menghasilkan kesimpulan kondisi perangkat (Device Security Posture) yang mudah dipahami.
        """
        if is_demo:
            self.ensure_demo_dataset_loaded()

        with get_db_session(self._session_factory) as session:
            # 1. Insiden Aktif (OPEN / INVESTIGATING)
            active_incidents = list(
                session.scalars(
                    select(SecurityIncident).where(
                        SecurityIncident.is_demo == is_demo,
                        SecurityIncident.status.in_(["OPEN", "INVESTIGATING"]),
                    )
                ).all()
            )
            resolved_incidents_count = session.scalar(
                select(func.count(SecurityIncident.id)).where(
                    SecurityIncident.is_demo == is_demo,
                    SecurityIncident.status.in_(["CONTAINED", "RESOLVED"]),
                )
            ) or 0

            # 2. Snapshot Jaringan Terbaru
            latest_net = session.scalars(
                select(NetworkSnapshot)
                .where(NetworkSnapshot.is_demo == is_demo)
                .order_by(desc(NetworkSnapshot.created_at), desc(NetworkSnapshot.id))
                .limit(1)
            ).first()

            # 3. Integritas File (Baseline & Perubahan)
            baselines_count = session.scalar(
                select(func.count(FileBaseline.id)).where(FileBaseline.is_demo == is_demo)
            ) or 0
            file_alerts_count = session.scalar(
                select(func.count(FileChange.id)).where(
                    FileChange.is_demo == is_demo,
                    FileChange.change_type.in_(["MODIFIED", "DELETED FILE"]),
                )
            ) or 0

            # 4. Pemindaian Port Terbaru
            latest_scan = session.scalars(
                select(ScanHistory)
                .where(ScanHistory.is_demo == is_demo)
                .order_by(desc(ScanHistory.created_at), desc(ScanHistory.id))
                .limit(1)
            ).first()

            # 5. Analisis Phishing
            phishing_high_count = session.scalar(
                select(func.count(PhishingHistory.id)).where(
                    PhishingHistory.is_demo == is_demo,
                    PhishingHistory.classification.in_(["HIGH RISK", "SUSPICIOUS"]),
                )
            ) or 0
            phishing_total_count = session.scalar(
                select(func.count(PhishingHistory.id)).where(PhishingHistory.is_demo == is_demo)
            ) or 0

            # 6. Rata-rata skor event keamanan
            total_events = session.scalar(
                select(func.count(SecurityEvent.id)).where(SecurityEvent.is_demo == is_demo)
            ) or 0
            avg_event_risk = session.scalar(
                select(func.avg(SecurityEvent.risk_score)).where(SecurityEvent.is_demo == is_demo)
            )
            avg_event_risk_val = float(avg_event_risk) if avg_event_risk is not None else 0.0

        # Hitung kontribusi risiko setiap pilar (0-100, transparan & terdokumentasi)
        incident_points = 0
        for inc in active_incidents:
            sev = (inc.severity or "LOW").upper()
            if sev == "CRITICAL":
                incident_points += 45
            elif sev == "HIGH":
                incident_points += 30
            elif sev == "MEDIUM":
                incident_points += 15
            else:
                incident_points += 5
        incident_points = min(60, incident_points)

        net_suspicious = int(latest_net.suspicious_count or 0) if latest_net else 0
        net_risk = int(latest_net.risk_score or 0) if latest_net else 0
        network_points = min(25, net_suspicious * 12) if net_suspicious > 0 else int(net_risk * 0.25)

        file_points = min(25, int(file_alerts_count) * 12)

        port_risk = int(latest_scan.risk_score or 0) if latest_scan else 0
        open_ports_num = int(latest_scan.open_ports_count or 0) if latest_scan else 0
        port_points = int(port_risk * 0.25)

        phishing_points = min(15, int(phishing_high_count) * 8)

        raw_score = incident_points + network_points + file_points + port_points + phishing_points
        if total_events > 0:
            raw_score = max(raw_score, int(round(avg_event_risk_val * 0.5)))
        posture_score = max(0, min(100, int(raw_score)))

        total_telemetry = (
            len(active_incidents)
            + resolved_incidents_count
            + (1 if latest_net else 0)
            + baselines_count
            + (1 if latest_scan else 0)
            + phishing_total_count
            + total_events
        )

        # Susun daftar temuan & rekomendasi nyata
        findings: List[str] = []
        recommendations: List[str] = []

        if len(active_incidents) > 0:
            findings.append(
                f"Terdapat {len(active_incidents)} insiden keamanan aktif (OPEN/INVESTIGATING) yang belum ditutup."
            )
            recommendations.append(
                "Tindak lanjuti dan ubah status insiden aktif menjadi CONTAINED atau RESOLVED pada tab Manajemen Insiden."
            )
        else:
            findings.append("Tidak ada insiden keamanan aktif (OPEN/INVESTIGATING) pada perangkat.")

        if latest_net:
            if net_suspicious > 0:
                findings.append(
                    f"Pemindaian jaringan terakhir ({latest_net.interface_name or 'Adapter'}) mendeteksi {net_suspicious} koneksi mencurigakan."
                )
                recommendations.append(
                    "Periksa daftar koneksi ESTABLISHED pada menu Network Monitoring dan tutup aplikasi yang tidak dikenal."
                )
            else:
                findings.append(
                    f"Trafik jaringan terakhir ({latest_net.local_ip or 'Lokal'}) bersih tanpa koneksi anomali ({latest_net.established_count} aktif)."
                )
        else:
            findings.append("Belum ada riwayat pemindaian jaringan pada mode ini.")
            recommendations.append("Jalankan pemindaian pada menu Network Monitoring untuk memverifikasi koneksi lokal.")

        if file_alerts_count > 0:
            findings.append(
                f"Terdeteksi {file_alerts_count} perubahan/penghapusan file dibandingkan baseline SHA-256."
            )
            recommendations.append(
                "Verifikasi keabsahan perubahan file pada menu File Integrity dan perbarui baseline jika perubahan memang sah."
            )
        elif baselines_count > 0:
            findings.append(f"Seluruh {baselines_count} file dalam baseline SHA-256 berada dalam kondisi utuh (UNCHANGED).")
        else:
            findings.append("Belum ada file/folder yang didaftarkan ke baseline integritas SHA-256.")

        if latest_scan:
            if port_risk >= 60:
                findings.append(
                    f"Pemindaian port terakhir menemukan {open_ports_num} port terbuka dengan risiko tinggi ({port_risk}/100)."
                )
                recommendations.append(
                    "Matikan layanan lokal yang tidak digunakan atau batasi aksesnya melalui Windows Defender Firewall."
                )
            else:
                findings.append(
                    f"Eksposur port lokal terkendali ({open_ports_num} port terbuka, skor risiko {port_risk}/100)."
                )

        if phishing_high_count > 0:
            findings.append(
                f"Tercatat {phishing_high_count} URL berstatus SUSPICIOUS/HIGH RISK pada riwayat analisis tautan."
            )
            recommendations.append(
                "Jangan membuka tautan mencurigakan tersebut di browser dan edukasi pengguna terkait ciri domain tiruan."
            )

        if not recommendations:
            recommendations.append(
                "Pertahankan kebersihan perangkat dengan melakukan pemindaian berkala dan menjaga pembaruan sistem operasi."
            )

        # Tentukan Vonis Akhir Kondisi Perangkat
        if total_telemetry == 0:
            status_code = "UNASSESSED"
            status_label = "BELUM DIPINDAI"
            risk_level = "LOW"
            icon = "🔵"
            accent_color = "#38bdf8"
            headline = "Belum ada data telemetri pada mode ini untuk menyimpulkan kondisi perangkat."
            conclusion_text = (
                "Sistem belum memiliki catatan pemindaian maupun insiden pada mode aktif saat ini. "
                "Silakan jalankan pemindaian pada modul Network Monitoring, Port Scanner, atau File Integrity, "
                "atau aktifkan DEMO MODE di sidebar untuk melihat simulasi analisis lengkap."
            )
        elif posture_score >= 80:
            status_code = "CRITICAL"
            status_label = "KRITIS — SEGERA TANGANI"
            risk_level = "CRITICAL"
            icon = "🔴"
            accent_color = "#ef4444"
            headline = "Perangkat Anda berada dalam kondisi KRITIS dan membutuhkan penanganan segera."
            conclusion_text = (
                f"Berdasarkan evaluasi menyeluruh (Skor Risiko Perangkat: {posture_score}/100), perangkat terdeteksi "
                f"memiliki ancaman serius berupa {len(active_incidents)} insiden aktif, {net_suspicious} anomali jaringan, "
                f"dan {file_alerts_count} peringatan integritas file. Segera lakukan isolasi dan mitigasi sesuai rekomendasi."
            )
        elif posture_score >= 60:
            status_code = "HIGH"
            status_label = "WASPADA — RISIKO TINGGI"
            risk_level = "HIGH"
            icon = "🟠"
            accent_color = "#f97316"
            headline = "Perangkat Anda berstatus WASPADA — ditemukan indikator risiko yang perlu segera ditindaklanjuti."
            conclusion_text = (
                f"Berdasarkan evaluasi gabungan seluruh modul (Skor Risiko Perangkat: {posture_score}/100), perangkat "
                f"menunjukkan aktivitas tidak biasa ({len(active_incidents)} insiden aktif, {net_suspicious} anomali jaringan, "
                f"{file_alerts_count} perubahan file). Disarankan segera memeriksa detail temuan dan melakukan mitigasi."
            )
        elif posture_score >= 30:
            status_code = "MEDIUM"
            status_label = "PERLU PERHATIAN"
            risk_level = "MEDIUM"
            icon = "🟡"
            accent_color = "#eab308"
            headline = "Perangkat Anda secara umum stabil, namun terdapat beberapa catatan ringan yang perlu dipantau."
            conclusion_text = (
                f"Berdasarkan hasil pemeriksaan (Skor Risiko Perangkat: {posture_score}/100), tidak ditemukan serangan "
                f"kritis, namun terdeteksi layanan/port aktif atau indikator ringan yang sebaiknya ditinjau agar "
                f"keamanan perangkat tetap optimal."
            )
        else:
            status_code = "LOW"
            status_label = "AMAN — TERLINDUNGI"
            risk_level = "LOW"
            icon = "🟢"
            accent_color = "#22c55e"
            headline = "Perangkat Anda dalam kondisi AMAN dan tidak menunjukkan tanda-tanda kompromi."
            conclusion_text = (
                f"Berdasarkan evaluasi seluruh modul pemantauan (Skor Risiko Perangkat: {posture_score}/100), "
                f"tidak ditemukan insiden terbuka, koneksi berbahaya, maupun modifikasi file tidak sah. "
                f"Perangkat siap digunakan dengan aman."
            )

        pillar_breakdown = [
            {
                "Pilar Keamanan": "Insiden Keamanan Aktif",
                "Status Terkini": f"{len(active_incidents)} Aktif / {resolved_incidents_count} Selesai",
                "Kontribusi Skor": f"+{incident_points} pts",
                "Kondisi": "Perlu Tindakan" if len(active_incidents) > 0 else "Aman",
            },
            {
                "Pilar Keamanan": "Pemantauan Jaringan",
                "Status Terkini": (
                    f"{net_suspicious} Anomali (Skor {net_risk}/100)" if latest_net else "Belum Dipindai"
                ),
                "Kontribusi Skor": f"+{network_points} pts",
                "Kondisi": "Waspada" if net_suspicious > 0 else ("Normal" if latest_net else "Menunggu Scan"),
            },
            {
                "Pilar Keamanan": "Integritas File (SHA-256)",
                "Status Terkini": f"{baselines_count} Baseline | {file_alerts_count} Berubah",
                "Kontribusi Skor": f"+{file_points} pts",
                "Kondisi": "Terdeteksi Perubahan" if file_alerts_count > 0 else "Utuh",
            },
            {
                "Pilar Keamanan": "Eksposur Port Lokal",
                "Status Terkini": (
                    f"{open_ports_num} Port Terbuka (Skor {port_risk}/100)" if latest_scan else "Belum Dipindai"
                ),
                "Kontribusi Skor": f"+{port_points} pts",
                "Kondisi": "Risiko Tinggi" if port_risk >= 60 else ("Terkendali" if latest_scan else "Menunggu Scan"),
            },
            {
                "Pilar Keamanan": "Filter Tautan Phishing",
                "Status Terkini": f"{phishing_high_count} Berisiko dari {phishing_total_count} URL",
                "Kontribusi Skor": f"+{phishing_points} pts",
                "Kondisi": "Terdeteksi Phishing" if phishing_high_count > 0 else "Bersih",
            },
        ]

        return {
            "status_code": status_code,
            "status_label": status_label,
            "risk_level": risk_level,
            "posture_score": posture_score,
            "icon": icon,
            "accent_color": accent_color,
            "headline": headline,
            "conclusion_text": conclusion_text,
            "findings": findings,
            "recommendations": recommendations,
            "pillar_breakdown": pillar_breakdown,
            "raw_counts": {
                "active_incidents": len(active_incidents),
                "resolved_incidents": int(resolved_incidents_count),
                "net_suspicious": net_suspicious,
                "file_alerts": int(file_alerts_count),
                "baselines": int(baselines_count),
                "open_ports": open_ports_num,
                "phishing_risky": int(phishing_high_count),
                "total_events": int(total_events),
            },
        }