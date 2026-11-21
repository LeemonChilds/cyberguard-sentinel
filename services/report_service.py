"""
CYBERGUARD SENTINEL — Security Reporting & Executive Export Service

Menyusun laporan keamanan terpadu yang mencakup:
1. Kesimpulan Kondisi Keamanan Perangkat (Device Security Posture) dalam bahasa yang mudah dipahami.
2. Ringkasan metrik seluruh modul (Jaringan, Phishing, Integritas File, Port Scanner, Insiden).
3. Ekspor siap unduh dalam format HTML (siap cetak/PDF), Markdown (.md), CSV (.csv), dan JSON (.json).
"""

from __future__ import annotations

import csv
from datetime import datetime
import html
import io
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from sqlalchemy import desc, select
from sqlalchemy.orm import sessionmaker
import config
from core.database import get_db_session
from core.logger import get_logger
from database.models import (
    FileChange,
    NetworkSnapshot,
    PhishingHistory,
    ScanHistory,
    SecurityEvent,
    SecurityIncident,
)
from services.monitoring_service import MonitoringService

logger = get_logger("cyberguard.report_service")

REPORTS_DIR = Path(getattr(config, "REPORTS_DIR", Path(__file__).resolve().parent.parent / "reports"))
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


class ReportService:
    """Layanan penyusunan dan ekspor laporan keamanan CYBERGUARD SENTINEL."""

    def __init__(self, session_factory: Optional[sessionmaker] = None) -> None:
        self._session_factory = session_factory
        self._monitoring = MonitoringService(session_factory=session_factory)

    def build_report_bundle(
        self,
        is_demo: bool = False,
        scope: str = "ALL",
        record_limit: int = 50,
    ) -> Dict[str, Any]:
        """Mengumpulkan seluruh data laporan beserta kesimpulan kondisi perangkat."""
        posture = self._monitoring.get_device_posture_assessment(is_demo=is_demo)
        metrics = self._monitoring.get_dashboard_metrics(is_demo=is_demo)
        generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        mode_label = "DEMO MODE (Simulasi)" if is_demo else "LIVE MODE (Perangkat Aktual)"

        with get_db_session(self._session_factory) as session:
            incidents = list(
                session.scalars(
                    select(SecurityIncident)
                    .where(SecurityIncident.is_demo == is_demo)
                    .order_by(desc(SecurityIncident.created_at), desc(SecurityIncident.id))
                    .limit(record_limit)
                ).all()
            )
            events = list(
                session.scalars(
                    select(SecurityEvent)
                    .where(SecurityEvent.is_demo == is_demo)
                    .order_by(desc(SecurityEvent.created_at), desc(SecurityEvent.id))
                    .limit(record_limit)
                ).all()
            )
            phishing_rows = list(
                session.scalars(
                    select(PhishingHistory)
                    .where(PhishingHistory.is_demo == is_demo)
                    .order_by(desc(PhishingHistory.created_at), desc(PhishingHistory.id))
                    .limit(record_limit)
                ).all()
            )
            scan_rows = list(
                session.scalars(
                    select(ScanHistory)
                    .where(ScanHistory.is_demo == is_demo)
                    .order_by(desc(ScanHistory.created_at), desc(ScanHistory.id))
                    .limit(record_limit)
                ).all()
            )
            net_rows = list(
                session.scalars(
                    select(NetworkSnapshot)
                    .where(NetworkSnapshot.is_demo == is_demo)
                    .order_by(desc(NetworkSnapshot.created_at), desc(NetworkSnapshot.id))
                    .limit(record_limit)
                ).all()
            )
            file_changes = list(
                session.scalars(
                    select(FileChange)
                    .where(FileChange.is_demo == is_demo)
                    .order_by(desc(FileChange.created_at), desc(FileChange.id))
                    .limit(record_limit)
                ).all()
            )

        incidents_data = [
            {
                "Kode": i.incident_code or f"INC-{i.id:04d}",
                "Judul": i.title,
                "Kategori": i.category,
                "Severity": i.severity,
                "Skor": i.risk_score,
                "Status": i.status,
                "Mitigasi": i.mitigation_notes or i.recommended_mitigation or "-",
                "Waktu (UTC)": i.created_at.strftime("%Y-%m-%d %H:%M:%S") if i.created_at else "-",
            }
            for i in incidents
        ]

        events_data = [
            {
                "Waktu (UTC)": e.created_at.strftime("%Y-%m-%d %H:%M:%S") if e.created_at else "-",
                "Modul": e.source_module,
                "Tipe Event": e.event_type,
                "Severity": e.severity,
                "Skor": e.risk_score,
                "Deskripsi": e.description,
            }
            for e in events
        ]

        phishing_data = [
            {
                "Waktu (UTC)": p.created_at.strftime("%Y-%m-%d %H:%M:%S") if p.created_at else "-",
                "Domain": p.domain or "-",
                "Klasifikasi": p.classification,
                "Skor": p.risk_score,
                "URL": p.url,
            }
            for p in phishing_rows
        ]

        scans_data = [
            {
                "Waktu (UTC)": s.created_at.strftime("%Y-%m-%d %H:%M:%S") if s.created_at else "-",
                "Target": s.target,
                "Rentang Port": s.port_range or "-",
                "Port Terbuka": s.open_ports_count,
                "Severity": s.severity,
                "Skor": s.risk_score,
            }
            for s in scan_rows
        ]

        network_data = [
            {
                "Waktu (UTC)": n.created_at.strftime("%Y-%m-%d %H:%M:%S") if n.created_at else "-",
                "Interface": n.interface_name or "-",
                "IP Lokal": n.local_ip or "-",
                "Established": n.active_connections_count,
                "Listening": n.listening_ports_count,
                "Anomali": n.suspicious_connections_count,
                "Skor": n.risk_score,
            }
            for n in net_rows
        ]

        file_data = [
            {
                "Waktu (UTC)": f.created_at.strftime("%Y-%m-%d %H:%M:%S") if f.created_at else "-",
                "Nama File": f.file_name or f.file_path,
                "Perubahan": f.change_type,
                "Severity": f.severity,
                "Skor": f.risk_score,
            }
            for f in file_changes
        ]

        return {
            "generated_at": generated_at,
            "mode_label": mode_label,
            "scope": scope,
            "posture": posture,
            "metrics": {
                "events_total": metrics["events_total"],
                "incidents_total": metrics["incidents_total"],
                "incidents_open": metrics["incidents_open"],
                "phishing_total": metrics["phishing_total"],
                "network_total": metrics["network_total"],
                "baselines_total": metrics["baselines_total"],
                "scans_total": metrics["scans_total"],
                "avg_risk_score": metrics["avg_risk_score"],
            },
            "incidents": incidents_data,
            "events": events_data,
            "phishing": phishing_data,
            "scans": scans_data,
            "network": network_data,
            "file_changes": file_data,
        }

    def render_markdown(self, bundle: Dict[str, Any]) -> str:
        """Menghasilkan dokumen laporan lengkap dalam format Markdown (.md)."""
        posture = bundle["posture"]
        lines: List[str] = [
            "# LAPORAN AUDIT & POSTUR KEAMANAN PERANGKAT — CYBERGUARD SENTINEL",
            "",
            f"- **Waktu Pembuatan:** {bundle['generated_at']}",
            f"- **Mode Operasi:** {bundle['mode_label']}",
            f"- **Cakupan Laporan:** {bundle['scope']}",
            "",
            "---",
            "",
            "## 1. KESIMPULAN KONDISI KEAMANAN PERANGKAT",
            "",
            f"### {posture['icon']} STATUS PERANGKAT: {posture['status_label']} (Skor Risiko: {posture['posture_score']}/100)",
            "",
            f"**{posture['headline']}**",
            "",
            posture["conclusion_text"],
            "",
            "### Rincian Evaluasi 5 Pilar Keamanan",
            "",
            "| Pilar Keamanan | Status Terkini | Kontribusi Skor | Kondisi |",
            "| :--- | :--- | :--- | :--- |",
        ]

        for row in posture["pillar_breakdown"]:
            lines.append(
                f"| {row['Pilar Keamanan']} | {row['Status Terkini']} | {row['Kontribusi Skor']} | {row['Kondisi']} |"
            )

        lines.extend(["", "### Temuan Utama", ""])
        for f_item in posture["findings"]:
            lines.append(f"- {f_item}")

        lines.extend(["", "### Rekomendasi Tindakan", ""])
        for rec in posture["recommendations"]:
            lines.append(f"- {rec}")

        lines.extend(["", "---", "", "## 2. DAFTAR INSIDEN KEAMANAN", ""])
        if not bundle["incidents"]:
            lines.append("_Tidak ada catatan insiden keamanan pada mode ini._")
        else:
            lines.extend(
                [
                    "| Kode | Judul | Kategori | Severity | Skor | Status | Waktu (UTC) |",
                    "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
                ]
            )
            for inc in bundle["incidents"]:
                lines.append(
                    f"| {inc['Kode']} | {inc['Judul']} | {inc['Kategori']} | "
                    f"{inc['Severity']} | {inc['Skor']}/100 | {inc['Status']} | {inc['Waktu (UTC)']} |"
                )

        lines.extend(["", "---", "", "## 3. LOG EVENT KEAMANAN TERBARU", ""])
        if not bundle["events"]:
            lines.append("_Tidak ada log event keamanan pada mode ini._")
        else:
            lines.extend(
                [
                    "| Waktu (UTC) | Modul | Tipe Event | Severity | Skor | Deskripsi |",
                    "| :--- | :--- | :--- | :--- | :--- | :--- |",
                ]
            )
            for ev in bundle["events"][:30]:
                desc_clean = str(ev["Deskripsi"]).replace("|", "/")
                lines.append(
                    f"| {ev['Waktu (UTC)']} | {ev['Modul']} | {ev['Tipe Event']} | "
                    f"{ev['Severity']} | {ev['Skor']} | {desc_clean} |"
                )

        lines.extend(
            [
                "",
                "---",
                "_Catatan: Laporan ini dihasilkan otomatis oleh CYBERGUARD SENTINEL. Tidak ada kata sandi plaintext yang disimpan maupun dicetak dalam laporan ini._",
            ]
        )
        return "\n".join(lines)

    def render_html_report(self, bundle: Dict[str, Any]) -> str:
        """Menghasilkan laporan eksekutif HTML mandiri yang rapi dan siap dicetak ke PDF."""
        posture = bundle["posture"]
        accent = html.escape(posture["accent_color"])

        pillar_rows_html = "".join(
            f"<tr><td>{html.escape(r['Pilar Keamanan'])}</td>"
            f"<td>{html.escape(r['Status Terkini'])}</td>"
            f"<td>{html.escape(r['Kontribusi Skor'])}</td>"
            f"<td><strong>{html.escape(r['Kondisi'])}</strong></td></tr>"
            for r in posture["pillar_breakdown"]
        )

        rec_items_html = "".join(f"<li>{html.escape(rec)}</li>" for rec in posture["recommendations"])

        if bundle["incidents"]:
            inc_rows_html = "".join(
                f"<tr><td>{html.escape(str(i['Kode']))}</td>"
                f"<td>{html.escape(str(i['Judul']))}</td>"
                f"<td>{html.escape(str(i['Kategori']))}</td>"
                f"<td>{html.escape(str(i['Severity']))}</td>"
                f"<td>{i['Skor']}/100</td>"
                f"<td>{html.escape(str(i['Status']))}</td></tr>"
                for i in bundle["incidents"]
            )
            incidents_section = f"""
            <table>
                <thead><tr><th>Kode</th><th>Judul</th><th>Kategori</th><th>Severity</th><th>Skor</th><th>Status</th></tr></thead>
                <tbody>{inc_rows_html}</tbody>
            </table>
            """
        else:
            incidents_section = "<p>Tidak ada catatan insiden keamanan pada mode ini.</p>"

        if bundle["events"]:
            ev_rows_html = "".join(
                f"<tr><td>{html.escape(str(e['Waktu (UTC)']))}</td>"
                f"<td>{html.escape(str(e['Modul']))}</td>"
                f"<td>{html.escape(str(e['Severity']))}</td>"
                f"<td>{e['Skor']}</td>"
                f"<td>{html.escape(str(e['Deskripsi']))}</td></tr>"
                for e in bundle["events"][:30]
            )
            events_section = f"""
            <table>
                <thead><tr><th>Waktu (UTC)</th><th>Modul</th><th>Severity</th><th>Skor</th><th>Deskripsi</th></tr></thead>
                <tbody>{ev_rows_html}</tbody>
            </table>
            """
        else:
            events_section = "<p>Tidak ada log event keamanan pada mode ini.</p>"

        return f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8" />
<title>Laporan Keamanan Perangkat — CYBERGUARD SENTINEL</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f8fafc; color: #0f172a; margin: 32px; line-height: 1.55; }}
  .header {{ background: #0f172a; color: #f8fafc; padding: 24px 28px; border-radius: 12px; margin-bottom: 24px; }}
  .header h1 {{ margin: 0 0 6px 0; font-size: 22px; color: #38bdf8; }}
  .meta {{ font-size: 13px; color: #cbd5e1; }}
  .verdict-card {{ background: #ffffff; border: 2px solid {accent}; border-left: 8px solid {accent}; border-radius: 10px; padding: 20px 24px; margin-bottom: 24px; }}
  .verdict-title {{ font-size: 20px; font-weight: 700; margin: 4px 0 8px 0; color: #0f172a; }}
  .score-pill {{ display: inline-block; background: #0f172a; color: #ffffff; padding: 4px 12px; border-radius: 999px; font-size: 12px; font-weight: 700; }}
  h2 {{ border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; margin-top: 28px; color: #1e293b; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; background: #ffffff; font-size: 13px; }}
  th, td {{ border: 1px solid #cbd5e1; padding: 9px 12px; text-align: left; }}
  th {{ background: #1e293b; color: #f8fafc; }}
  tr:nth-child(even) {{ background: #f1f5f9; }}
  .footer {{ margin-top: 32px; font-size: 12px; color: #64748b; text-align: center; }}
</style>
</head>
<body>
  <div class="header">
    <h1>CYBERGUARD SENTINEL — LAPORAN KONDISI KEAMANAN PERANGKAT</h1>
    <div class="meta">Waktu Pembuatan: {html.escape(bundle['generated_at'])} &nbsp;|&nbsp; Mode: {html.escape(bundle['mode_label'])}</div>
  </div>

  <div class="verdict-card">
    <span class="score-pill">SKOR RISIKO PERANGKAT: {posture['posture_score']}/100 ({html.escape(posture['risk_level'])})</span>
    <div class="verdict-title">{html.escape(posture['icon'])} STATUS PERANGKAT: {html.escape(posture['status_label'])}</div>
    <p><strong>{html.escape(posture['headline'])}</strong></p>
    <p>{html.escape(posture['conclusion_text'])}</p>
    <h3>Rekomendasi Tindakan Prioritas</h3>
    <ul>{rec_items_html}</ul>
  </div>

  <h2>1. Evaluasi 5 Pilar Keamanan Perangkat</h2>
  <table>
    <thead><tr><th>Pilar Keamanan</th><th>Status Terkini</th><th>Kontribusi Skor</th><th>Kondisi</th></tr></thead>
    <tbody>{pillar_rows_html}</tbody>
  </table>

  <h2>2. Daftar Insiden Keamanan</h2>
  {incidents_section}

  <h2>3. Log Event Keamanan Terbaru</h2>
  {events_section}

  <div class="footer">
    Dihasilkan otomatis oleh CYBERGUARD SENTINEL (DETECT. ANALYZE. PROTECT.) — Privasi Terjaga: Tanpa Penyimpanan Kata Sandi.
  </div>
</body>
</html>"""

    def render_csv(self, bundle: Dict[str, Any]) -> str:
        """Menghasilkan CSV gabungan yang diawali ringkasan kesimpulan perangkat dan diikuti tabel data."""
        posture = bundle["posture"]
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["KESIMPULAN KONDISI KEAMANAN PERANGKAT"])
        writer.writerow(["Waktu Pembuatan", bundle["generated_at"]])
        writer.writerow(["Mode Operasi", bundle["mode_label"]])
        writer.writerow(["Status Perangkat", posture["status_label"]])
        writer.writerow(["Skor Risiko Perangkat", f"{posture['posture_score']}/100"])
        writer.writerow(["Kesimpulan Utama", posture["headline"]])
        writer.writerow(["Penjelasan Lengkap", posture["conclusion_text"]])
        writer.writerow([])

        writer.writerow(["RINCIAN 5 PILAR KEAMANAN"])
        writer.writerow(["Pilar Keamanan", "Status Terkini", "Kontribusi Skor", "Kondisi"])
        for p in posture["pillar_breakdown"]:
            writer.writerow([p["Pilar Keamanan"], p["Status Terkini"], p["Kontribusi Skor"], p["Kondisi"]])
        writer.writerow([])

        writer.writerow(["DAFTAR INSIDEN KEAMANAN"])
        writer.writerow(["Kode", "Judul", "Kategori", "Severity", "Skor", "Status", "Waktu (UTC)"])
        for inc in bundle["incidents"]:
            writer.writerow(
                [inc["Kode"], inc["Judul"], inc["Kategori"], inc["Severity"], inc["Skor"], inc["Status"], inc["Waktu (UTC)"]]
            )
        writer.writerow([])

        writer.writerow(["LOG EVENT KEAMANAN"])
        writer.writerow(["Waktu (UTC)", "Modul", "Tipe Event", "Severity", "Skor", "Deskripsi"])
        for ev in bundle["events"]:
            writer.writerow(
                [ev["Waktu (UTC)"], ev["Modul"], ev["Tipe Event"], ev["Severity"], ev["Skor"], ev["Deskripsi"]]
            )

        return output.getvalue()

    def render_json(self, bundle: Dict[str, Any]) -> str:
        """Menghasilkan dokumen JSON terstruktur lengkap dengan kesimpulan postur perangkat."""
        return json.dumps(bundle, indent=2, ensure_ascii=False)

    def save_report_to_disk(self, content: str, extension: str) -> Path:
        """Menyimpan salinan laporan ke direktori reports/ lokal."""
        stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        ext_clean = extension.lstrip(".")
        target_path = REPORTS_DIR / f"cyberguard_report_{stamp}.{ext_clean}"
        target_path.write_text(content, encoding="utf-8")
        return target_path