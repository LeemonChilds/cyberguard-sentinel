"""
CYBERGUARD SENTINEL — Security Reports & Executive Export Dashboard

Menampilkan kesimpulan kondisi keamanan perangkat secara langsung di layar,
pratinjau laporan lintas modul, serta ekspor sekali klik ke format HTML (Siap Cetak/PDF),
Markdown (.md), CSV (.csv), dan JSON (.json).
"""

from __future__ import annotations

from typing import Any
import pandas as pd
import streamlit as st
from services.report_service import ReportService


def _resolve_is_demo(mode: Any) -> bool:
    if isinstance(mode, bool):
        return mode
    return str(mode or "LIVE").strip().upper() == "DEMO"


def render_reports_page(mode: Any = "LIVE") -> None:
    """Merender halaman lengkap Reports beserta kesimpulan kondisi perangkat."""
    is_demo = _resolve_is_demo(mode)
    service = ReportService()

    st.title("📑 Security Reports & Device Posture Summary")
    st.caption(
        "Laporan eksekutif dan audit teknis perangkat yang siap diunduh untuk dokumentasi, "
        "evaluasi keamanan, maupun presentasi pameran."
    )

    col_opt1, col_opt2 = st.columns([1.4, 1.0])
    with col_opt1:
        scope_choice = st.selectbox(
            "Cakupan Laporan",
            options=[
                "ALL — Laporan Lengkap Seluruh Modul",
                "INCIDENTS — Fokus Kesimpulan & Insiden",
                "EVENTS — Fokus Log Aktivitas Keamanan",
            ],
            index=0,
        )
    with col_opt2:
        limit_choice = st.selectbox(
            "Batas Riwayat Data per Tabel",
            options=[20, 50, 100],
            index=1,
        )

    scope_code = scope_choice.split(" — ", 1)[0]
    bundle = service.build_report_bundle(
        is_demo=is_demo,
        scope=scope_code,
        record_limit=int(limit_choice),
    )
    posture = bundle["posture"]
    accent = posture["accent_color"]

    # Kartu Kesimpulan Eksekutif Kondisi Perangkat
    st.markdown(
        f"""
        <div style="
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.96), rgba(30, 41, 59, 0.92));
            border: 1px solid {accent};
            border-left: 6px solid {accent};
            border-radius: 12px;
            padding: 18px 22px;
            margin: 12px 0 18px 0;
        ">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                <span style="font-size: 0.80rem; letter-spacing: 0.08em; color: #94a3b8; font-weight: 600;">
                    RINGKASAN EKSEKUTIF KONDISI PERANGKAT • {bundle['mode_label'].upper()}
                </span>
                <span style="
                    background: rgba(15, 23, 42, 0.85);
                    border: 1px solid {accent};
                    color: {accent};
                    padding: 3px 12px;
                    border-radius: 999px;
                    font-size: 0.82rem;
                    font-weight: 700;
                ">
                    SKOR RISIKO: {posture['posture_score']}/100 ({posture['risk_level']})
                </span>
            </div>
            <h3 style="margin: 10px 0 6px 0; color: #f8fafc; font-size: 1.30rem;">
                {posture['icon']} VONIS PERANGKAT: {posture['status_label']}
            </h3>
            <p style="margin: 0 0 8px 0; color: #e2e8f0; font-weight: 600;">
                {posture['headline']}
            </p>
            <p style="margin: 0; color: #cbd5e1; font-size: 0.93rem; line-height: 1.55;">
                {posture['conclusion_text']}
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Ringkasan Angka Laporan
    m = bundle["metrics"]
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Skor Perangkat", f"{posture['posture_score']}/100")
    c2.metric("Insiden Aktif", m["incidents_open"])
    c3.metric("Total Event", m["events_total"])
    c4.metric("Scan Jaringan", m["network_total"])
    c5.metric("URL Diperiksa", m["phishing_total"])

    st.markdown("---")
    st.subheader("⬇️ Unduh Laporan (Sudah Termasuk Kesimpulan Kondisi Perangkat)")

    html_str = service.render_html_report(bundle)
    md_str = service.render_markdown(bundle)
    csv_str = service.render_csv(bundle)
    json_str = service.render_json(bundle)

    d1, d2, d3, d4 = st.columns(4)
    with d1:
        st.download_button(
            label="🌐 Unduh Laporan HTML (Siap Cetak PDF)",
            data=html_str,
            file_name="CYBERGUARD_Laporan_Keamanan_Perangkat.html",
            mime="text/html",
            use_container_width=True,
        )
    with d2:
        st.download_button(
            label="📝 Unduh Laporan Markdown (.md)",
            data=md_str,
            file_name="CYBERGUARD_Laporan_Keamanan_Perangkat.md",
            mime="text/markdown",
            use_container_width=True,
        )
    with d3:
        st.download_button(
            label="📊 Unduh Data Tabel (.csv)",
            data=csv_str,
            file_name="CYBERGUARD_Data_Keamanan.csv",
            mime="text/csv",
            use_container_width=True,
        )
    with d4:
        st.download_button(
            label="🧩 Unduh Audit JSON (.json)",
            data=json_str,
            file_name="CYBERGUARD_Audit_Keamanan.json",
            mime="application/json",
            use_container_width=True,
        )

    if st.button("💾 Simpan Salinan Laporan ke Folder Lokal (reports/)"):
        try:
            saved_html = service.save_report_to_disk(html_str, "html")
            saved_md = service.save_report_to_disk(md_str, "md")
            st.success(f"Laporan tersimpan di:\n- `{saved_html}`\n- `{saved_md}`")
        except Exception as exc:
            st.error(f"Gagal menyimpan laporan ke folder reports/: {exc}")

    st.markdown("---")
    tab_posture, tab_inc, tab_ev, tab_preview = st.tabs(
        [
            "🛡️ Rincian Kesimpulan & Rekomendasi",
            "🚨 Tabel Insiden",
            "📜 Log Event Keamanan",
            "👁️ Pratinjau Dokumen Laporan",
        ]
    )

    with tab_posture:
        st.markdown("**Tabel Penilaian 5 Pilar Keamanan Perangkat**")
        st.dataframe(pd.DataFrame(posture["pillar_breakdown"]), use_container_width=True, hide_index=True)

        col_f, col_r = st.columns(2)
        with col_f:
            st.markdown("**Temuan Teknis Terdeteksi**")
            for f_item in posture["findings"]:
                st.markdown(f"- {f_item}")
        with col_r:
            st.markdown("**Rekomendasi Tindakan Perbaikan**")
            for rec in posture["recommendations"]:
                st.markdown(f"- **{rec}**")

    with tab_inc:
        if bundle["incidents"]:
            st.dataframe(pd.DataFrame(bundle["incidents"]), use_container_width=True, hide_index=True)
        else:
            st.info("Belum ada data insiden pada mode ini.")

    with tab_ev:
        if bundle["events"]:
            st.dataframe(pd.DataFrame(bundle["events"]), use_container_width=True, hide_index=True)
        else:
            st.info("Belum ada data log event pada mode ini.")

    with tab_preview:
        st.markdown(md_str)