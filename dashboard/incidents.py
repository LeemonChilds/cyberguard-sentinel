"""
CYBERGUARD SENTINEL — Security Incident Center Dashboard

Menampilkan kesimpulan kondisi keamanan perangkat secara menyeluruh di bagian atas,
ringkasan status insiden, korelasi event otomatis, pembuatan insiden, serta manajemen
status mitigasi dan timeline investigasi.
"""

from __future__ import annotations

from typing import Any
import pandas as pd
import streamlit as st
from services.incident_service import (
    IncidentService,
    VALID_INCIDENT_CATEGORIES,
    VALID_INCIDENT_STATUSES,
    VALID_SEVERITIES,
)


def _resolve_is_demo(mode: Any) -> bool:
    if isinstance(mode, bool):
        return mode
    return str(mode or "LIVE").strip().upper() == "DEMO"


def _render_device_conclusion_banner(posture: dict[str, Any], is_demo: bool) -> None:
    """Merender kartu kesimpulan kondisi perangkat yang jelas untuk pengguna maupun pengunjung."""
    mode_tag = "SIMULASI DEMO" if is_demo else "TELEMETRI PERANGKAT AKTUAL"
    accent = posture["accent_color"]

    st.markdown(
        f"""
        <div style="
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.96), rgba(30, 41, 59, 0.92));
            border: 1px solid {accent};
            border-left: 6px solid {accent};
            border-radius: 12px;
            padding: 18px 22px;
            margin-bottom: 18px;
        ">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                <span style="font-size: 0.80rem; letter-spacing: 0.08em; color: #94a3b8; font-weight: 600;">
                    KESIMPULAN KONDISI KEAMANAN PERANGKAT • {mode_tag}
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
                    SKOR RISIKO PERANGKAT: {posture['posture_score']}/100 ({posture['risk_level']})
                </span>
            </div>
            <h3 style="margin: 10px 0 6px 0; color: #f8fafc; font-size: 1.32rem;">
                {posture['icon']} STATUS PERANGKAT: {posture['status_label']}
            </h3>
            <p style="margin: 0 0 8px 0; color: #e2e8f0; font-weight: 600; font-size: 1.0rem;">
                {posture['headline']}
            </p>
            <p style="margin: 0; color: #cbd5e1; font-size: 0.93rem; line-height: 1.55;">
                {posture['conclusion_text']}
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.expander("Lihat Rincian 5 Pilar Penilaian & Rekomendasi Tindakan Perangkat", expanded=True):
        col_left, col_right = st.columns([1.3, 1.0])
        with col_left:
            st.markdown("**Evaluasi 5 Pilar Keamanan Perangkat**")
            df_pillars = pd.DataFrame(posture["pillar_breakdown"])
            st.dataframe(df_pillars, use_container_width=True, hide_index=True)

        with col_right:
            st.markdown("**Temuan Utama**")
            for item in posture["findings"]:
                st.markdown(f"- {item}")

            st.markdown("**Rekomendasi Tindakan**")
            for rec in posture["recommendations"]:
                st.markdown(f"- **{rec}**")


def render_incidents_page(mode: Any = "LIVE") -> None:
    """Merender halaman lengkap Security Incident Center."""
    is_demo = _resolve_is_demo(mode)
    service = IncidentService()

    st.title("🛡️ Security Incident Center")
    st.caption(
        "Pusat kesimpulan kondisi keamanan perangkat, korelasi ancaman lintas modul, "
        "dan manajemen penanganan insiden (SOC Workflow)."
    )

    # 1. Kesimpulan Kondisi Perangkat (Device Security Posture)
    posture = service.get_device_posture(is_demo=is_demo)
    _render_device_conclusion_banner(posture, is_demo=is_demo)

    # 2. Ringkasan KPI Insiden
    summary = service.get_status_summary(is_demo=is_demo)
    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("Total Insiden", summary["total"])
    k2.metric("OPEN (Baru)", summary["OPEN"])
    k3.metric("INVESTIGATING", summary["INVESTIGATING"])
    k4.metric("CONTAINED", summary["CONTAINED"])
    k5.metric("RESOLVED", summary["RESOLVED"])

    st.markdown("---")

    tab_manage, tab_create, tab_correlate = st.tabs(
        [
            "📋 Daftar & Penanganan Insiden",
            "➕ Buat Insiden Baru",
            "🔗 Korelasi Event Otomatis",
        ]
    )

    # TAB 1: Daftar & Penanganan Insiden
    with tab_manage:
        f1, f2 = st.columns(2)
        with f1:
            selected_status = st.selectbox(
                "Filter Status Insiden",
                options=["SEMUA"] + VALID_INCIDENT_STATUSES,
                index=0,
            )
        with f2:
            selected_category = st.selectbox(
                "Filter Kategori Insiden",
                options=["SEMUA"] + VALID_INCIDENT_CATEGORIES,
                index=0,
            )

        incidents = service.list_incidents(
            status_filter=selected_status,
            category_filter=selected_category,
            is_demo=is_demo,
        )

        if not incidents:
            st.info(
                "Belum ada insiden yang cocok dengan filter saat ini. "
                "Anda dapat membuat insiden baru atau menjalankan Korelasi Event Otomatis."
            )
        else:
            table_rows = [
                {
                    "ID": inc["id"],
                    "Kode": inc["incident_code"],
                    "Judul Insiden": inc["title"],
                    "Kategori": inc["category"],
                    "Severity": inc["severity"],
                    "Skor": f"{inc['risk_score']}/100",
                    "Status": inc["status"],
                    "Event Terkait": inc["correlated_events_count"],
                    "Dibuat (UTC)": inc["created_at"],
                }
                for inc in incidents
            ]
            st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)

            st.subheader("Perbarui Status & Catatan Mitigasi Insiden")
            incident_options = {
                f"[{inc['incident_code']}] {inc['title']} ({inc['status']})": inc for inc in incidents
            }
            chosen_label = st.selectbox("Pilih Insiden untuk Ditangani", options=list(incident_options.keys()))
            chosen_inc = incident_options[chosen_label]

            c_info1, c_info2 = st.columns([1.2, 1.0])
            with c_info1:
                st.markdown(f"**Deskripsi:** {chosen_inc['description']}")
                if chosen_inc.get("recommended_mitigation"):
                    st.info(f"**Saran Mitigasi Sistem:** {chosen_inc['recommended_mitigation']}")

                with st.form("update_incident_form"):
                    current_idx = (
                        VALID_INCIDENT_STATUSES.index(chosen_inc["status"])
                        if chosen_inc["status"] in VALID_INCIDENT_STATUSES
                        else 0
                    )
                    new_status = st.selectbox(
                        "Ubah Status Menjadi",
                        options=VALID_INCIDENT_STATUSES,
                        index=current_idx,
                    )
                    notes_input = st.text_area(
                        "Catatan Investigasi / Tindakan Mitigasi",
                        value=chosen_inc.get("mitigation_notes", ""),
                        height=100,
                    )
                    submitted_update = st.form_submit_button("Simpan Perubahan Status", type="primary")
                    if submitted_update:
                        try:
                            ok = service.update_incident_status(
                                incident_id=chosen_inc["id"],
                                new_status=new_status,
                                mitigation_notes=notes_input,
                            )
                            if ok:
                                st.success(f"Status insiden {chosen_inc['incident_code']} diperbarui ke {new_status}.")
                                st.rerun()
                            else:
                                st.error("Insiden tidak ditemukan di database.")
                        except Exception as exc:
                            st.error(f"Gagal memperbarui status insiden: {exc}")

            with c_info2:
                st.markdown("**Timeline Investigasi Insiden**")
                timeline_entries = chosen_inc.get("timeline") or []
                if not timeline_entries:
                    st.caption("Belum ada riwayat perubahan status.")
                else:
                    for entry in timeline_entries:
                        ts = entry.get("timestamp", "-")
                        st_lbl = entry.get("status", "-")
                        note_txt = entry.get("note", "-")
                        st.markdown(f"- **`{ts}`** — **{st_lbl}**: {note_txt}")

    # TAB 2: Buat Insiden Baru
    with tab_create:
        st.subheader("Catat Insiden Keamanan Baru")
        with st.form("create_incident_form", clear_on_submit=True):
            title_in = st.text_input(
                "Judul Insiden *",
                placeholder="Contoh: Port 445 SMB Terbuka pada Antarmuka Wi-Fi Lokal",
            )
            col_a, col_b, col_c = st.columns(3)
            with col_a:
                category_in = st.selectbox("Kategori Insiden *", options=VALID_INCIDENT_CATEGORIES)
            with col_b:
                severity_in = st.selectbox("Tingkat Keparahan (Severity) *", options=VALID_SEVERITIES, index=1)
            with col_c:
                score_in = st.slider("Skor Risiko (0–100)", min_value=0, max_value=100, value=55)

            target_in = st.text_input(
                "Target / Aset Terdampak (Opsional)",
                placeholder="Contoh: 127.0.0.1:445 atau C:\\Users\\...\\config.ini",
            )
            desc_in = st.text_area(
                "Deskripsi Kronologi & Bukti Temuan *",
                placeholder="Jelaskan indikator ancaman yang ditemukan dan dampaknya pada perangkat...",
                height=110,
            )
            mitigation_in = st.text_area(
                "Rencana / Langkah Mitigasi Awal (Opsional)",
                placeholder="Kosongkan untuk menggunakan rekomendasi mitigasi standar otomatis.",
                height=80,
            )

            submitted_create = st.form_submit_button("Simpan Insiden ke Database", type="primary")
            if submitted_create:
                try:
                    code = service.create_incident(
                        title=title_in,
                        category=category_in,
                        severity=severity_in,
                        risk_score=score_in,
                        description=desc_in,
                        target=target_in,
                        mitigation_notes=mitigation_in,
                        is_demo=is_demo,
                    )
                    st.success(f"Insiden baru berhasil disimpan dengan kode **{code}**.")
                    st.rerun()
                except ValueError as val_err:
                    st.warning(str(val_err))
                except Exception as exc:
                    st.error(f"Terjadi kesalahan saat menyimpan insiden: {exc}")

    # TAB 3: Korelasi Event Otomatis
    with tab_correlate:
        st.subheader("Korelasi Event Keamanan Menjadi Insiden")
        st.write(
            "Fitur ini memindai tabel `security_events` yang memiliki tingkat risiko **MEDIUM, HIGH, atau CRITICAL** "
            "dan belum ditautkan ke insiden mana pun, lalu mengelompokkannya menjadi tiket insiden terstruktur."
        )
        if st.button("Jalankan Korelasi Event Sekarang", type="primary"):
            try:
                created_count = service.correlate_unlinked_events(is_demo=is_demo)
                if created_count > 0:
                    st.success(f"Berhasil membuat **{created_count} insiden baru** dari korelasi event keamanan.")
                    st.rerun()
                else:
                    st.info("Tidak ada event berisiko baru yang belum dikorelasikan.")
            except Exception as exc:
                st.error(f"Gagal menjalankan korelasi event: {exc}")