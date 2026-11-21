"""
CYBERGUARD SENTINEL — Page 03: Network Monitoring Engine (Real-Time Stream)

Menyediakan pemantauan soket koneksi aktif, antarmuka IPv4, dan filter proses
secara otomatis setiap 3 detik menggunakan @st.fragment.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st
from dashboard.ui_components import render_mode_banner, render_page_header
from modules.network_monitor import NetworkMonitor, NetworkSnapshotReport


def _render_snapshot_details(report: NetworkSnapshotReport, process_filter: str) -> None:
    """Merender metrik jaringan, tabel antarmuka IP, dan daftar soket aktif."""
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Primary Host IP", report.primary_local_ip)
    m2.metric("ESTABLISHED (Aktif)", report.established_count)
    m3.metric("LISTENING (Port Siaga)", report.listening_count)
    m4.metric("Skor Risiko Jaringan", f"{report.risk_score} / 100")

    notes_list = getattr(report, "observations", None) or getattr(report, "risk_notes", [])
    summary_notes = "; ".join(notes_list) if notes_list else "Koneksi jaringan lokal berjalan normal."

    if report.risk_score >= 60:
        st.error(f"🚨 **ANOMALI JARINGAN TINGGI ({report.severity}):** {summary_notes}")
    elif report.risk_score >= 30:
        st.warning(f"⚠️ **PERINGATAN JARINGAN ({report.severity}):** {summary_notes}")
    else:
        st.success(f"✅ **JARINGAN AMAN ({report.severity}):** {summary_notes}")

    col_if, col_conn = st.columns([1, 2.1])

    with col_if:
        st.markdown("#### 🖧 Antarmuka Jaringan")
        if report.interfaces:
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Interface": iface.name,
                            "IPv4": iface.ipv4_address,
                            "Status": "UP" if iface.is_up else "DOWN",
                        }
                        for iface in report.interfaces
                    ]
                ),
                use_container_width=True,
                hide_index=True,
            )

    with col_conn:
        st.markdown("#### 🔗 Live Active Sockets & Process Mapping")
        if report.connections:
            rows = [
                {
                    "Protokol": c.protocol,
                    "Lokal": c.local_address,
                    "Remote": c.remote_address,
                    "Status": c.status,
                    "PID": c.pid if c.pid is not None else "-",
                    "Nama Proses": c.process_name,
                }
                for c in report.connections
            ]
            df_conn = pd.DataFrame(rows)
            if process_filter.strip():
                kw = process_filter.strip().lower()
                df_conn = df_conn[
                    df_conn["Nama Proses"].str.lower().str.contains(kw, na=False)
                    | df_conn["Remote"].str.lower().str.contains(kw, na=False)
                    | df_conn["Lokal"].str.lower().str.contains(kw, na=False)
                ]
            st.dataframe(df_conn, use_container_width=True, hide_index=True)
        else:
            st.info("Tidak ada koneksi soket aktif yang terdeteksi.")


@st.fragment(run_every=3)
def _realtime_network_fragment(is_demo: bool, process_filter: str) -> None:
    """Memperbarui telemetri soket jaringan secara real-time setiap 3 detik."""
    monitor = NetworkMonitor()
    report = monitor.capture_snapshot(save_to_db=False, is_demo=is_demo)
    _render_snapshot_details(report, process_filter)


def render_network_page(current_mode: str) -> None:
    """Merender halaman Network Monitoring Engine."""
    render_mode_banner(current_mode)
    render_page_header(
        title="🌐 Real-Time Network & Socket Monitor",
        subtitle="Inspeksi koneksi jaringan aktif, pemetaan proses aplikasi, dan deteksi layanan terbuka secara live.",
        module_code="MODULE 02 • LIVE SOCKET",
    )

    is_demo = current_mode == "DEMO"
    monitor = NetworkMonitor()

    c1, c2, c3 = st.columns([1.8, 1.4, 2.2])
    with c1:
        save_snap = st.button("💾 Rekam Snapshot ke Database", type="primary", use_container_width=True)
    with c2:
        live_net_stream = st.toggle("🟢 LIVE SOCKET STREAM (3s)", value=True)
    with c3:
        proc_filter = st.text_input(
            "Filter Proses / IP:",
            placeholder="Ketik nama aplikasi (misal: chrome, Code, python)...",
            label_visibility="collapsed",
        )

    if save_snap:
        saved_rep = monitor.capture_snapshot(save_to_db=True, is_demo=is_demo)
        st.success(
            f"Snapshot jaringan berhasil disimpan ke database! "
            f"({saved_rep.established_count} ESTABLISHED, {saved_rep.listening_count} LISTENING)"
        )

    if live_net_stream:
        _realtime_network_fragment(is_demo=is_demo, process_filter=proc_filter)
    else:
        report = monitor.capture_snapshot(save_to_db=False, is_demo=is_demo)
        _render_snapshot_details(report, proc_filter)

    st.divider()
    st.markdown(f"### 📜 Riwayat Snapshot Tersimpan ({current_mode} MODE)")
    history = monitor.get_snapshot_history(is_demo=is_demo, limit=15)
    if history:
        st.dataframe(pd.DataFrame(history), use_container_width=True, hide_index=True)
    else:
        st.info("Belum ada snapshot yang direkam ke database.")