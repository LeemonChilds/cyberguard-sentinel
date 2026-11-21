"""
CYBERGUARD SENTINEL — Page 09: System Settings & Security Guardrails

Menyediakan pengaturan mode operasi (LIVE vs DEMO), diagnostik database,
dan tampilan transparansi batasan keamanan sistem.
"""

from __future__ import annotations

import streamlit as st
import config
from core.database import check_database_health
from core.validators import validate_mode
from dashboard.ui_components import render_mode_banner, render_page_header


def render_settings_page(current_mode: str) -> None:
    """Merender halaman System Settings."""
    render_mode_banner(current_mode)
    render_page_header(
        title="⚙️ System Settings & Security Guardrails",
        subtitle="Konfigurasi mode operasi pameran/produksi serta parameter keamanan defensif sistem.",
        module_code="SYSTEM CONFIG",
    )

    st.markdown("### 1. Mode Operasi Sistem")
    selected_mode = st.radio(
        "Pilih Mode Operasi Aktif:",
        options=["DEMO", "LIVE"],
        index=0 if current_mode == "DEMO" else 1,
        horizontal=True,
        help="DEMO Mode menggunakan dataset simulasi offline. LIVE Mode menjalankan analisis lokal nyata.",
    )

    if selected_mode != current_mode:
        st.session_state["operating_mode"] = validate_mode(selected_mode)
        st.rerun()

    st.divider()
    st.markdown("### 2. Parameter Batasan Keamanan (Read-Only Guardrails)")
    col1, col2 = st.columns(2)
    with col1:
        st.text_input("Default Scan Target", value=config.DEFAULT_SCAN_TARGET, disabled=True)
        st.number_input("Maksimal Port per Pemindaian", value=config.MAX_PORTS_PER_SCAN, disabled=True)
        st.number_input("Socket Timeout (Detik)", value=config.SCAN_TIMEOUT_SECONDS, disabled=True)
    with col2:
        st.number_input("HTTP Timeout Phishing Check (Detik)", value=config.HTTP_REQUEST_TIMEOUT, disabled=True)
        st.number_input("Maksimal HTTP Redirect", value=config.MAX_HTTP_REDIRECTS, disabled=True)
        st.text_input("Kebijakan Penyimpanan Password", value="STRICT ZERO-STORAGE (Tidak Disimpan)", disabled=True)

    st.divider()
    st.markdown("### 3. Diagnostik Penyimpanan & Log")
    db_ok = check_database_health()
    if db_ok:
        st.success(f"Database SQLite Terhubung: `{config.DEFAULT_DB_PATH}`")
    else:
        st.error("Database SQLite tidak merespons.")
    st.caption(f"Lokasi Log Sistem (dengan sensor otomatis): `{config.LOG_FILE_PATH}`")