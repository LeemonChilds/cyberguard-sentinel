"""
CYBERGUARD SENTINEL — Main Application Entry Point
Tagline: DETECT. ANALYZE. PROTECT.

Mengelola inisialisasi sistem rerun-safe, tema SOC Dark Navy, sakelar mode operasi
(LIVE vs DEMO), dan navigasi sidebar menuju 9 halaman utama dashboard.
"""

from __future__ import annotations


from dotenv import load_dotenv
load_dotenv()



import streamlit as st
import config
from core.database import check_database_health, init_database
from core.logger import get_logger
from core.validators import validate_mode
from dashboard.incidents import render_incidents_page
from dashboard.integrity import render_integrity_page
from dashboard.network import render_network_page
from dashboard.overview import render_overview_page
from dashboard.password import render_password_page
from dashboard.phishing import render_phishing_page
from dashboard.ports import render_ports_page
from dashboard.reports import render_reports_page
from dashboard.settings import render_settings_page
from dashboard.ui_components import inject_custom_css

logger = get_logger("cyberguard.app")


@st.cache_resource
def bootstrap_system() -> bool:
    """
    Inisialisasi database SQLite satu kali per siklus hidup server Streamlit.
    Mencegah koneksi berulang atau lock saat UI melakukan rerun.
    """
    init_database()
    logger.info("%s v%s berhasil diinisialisasi.", config.APP_NAME, config.APP_VERSION)
    return True


def _init_session_state() -> None:
    """Menginisialisasi state sesi default secara aman."""
    if "operating_mode" not in st.session_state:
        st.session_state["operating_mode"] = config.DEFAULT_MODE


def main() -> None:
    st.set_page_config(
        page_title=f"{config.APP_NAME} — {config.APP_TAGLINE}",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # 1. Bootstrap fondasi & suntikkan tema Dark Navy
    bootstrap_system()
    _init_session_state()
    inject_custom_css()

    # 2. Render Sidebar Navigasi Utama (9 Halaman)
    with st.sidebar:
        st.markdown(f"## 🛡️ {config.APP_NAME}")
        st.caption(f"**{config.APP_TAGLINE}**")
        st.divider()

        # Quick Mode Switcher di Sidebar
        mode_choice = st.selectbox(
            "Mode Operasi:",
            options=["DEMO", "LIVE"],
            index=0 if st.session_state["operating_mode"] == "DEMO" else 1,
            help="DEMO: Dataset simulasi offline. LIVE: Analisis sistem lokal nyata.",
        )
        if mode_choice != st.session_state["operating_mode"]:
            st.session_state["operating_mode"] = validate_mode(mode_choice)
            st.rerun()

        st.divider()

        menu_options = [
            "1. Overview",
            "2. Phishing Detection",
            "3. Network Monitoring",
            "4. File Integrity",
            "5. Password Analyzer",
            "6. Port Scanner",
            "7. Incident Center",
            "8. Reports",
            "9. Settings",
        ]
        selected_menu = st.radio("Navigasi Modul SOC:", options=menu_options)

        st.divider()
        db_status = "ONLINE" if check_database_health() else "OFFLINE"
        st.caption(f"Database: **{db_status}** | Versi: **v{config.APP_VERSION}**")

    # 3. Routing Halaman Aktif
    current_mode: str = st.session_state["operating_mode"]

    page_routes = {
        "1. Overview": render_overview_page,
        "2. Phishing Detection": render_phishing_page,
        "3. Network Monitoring": render_network_page,
        "4. File Integrity": render_integrity_page,
        "5. Password Analyzer": render_password_page,
        "6. Port Scanner": render_ports_page,
        "7. Incident Center": render_incidents_page,
        "8. Reports": render_reports_page,
        "9. Settings": render_settings_page,
    }

    render_func = page_routes.get(selected_menu, render_overview_page)
    render_func(current_mode)


if __name__ == "__main__":
    main()