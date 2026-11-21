"""
CYBERGUARD SENTINEL — Reusable Mil-Spec SOC UI Components

Menyediakan komponen antarmuka Tactical Command Center dengan bilah telemetri
waktu nyata, radar pulse indicator, dan header HUD futuristik.
"""

from __future__ import annotations

from datetime import datetime, timezone
import streamlit as st
import config


def inject_custom_css() -> None:
    """Memuat stylesheet kustom Mil-Spec SOC dari assets/style.css."""
    css_path = config.ASSETS_DIR / "style.css"
    if css_path.exists():
        css_content = css_path.read_text(encoding="utf-8")
        st.markdown(f"<style>{css_content}</style>", unsafe_allow_html=True)


def render_mode_banner(current_mode: str) -> None:
    """
    Menampilkan bilah telemetri atas dengan animasi scanline, status sensor,
    dan jam operasi UTC secara real-time.
    """
    utc_stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if current_mode == "DEMO":
        st.markdown(
            f"""
            <div class="cyber-top-telemetry-demo">
                <div>
                    <span class="radar-dot-demo"></span>
                    <strong style="font-family:'JetBrains Mono',monospace; color:#fbbf24;">
                        [TELEMETRY: OFFLINE SIMULATION MODE]
                    </strong>
                    <span style="color:#fef3c7; font-size:0.9rem;"> — Sandbox Dataset Aktif (Tanpa Akses Jaringan)</span>
                </div>
                <div style="font-family:'JetBrains Mono',monospace; font-size:0.8rem; color:#fcd34d;">
                    SYS-CLOCK: {utc_stamp}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f"""
            <div class="cyber-top-telemetry">
                <div>
                    <span class="radar-dot-live"></span>
                    <strong style="font-family:'JetBrains Mono',monospace; color:#34d399;">
                        [ACTIVE DEFENSE: LIVE TELEMETRY ONLINE]
                    </strong>
                    <span style="color:#d1fae5; font-size:0.9rem;"> — Sensor Host <code>127.0.0.1</code> Terkunci & Memantau</span>
                </div>
                <div style="font-family:'JetBrains Mono',monospace; font-size:0.8rem; color:#00f0ff;">
                    SYS-CLOCK: {utc_stamp}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_page_header(title: str, subtitle: str, module_code: str) -> None:
    """Menampilkan header halaman bergaya Command Center HUD dengan sudut terpotong."""
    st.markdown(
        f"""
        <div class="command-banner">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
                <div>
                    <div class="command-title">{title}</div>
                    <div class="command-subtitle">{subtitle}</div>
                </div>
                <div>
                    <span class="module-chip">⚡ {module_code}</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )