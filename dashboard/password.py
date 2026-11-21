"""
CYBERGUARD SENTINEL — Password Security Analyzer Dashboard (Module 04 UI)

Antarmuka interaktif untuk menguji kekuatan kata sandi secara lokal:
- Zero-Storage Privacy Guarantee (kata sandi tidak pernah disimpan/dicatat)
- Mode DEMO dengan sampel kata sandi simulasi yang aman untuk pameran
- Rincian entropi, estimasi waktu brute-force, checklist kriteria, dan rekomendasi
"""

from __future__ import annotations

import pandas as pd
import streamlit as st
from modules.password_analyzer import PasswordAnalysisResult, PasswordAnalyzer


def _render_strength_banner(res: PasswordAnalysisResult) -> None:
    """Merender banner hasil evaluasi kekuatan kata sandi."""
    if res.strength in {"VERY STRONG", "STRONG"}:
        border_color = "#10b981"
        bg_grad = "linear-gradient(90deg, rgba(6, 78, 59, 0.82), rgba(15, 23, 42, 0.96))"
        icon = "✅"
    elif res.strength == "MODERATE":
        border_color = "#f59e0b"
        bg_grad = "linear-gradient(90deg, rgba(120, 53, 15, 0.85), rgba(15, 23, 42, 0.96))"
        icon = "⚠️"
    else:
        border_color = "#ef4444"
        bg_grad = "linear-gradient(90deg, rgba(127, 29, 29, 0.85), rgba(15, 23, 42, 0.96))"
        icon = "🚨"

    st.markdown(
        f"""
        <div style="
            background: {bg_grad};
            border: 1px solid {border_color};
            border-left: 7px solid {border_color};
            border-radius: 8px;
            padding: 16px 20px;
            margin: 12px 0 18px 0;
        ">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
                <span style="font-size:1.12rem; font-weight:800; color:#ffffff;">
                    {icon} TINGKAT KEKUATAN: {res.strength} ({res.score}/100)
                </span>
                <span style="color:{border_color}; font-weight:700; font-size:0.85rem;">
                    RISIKO KEBOCORAN: {res.severity} ({res.risk_score}/100)
                </span>
            </div>
            <p style="margin:8px 0 0 0; color:#e2e8f0; font-size:0.93rem;">
                Estimasi ketahanan terhadap serangan brute-force offline: <strong>{res.crack_time_display}</strong>
                (Entropi: <strong>{res.entropy_bits} bits</strong>).
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_password_page(mode: str = "REAL-TIME") -> None:
    """Merender halaman Password Security Analyzer."""
    is_demo = mode.upper() == "DEMO"
    analyzer = PasswordAnalyzer()

    st.markdown(
        """
        <div style="background: linear-gradient(135deg, #071926 0%, #0b2638 100%);
                    border: 1px solid #00f0ff44; border-left: 4px solid #00f0ff;
                    border-radius: 10px; padding: 18px 22px; margin-bottom: 18px;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
                <div>
                    <h2 style="margin:0; color:#e6f7ff; font-size:1.35rem; letter-spacing:0.5px;">
                        🔐 Password Security & Entropy Analyzer
                    </h2>
                    <p style="margin:4px 0 0 0; color:#8bb8d0; font-size:0.88rem;">
                        Audit kekuatan kombinasi kata sandi secara lokal tanpa menyimpan atau mengirim teks sandi ke mana pun.
                    </p>
                </div>
                <span style="background:#10b9811f; color:#34d399; border:1px solid #10b98166;
                             padding:5px 12px; border-radius:6px; font-size:0.75rem; font-weight:700;">
                    🛡️ ZERO-STORAGE PRIVACY
                </span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    candidate: str = ""

    if is_demo:
        st.info(
            "🧪 **MODE DEMO AKTIF:** Pilih salah satu contoh kata sandi simulasi di bawah ini untuk demonstrasi publik "
            "tanpa menggunakan kata sandi pribadi Anda."
        )
        demo_choice = st.selectbox(
            "Pilih Sampel Kata Sandi Simulasi:",
            options=[
                "rahasia123 (Contoh Lemah — Kata Umum & Angka Urut)",
                "Sman1Bali2026 (Contoh Sedang — Tanpa Simbol & Pola Tahun)",
                "Kopi@Bali#2026!Aman (Contoh Sangat Kuat — Panjang & Beragam)",
            ],
            key="demo_password_selector",
        )
        candidate = demo_choice.split(" (")[0].strip()
    else:
        st.caption(
            "🔒 Kata sandi hanya diproses sementara di RAM lokal komputer ini dan langsung dibersihkan setelah analisis selesai."
        )
        candidate = st.text_input(
            "Masukkan Kata Sandi Uji (Gunakan sandi simulasi, jangan sandi akun aktif):",
            type="password",
            placeholder="Ketik kata sandi uji di sini...",
            key="realtime_password_candidate",
        )

    analyze_btn = st.button(
        "🔍 Analisis Kekuatan Kata Sandi",
        type="primary",
        key="btn_run_password_analysis",
    )

    if analyze_btn:
        if not candidate:
            st.warning("Silakan masukkan kata sandi uji terlebih dahulu sebelum menjalankan analisis.")
        else:
            try:
                res = analyzer.analyze(
                    password=candidate,
                    save_metadata_to_db=True,
                    is_demo=is_demo,
                )
                st.session_state["latest_password_audit"] = res
            except ValueError as val_err:
                st.error(f"Input tidak valid: {val_err}")
            except Exception as exc:
                st.error(f"Terjadi kesalahan saat menganalisis kata sandi: {exc}")
            finally:
                candidate = ""

    latest_res: PasswordAnalysisResult | None = st.session_state.get("latest_password_audit")
    if latest_res is not None:
        _render_strength_banner(latest_res)

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Skor Kekuatan", f"{latest_res.score} / 100")
        m2.metric("Panjang Karakter", f"{latest_res.length} karakter")
        m3.metric("Entropi Sandi", f"{latest_res.entropy_bits} bits")
        m4.metric("Estimasi Brute-Force", latest_res.crack_time_display)

        st.progress(latest_res.score / 100.0)

        st.subheader("📋 Audit Kriteria & Komposisi Karakter")
        st.dataframe(pd.DataFrame(latest_res.criteria_checks), use_container_width=True, hide_index=True)

        col_f, col_r = st.columns(2)
        with col_f:
            st.subheader("🔎 Temuan Analisis")
            for item in latest_res.findings:
                st.markdown(f"- {item}")
        with col_r:
            st.subheader("🧰 Rekomendasi Penguatan")
            for rec in latest_res.recommendations:
                st.markdown(f"- {rec}")