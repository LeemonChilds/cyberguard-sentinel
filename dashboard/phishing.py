"""
CYBERGUARD SENTINEL — Multi-Category Hybrid AI Phishing & Scam Analyzer UI

Menyediakan analisis tautan lintas kategori (Perbankan, Ekspedisi/Paket, Pemerintah/Bansos,
Game, Media Sosial, Kripto, Webmail, dan Malware APK) dengan:
- Banner peringatan real-time (Merah / Kuning / Hijau)
- Panel Audit AI Threat Intelligence (Local ML + Gemini Cloud AI)
- Pembedahan anatomi domain & tombol uji cepat multi-kategori
"""

from __future__ import annotations

import os
import pandas as pd
import streamlit as st
from modules.phishing_detector import PhishingAnalysisResult, PhishingDetector


def _render_threat_verdict_banner(res: PhishingAnalysisResult) -> None:
    """Merender banner status ancaman yang selaras 100% dengan klasifikasi dan skor risiko."""
    if res.classification == "PHISHING" or res.risk_score >= 60:
        border_color = "#ef4444"
        bg_grad = "linear-gradient(90deg, rgba(127, 29, 29, 0.85), rgba(15, 23, 42, 0.96))"
        badge_bg = "rgba(239, 68, 68, 0.22)"
        badge_text = f"🚨 CRITICAL PHISHING ALERT • {res.severity}"
        icon = "🚨"
    elif res.classification == "SUSPICIOUS" or res.risk_score >= 30:
        border_color = "#f59e0b"
        bg_grad = "linear-gradient(90deg, rgba(120, 53, 15, 0.85), rgba(15, 23, 42, 0.96))"
        badge_bg = "rgba(245, 158, 11, 0.22)"
        badge_text = f"⚠️ SUSPICIOUS LINK • {res.severity}"
        icon = "⚠️"
    else:
        border_color = "#10b981"
        bg_grad = "linear-gradient(90deg, rgba(6, 78, 59, 0.80), rgba(15, 23, 42, 0.96))"
        badge_bg = "rgba(16, 185, 129, 0.22)"
        badge_text = f"✅ VERIFIED SAFE • {res.severity}"
        icon = "✅"

    category_html = (
        f"<div style='margin-top:8px; color:#bae6fd; font-size:0.90rem;'>"
        f"<strong>📂 Kategori Analisis:</strong> {res.attack_category}"
        f"</div>"
    )

    brand_html = ""
    if res.impersonated_brand:
        official_str = ", ".join(res.official_domains) if res.official_domains else "-"
        if res.classification == "SAFE":
            brand_html = (
                f"<div style='margin-top:6px; color:#6ee7b7; font-size:0.92rem;'>"
                f"<strong>🏛️ Identitas Resmi Terverifikasi:</strong> {res.impersonated_brand} ({official_str})"
                f"</div>"
            )
        else:
            official_note = (
                f"(Domain resmi seharusnya: <code>{official_str}</code>, bukan <code>{res.registered_domain}</code>)"
                if res.official_domains
                else f"(Domain palsu yang digunakan: <code>{res.registered_domain}</code>)"
            )
            brand_html = (
                f"<div style='margin-top:8px; padding:8px 12px; background:rgba(0,0,0,0.45); "
                f"border-left:3px solid {border_color}; color:#fecaca; font-size:0.93rem;'>"
                f"<strong>🎭 Target Penyamaran Entitas:</strong> {res.impersonated_brand} {official_note}"
                f"</div>"
            )

    st.markdown(
        f"""
        <div style="
            background: {bg_grad};
            border: 1px solid {border_color};
            border-left: 7px solid {border_color};
            border-radius: 8px;
            padding: 18px 22px;
            margin: 14px 0 18px 0;
            box-shadow: 0 8px 28px rgba(0, 0, 0, 0.65);
        ">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
                <div style="font-size:1.15rem; font-weight:800; color:#ffffff; letter-spacing:0.4px;">
                    {icon} {res.verdict_title}
                </div>
                <span style="
                    background:{badge_bg};
                    border:1px solid {border_color};
                    color:{border_color};
                    padding:4px 12px;
                    border-radius:6px;
                    font-size:0.78rem;
                    font-weight:700;
                ">{badge_text}</span>
            </div>
            <p style="margin:10px 0 0 0; color:#f1f5f9; font-size:0.96rem; line-height:1.5;">
                {res.verdict_explanation}
            </p>
            {category_html}
            {brand_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_ai_intelligence_panel(res: PhishingAnalysisResult) -> None:
    """Merender kartu analisis AI Threat Intelligence & rincian temuan AI."""
    st.subheader("🤖 AI Threat Intelligence Second-Opinion")

    if res.ai_verdict == "PHISHING":
        ai_accent = "#f43f5e"
    elif res.ai_verdict == "SUSPICIOUS":
        ai_accent = "#f59e0b"
    else:
        ai_accent = "#10b981"

    st.markdown(
        f"""
        <div style="
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.96), rgba(14, 38, 56, 0.92));
            border: 1px solid #38bdf855;
            border-left: 5px solid {ai_accent};
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 14px;
        ">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
                <span style="color:#38bdf8; font-weight:700; font-size:0.86rem; letter-spacing:0.5px;">
                    🧠 ENGINE: {res.ai_engine_mode}
                </span>
                <span style="color:{ai_accent}; font-weight:800; font-size:0.90rem;">
                    AI VERDICT: {res.ai_verdict} • PROBABILITAS: {res.ai_phishing_probability:.1f}% • KEYAKINAN: {res.ai_confidence}
                </span>
            </div>
            <p style="margin:10px 0 0 0; color:#e2e8f0; font-size:0.94rem; line-height:1.5;">
                {res.ai_reasoning}
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if res.ai_red_flags:
        st.markdown("**🎯 Poin Analisis Semantik Gemini AI:**")
        for flag in res.ai_red_flags:
            st.markdown(f"- 🧠 {flag}")

    if res.ai_feature_weights:
        with st.expander("📊 Lihat Rincian Bobot Fitur Model ML Leksikal", expanded=False):
            st.dataframe(pd.DataFrame(res.ai_feature_weights), use_container_width=True, hide_index=True)


def render_phishing_page(mode: str = "REAL-TIME") -> None:
    """Merender halaman Multi-Category Hybrid AI Phishing & Scam Analyzer."""
    is_demo = mode.upper() == "DEMO"
    detector = PhishingDetector()

    st.markdown(
        """
        <div style="background: linear-gradient(135deg, #071926 0%, #0b2638 100%);
                    border: 1px solid #00f0ff44; border-left: 4px solid #00f0ff;
                    border-radius: 10px; padding: 18px 22px; margin-bottom: 18px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <div>
                    <h2 style="margin:0; color:#e6f7ff; font-size:1.35rem; letter-spacing:0.5px;">
                        🎣 Multi-Category Hybrid AI Phishing & Scam Analyzer
                    </h2>
                    <p style="margin:4px 0 0 0; color:#8bb8d0; font-size:0.88rem;">
                        Mendeteksi penipuan lintas kategori: Perbankan, Ekspedisi/Paket, Pemerintah/Bansos, Game, Media Sosial, Kripto, dan Malware APK.
                    </p>
                </div>
                <span style="background:#00f0ff1a; color:#00f0ff; border:1px solid #00f0ff66;
                             padding:5px 12px; border-radius:6px; font-size:0.75rem; font-weight:700;">
                    🤖 HYBRID AI • ALL-LINK SHIELD
                </span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if "phishing_url_input" not in st.session_state:
        st.session_state["phishing_url_input"] = "hxxp://login-bri.verifikasi-akun.xyz"

    st.caption("⚡ Uji Cepat Multi-Kategori (Klik untuk mengisi contoh tautan):")
    q1, q2, q3, q4, q5 = st.columns(5)
    if q1.button("📦 Paket Palsu", use_container_width=True):
        st.session_state["phishing_url_input"] = "http://cek-resi-jne.paket-tertahan.xyz/konfirmasi"
    if q2.button("🏛️ Bansos Palsu", use_container_width=True):
        st.session_state["phishing_url_input"] = "http://daftar-bansos-kemensos.bantuan-2026.top/klaim"
    if q3.button("🎮 Akun Game", use_container_width=True):
        st.session_state["phishing_url_input"] = "https://steamcommunity-gift.nitro-reward.click/login"
    if q4.button("💌 Undangan APK", use_container_width=True):
        st.session_state["phishing_url_input"] = "http://undangan-pernikahan-digital.my.id/undangan.apk"
    if q5.button("✅ Situs Resmi", use_container_width=True):
        st.session_state["phishing_url_input"] = "https://www.kemensos.go.id"

    url_input = st.text_input(
        "Masukkan URL / Tautan yang Diterima (dari Email, WhatsApp, SMS, atau Browser):",
        placeholder="Contoh: https://jne.co.id atau http://cek-resi-jne.paket-tertahan.xyz",
        key="phishing_url_input",
    )

    env_key_exists = bool(os.getenv("GEMINI_API_KEY", "").strip())
    with st.expander("⚙️ Konfigurasi Real-Time Cloud AI Auditor (Gemini API Key)", expanded=False):
        if env_key_exists:
            st.success("GEMINI_API_KEY terdeteksi aktif dari environment (.env). Audit Hybrid Gemini AI siap digunakan.")
        else:
            st.caption(
                "Local ML Lexical AI selalu aktif secara real-time tanpa API Key. "
                "Tambahkan GEMINI_API_KEY di file .env atau masukkan di bawah ini untuk audit semantik lintas semua kategori."
            )
        session_gemini_key = st.text_input(
            "Gemini API Key (Opsional jika sudah ada di .env):",
            type="password",
            placeholder="AIzaSy...",
            key="phishing_gemini_api_key",
        )

    col_chk, col_btn = st.columns([2.4, 1.2])
    with col_chk:
        perform_live_http = st.checkbox(
            "Aktifkan Resolusi DNS & Inspeksi HTTP Header / Redirect Langsung (Timeout 5 detik)",
            value=True,
            key="phishing_live_http_chk",
        )
    with col_btn:
        analyze_clicked = st.button(
            "⚡ Analisis Tautan + AI Sekarang",
            type="primary",
            use_container_width=True,
            key="btn_analyze_phishing_url",
        )

    if analyze_clicked:
        if not url_input.strip():
            st.warning("Silakan masukkan URL terlebih dahulu sebelum memulai analisis.")
        else:
            with st.spinner("Menjalankan analisis forensik URL, DNS, HTTP, dan klasifikasi Hybrid AI..."):
                try:
                    analysis = detector.analyze_url(
                        raw_url=url_input.strip(),
                        perform_live_http=perform_live_http,
                        save_to_db=True,
                        is_demo=is_demo,
                        gemini_api_key=session_gemini_key.strip() or None,
                    )
                    st.session_state["latest_phishing_result"] = analysis
                    if analysis.classification == "PHISHING":
                        st.toast(
                            f"BAHAYA PHISHING! Skor: {analysis.risk_score}/100 (AI: {analysis.ai_phishing_probability}%)",
                            icon="🚨",
                        )
                    elif analysis.classification == "SUSPICIOUS":
                        st.toast(
                            f"WASPADA! Skor: {analysis.risk_score}/100 (AI: {analysis.ai_phishing_probability}%)",
                            icon="⚠️",
                        )
                    else:
                        st.toast(
                            f"AMAN! Skor: {analysis.risk_score}/100 (AI: {analysis.ai_phishing_probability}%)",
                            icon="✅",
                        )
                except ValueError as val_err:
                    st.error(f"Input URL tidak valid: {val_err}")
                except Exception as exc:
                    st.error(f"Terjadi kesalahan saat menganalisis tautan: {exc}")

    res: PhishingAnalysisResult | None = st.session_state.get("latest_phishing_result")
    if res is not None:
        st.subheader("🛡️ HASIL ANALISIS KEAMANAN TAUTAN")

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Skor Risiko Gabungan", f"{res.risk_score} / 100")
        c2.metric("Klasifikasi Akhir", res.classification)
        c3.metric("Probabilitas AI Phishing", f"{res.ai_phishing_probability:.1f}%")
        c4.metric("Status HTTP / Server", res.http_status_text)

        _render_threat_verdict_banner(res)
        _render_ai_intelligence_panel(res)

        st.subheader("🔬 Bedah Anatomi & Telemetri Tautan")
        anatomy_rows = [
            {"Komponen": "URL Input Mentah", "Nilai Hasil Pembacaan": res.raw_url},
            {"Komponen": "URL Ternormalisasi", "Nilai Hasil Pembacaan": res.normalized_url},
            {"Komponen": "Kategori Modus", "Nilai Hasil Pembacaan": res.attack_category},
            {
                "Komponen": "Protokol & Enkripsi",
                "Nilai Hasil Pembacaan": f"{res.scheme.upper()} ({'Terenkripsi HTTPS' if res.is_https else 'TIDAK TERENKRIPSI / HTTP'})",
            },
            {
                "Komponen": "Subdomain (Sering Dipakai Mengecoh)",
                "Nilai Hasil Pembacaan": res.subdomain if res.subdomain else "(Tidak ada subdomain)",
            },
            {"Komponen": "Domain Utama Terdaftar (Asli)", "Nilai Hasil Pembacaan": res.registered_domain},
            {
                "Komponen": "Ekstensi Domain (TLD)",
                "Nilai Hasil Pembacaan": f".{res.tld}" if res.tld != "IP" else "Alamat IP Langsung",
            },
            {"Komponen": "Status DNS Real-Time", "Nilai Hasil Pembacaan": res.dns_status_text},
            {"Komponen": "URL Tujuan Akhir", "Nilai Hasil Pembacaan": res.final_url},
        ]
        st.dataframe(pd.DataFrame(anatomy_rows), use_container_width=True, hide_index=True)

        st.subheader("🔍 Indikator Teknis yang Ditemukan")
        if res.indicators:
            for ind in res.indicators:
                badge = (
                    "🔴"
                    if ind.severity in {"CRITICAL", "HIGH"}
                    else ("🟠" if ind.severity == "MEDIUM" else "🔵")
                )
                st.markdown(
                    f"- {badge} **`[{ind.code}]`** *(+{ind.points} poin • {ind.severity})*: {ind.description}"
                )
        else:
            st.info("Tidak ditemukan indikator anomali pada struktur maupun reputasi domain tautan ini.")

        st.subheader("🧰 Rekomendasi Tindakan Keamanan")
        for step in res.mitigation_steps:
            st.markdown(f"- {step}")

    st.divider()
    st.subheader("📜 Riwayat Analisis Tautan (Database Log)")
    try:
        history = detector.get_recent_history(is_demo=is_demo, limit=15)
        if history:
            st.dataframe(pd.DataFrame(history), use_container_width=True, hide_index=True)
        else:
            st.info("Belum ada riwayat analisis tautan tersimpan di database.")
    except Exception as exc:
        st.error(f"Gagal memuat riwayat analisis tautan: {exc}")