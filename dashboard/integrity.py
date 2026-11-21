"""
CYBERGUARD SENTINEL — Page 04: File Integrity Monitor (Cloud & Local Ready)

Mendukung:
1. Browser Drag & Drop File Hasher & Verifier (SHA-256 & SHA-512) untuk pengguna web hosting.
2. Audit Baseline Direktori Server/Lokal dengan pelacakan perubahan ke SQLite.
"""

from __future__ import annotations

import hashlib
import pandas as pd
import streamlit as st
from core.validators import ValidationError
from dashboard.ui_components import render_mode_banner, render_page_header
from modules.file_integrity import FileIntegrityMonitor, IntegrityAuditReport


def _render_audit_report(report: IntegrityAuditReport) -> None:
    """Menampilkan ringkasan hasil audit integritas file berbasis SHA-256."""
    st.markdown("### 📊 Hasil Audit Integritas Direktori")
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total File", report.total_files_checked)
    m2.metric("UNCHANGED", report.unchanged_count)
    m3.metric("MODIFIED", report.modified_count)
    m4.metric("NEW FILE", report.new_file_count)
    m5.metric("DELETED FILE", report.deleted_file_count)

    if report.risk_score >= 60:
        st.error(f"🚨 **PERINGATAN INTEGRITAS ({report.severity}):** Terdeteksi modifikasi atau penghapusan file!")
    elif report.risk_score >= 30:
        st.warning(f"⚠️ **PERUBAHAN TERDETEKSI ({report.severity}):** Ditemukan file baru di luar baseline.")
    else:
        st.success("✅ **INTEGRITAS TERVERIFIKASI (UNCHANGED):** Seluruh file cocok dengan sidik jari SHA-256.")

    if report.items:
        df_items = pd.DataFrame(
            [
                {
                    "File": item.relative_path,
                    "Status": item.status,
                    "Ukuran (Bytes)": item.file_size,
                    "SHA-256 Baseline": (item.baseline_hash[:16] + "...") if item.baseline_hash else "-",
                    "SHA-256 Aktual": (item.current_hash[:16] + "...") if item.current_hash else "-",
                }
                for item in report.items
            ]
        )
        st.dataframe(df_items, use_container_width=True, hide_index=True)


def render_integrity_page(current_mode: str) -> None:
    """Merender halaman File Integrity Monitor."""
    render_mode_banner(current_mode)
    render_page_header(
        title="🔐 File Integrity & Cryptographic Hash Vault",
        subtitle="Verifikasi keaslian dokumen digital dengan sidik jari kriptografi SHA-256 & audit baseline.",
        module_code="MODULE 03 • SHA-256 VAULT",
    )

    is_demo = current_mode == "DEMO"
    monitor = FileIntegrityMonitor()
    sandbox_dir = monitor.prepare_demo_sandbox()

    tab_upload, tab_dir = st.tabs(
        ["📤 Cek & Verifikasi File Pengguna (Upload)", "📁 Audit Baseline Direktori Sistem"]
    )

    with tab_upload:
        st.markdown("#### 🔍 Hitung Sidik Jari SHA-256 / SHA-512 & Verifikasi Keaslian Dokumen")
        st.caption(
            "Unggah dokumen penting (PDF, DOCX, ZIP, EXE, Gambar, atau Kode) untuk mendapatkan sidik jari kriptografi "
            "dan memastikan file tidak pernah diubah atau disisipi malware. File diproses di memori & tidak disimpan di server."
        )

        uploaded_files = st.file_uploader(
            "Pilih atau seret file ke sini (mendukung banyak file sekaligus):",
            accept_multiple_files=True,
        )
        expected_hash = st.text_input(
            "Hash SHA-256 Pembanding (Opsional — tempel hash asli untuk memverifikasi apakah file 100% identik):",
            placeholder="Contoh: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ).strip().lower()

        if uploaded_files:
            results_rows = []
            for up_file in uploaded_files:
                file_bytes = up_file.getvalue()
                sha256_hex = hashlib.sha256(file_bytes).hexdigest()
                sha512_hex = hashlib.sha512(file_bytes).hexdigest()

                if expected_hash:
                    match_status = (
                        "✅ COCOK (100% ASLI)"
                        if sha256_hex == expected_hash
                        else "🚨 BERBEDA (FILE TELAH DIUBAH!)"
                    )
                else:
                    match_status = "HASH GENERATED"

                results_rows.append(
                    {
                        "Nama File": up_file.name,
                        "Ukuran (KB)": round(len(file_bytes) / 1024, 2),
                        "Status Verifikasi": match_status,
                        "SHA-256 Fingerprint": sha256_hex,
                        "SHA-512 (Preview)": sha512_hex[:32] + "...",
                    }
                )

            st.dataframe(pd.DataFrame(results_rows), use_container_width=True, hide_index=True)

            if expected_hash:
                if any("BERBEDA" in r["Status Verifikasi"] for r in results_rows):
                    st.error("🚨 **PERINGATAN:** Sidik jari SHA-256 file tidak cocok dengan hash pembanding!")
                else:
                    st.success("✅ **TERVERIFIKASI:** Dokumen 100% asli dan tidak mengalami modifikasi sekecil apa pun.")

    with tab_dir:
        target_path_input = st.text_input(
            "Path Direktori Server / Lokal yang Dipantau:",
            value=str(sandbox_dir),
        )
        col_b1, col_b2 = st.columns(2)
        with col_b1:
            create_btn = st.button("1. Buat / Perbarui Baseline SHA-256", type="primary", use_container_width=True)
        with col_b2:
            verify_btn = st.button("2. Jalankan Audit Integritas Sekarang", use_container_width=True)

        with st.expander("🧪 Simulasi Uji Perubahan File (Untuk Demonstrasi)"):
            s1, s2, s3 = st.columns(3)
            with s1:
                if st.button("Simulasikan Modifikasi File"):
                    monitor.simulate_tampering("modify")
                    st.warning("File `kebijakan_keamanan.txt` dimodifikasi. Klik 'Jalankan Audit Integritas Sekarang'!")
            with s2:
                if st.button("Simulasikan File Baru"):
                    monitor.simulate_tampering("new")
                    st.info("File `skrip_tidak_dikenal.py` ditambahkan.")
            with s3:
                if st.button("Reset Sandbox"):
                    monitor.simulate_tampering("reset")
                    st.success("Sandbox dikembalikan ke kondisi awal.")

        if create_btn:
            try:
                count = monitor.create_or_update_baseline(target_path_input)
                st.success(f"Baseline SHA-256 aktif untuk **{count} file** pada `{target_path_input}`.")
            except ValidationError as ve:
                st.error(f"Validasi Gagal: {ve}")

        if verify_btn:
            try:
                rep = monitor.verify_integrity(target_path_input, save_changes_to_db=True, is_demo=is_demo)
                _render_audit_report(rep)
            except ValidationError as ve:
                st.error(f"Audit Ditolak: {ve}")