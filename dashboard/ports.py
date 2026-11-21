"""
CYBERGUARD SENTINEL — Web & Network Port Security Scanner Dashboard (Module 05 UI)

Antarmuka pemindaian port TCP (1 - 65535) secara defensif dan terotorisasi:
- Mendukung target localhost (127.0.0.1), IP jaringan lokal (LAN), atau domain/URL web milik sendiri
- Preset khusus Web & API, Network & Infrastruktur, Database, maupun input port bebas 1 - 65535
- Pembatasan defensif maksimal 100 port per sesi pemindaian
- Menampilkan kategori layanan (WEB / NETWORK / DATABASE / CUSTOM), tingkat risiko, dan mitigasi
"""

from __future__ import annotations

import pandas as pd
import streamlit as st
from modules.port_scanner import (
    DATABASE_PORTS_PRESET,
    NETWORK_PORTS_PRESET,
    WEB_PORTS_PRESET,
    PortFinding,
    PortScanReport,
    PortScanner,
)


def _parse_custom_ports(raw_text: str) -> list[int]:
    ports: list[int] = []
    for part in raw_text.split(","):
        cleaned = part.strip()
        if not cleaned:
            continue
        if "-" in cleaned:
            bounds = cleaned.split("-", 1)
            if len(bounds) != 2 or not bounds[0].strip().isdigit() or not bounds[1].strip().isdigit():
                raise ValueError(f"Format rentang '{cleaned}' tidak valid. Gunakan format seperti 8000-8010.")
            start_b, end_b = int(bounds[0].strip()), int(bounds[1].strip())
            if start_b > end_b or start_b < 1 or end_b > 65535:
                raise ValueError(f"Rentang '{cleaned}' harus berada di antara 1 hingga 65535.")
            if (end_b - start_b + 1) > 100:
                raise ValueError(f"Rentang '{cleaned}' melebihi batas maksimal 100 port per sesi.")
            ports.extend(range(start_b, end_b + 1))
        else:
            if not cleaned.isdigit():
                raise ValueError(f"Port '{cleaned}' bukan angka yang valid.")
            ports.append(int(cleaned))
    if not ports:
        raise ValueError("Masukkan minimal satu nomor port antara 1 hingga 65535 (contoh: 80, 443, 8080, 3306).")
    return sorted(set(ports))


def _build_demo_report(target_host: str, preset_label: str) -> PortScanReport:
    """Menyediakan hasil simulasi aman saat pengguna mengaktifkan Mode DEMO."""
    clean_target = PortScanner.normalize_target_input(target_host or "demo-server.local")
    demo_findings = [
        PortFinding(
            port=80,
            state="OPEN",
            service="HTTP Web Server",
            category="WEB",
            risk_level="LOW",
            points=10,
            recommendation="Server web tanpa enkripsi TLS; alihkan lalu lintas ke HTTPS (443).",
        ),
        PortFinding(
            port=443,
            state="OPEN",
            service="HTTPS Secure Web",
            category="WEB",
            risk_level="LOW",
            points=5,
            recommendation="Server web terenkripsi TLS/SSL; pastikan sertifikat valid dan TLS 1.2/1.3 aktif.",
        ),
        PortFinding(
            port=22,
            state="OPEN",
            service="SSH Remote Shell",
            category="NETWORK",
            risk_level="MEDIUM",
            points=15,
            recommendation="Akses remote aman; gunakan SSH key, nonaktifkan root login, dan batasi IP.",
        ),
        PortFinding(
            port=3306,
            state="OPEN",
            service="MySQL / MariaDB",
            category="DATABASE",
            risk_level="HIGH",
            points=30,
            recommendation="Database relasional; jangan ekspos langsung ke internet publik.",
        ),
    ]
    return PortScanReport(
        target_host=clean_target,
        resolved_ip="192.168.10.25 (Simulasi)",
        target_scope="DEMO_SIMULATION",
        port_range_label=preset_label,
        total_scanned=20,
        open_ports=demo_findings,
        closed_ports_count=16,
        duration_seconds=0.12,
        risk_score=60,
        severity="HIGH",
        summary=(
            f"[SIMULASI DEMO] Ditemukan 4 port terbuka pada {clean_target}: "
            "80/HTTP, 443/HTTPS, 22/SSH, dan 3306/MySQL."
        ),
        recommendations=[
            f"Port {f.port} [{f.category}] ({f.service} — {f.risk_level}): {f.recommendation}"
            for f in demo_findings
        ],
    )


def render_ports_page(mode: str = "REAL-TIME") -> None:
    """Merender halaman Web & Network Port Security Scanner."""
    is_demo = mode.upper() == "DEMO"
    scanner = PortScanner()

    st.markdown(
        """
        <div style="background: linear-gradient(135deg, #071926 0%, #0b2638 100%);
                    border: 1px solid #00f0ff44; border-left: 4px solid #00f0ff;
                    border-radius: 10px; padding: 18px 22px; margin-bottom: 18px;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
                <div>
                    <h2 style="margin:0; color:#e6f7ff; font-size:1.35rem; letter-spacing:0.5px;">
                        🔌 Web &amp; Network Port Security Scanner
                    </h2>
                    <p style="margin:4px 0 0 0; color:#8bb8d0; font-size:0.88rem;">
                        Audit layanan TCP pada port 1–65535 untuk server Web, perangkat Network lokal, maupun Database terotorisasi.
                    </p>
                </div>
                <span style="background:#00f0ff1a; color:#00f0ff; border:1px solid #00f0ff66;
                             padding:5px 12px; border-radius:6px; font-size:0.75rem; font-weight:700;">
                    🛡️ AUTHORIZED AUDIT (1–65535)
                </span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if is_demo:
        st.info("🧪 **MODE DEMO AKTIF:** Menampilkan simulasi audit port gabungan Web & Network tanpa mengirim paket keluar.")

    col_host, col_mode = st.columns([1.35, 1.65])
    with col_host:
        target_host = st.text_input(
            "Target Host / IP / Domain Web:",
            value="127.0.0.1",
            placeholder="Contoh: 127.0.0.1, 192.168.1.1, atau domain-web-anda.com",
            key="port_scanner_target_host",
        )
    with col_mode:
        scan_preset = st.selectbox(
            "Kategori & Metode Pemilihan Port:",
            options=[
                "Web & Aplikasi (HTTP, HTTPS, API, Dev Server)",
                "Network & Infrastruktur (SSH, DNS, SMB, RDP, Mail)",
                "Database & Cache Server (MySQL, PostgreSQL, Redis, MongoDB)",
                "Gabungan Web + Network + Database (Top 30 Port)",
                "Custom Port Bebas (Port Apa Saja 1–65535)",
                "Rentang Port Bebas (Start–End, Maksimal 100 Port)",
            ],
            key="port_scanner_preset",
        )

    cleaned_preview = target_host.strip().lower()
    is_localhost = cleaned_preview in {"", "127.0.0.1", "localhost", "::1", "http://127.0.0.1", "http://localhost"}
    is_authorized = True

    if not is_localhost and not is_demo:
        is_authorized = st.checkbox(
            f"Saya menyatakan bahwa '{target_host.strip()}' adalah aset milik saya atau saya memiliki izin resmi untuk mengauditnya.",
            value=False,
            key="port_scanner_auth_chk",
        )

    custom_ports_list: list[int] | None = None
    start_port = 1
    end_port = 100

    if scan_preset == "Web & Aplikasi (HTTP, HTTPS, API, Dev Server)":
        default_str = ", ".join(str(p) for p in WEB_PORTS_PRESET)
        ports_text = st.text_input(
            "Daftar Port Web yang Akan Diperiksa (bisa ditambah/ubah):",
            value=default_str,
            key="port_list_web",
        )
    elif scan_preset == "Network & Infrastruktur (SSH, DNS, SMB, RDP, Mail)":
        default_str = ", ".join(str(p) for p in NETWORK_PORTS_PRESET)
        ports_text = st.text_input(
            "Daftar Port Network yang Akan Diperiksa (bisa ditambah/ubah):",
            value=default_str,
            key="port_list_network",
        )
    elif scan_preset == "Database & Cache Server (MySQL, PostgreSQL, Redis, MongoDB)":
        default_str = ", ".join(str(p) for p in DATABASE_PORTS_PRESET)
        ports_text = st.text_input(
            "Daftar Port Database yang Akan Diperiksa (bisa ditambah/ubah):",
            value=default_str,
            key="port_list_db",
        )
    elif scan_preset == "Gabungan Web + Network + Database (Top 30 Port)":
        combined_ports = sorted(set(WEB_PORTS_PRESET[:10] + NETWORK_PORTS_PRESET[:12] + DATABASE_PORTS_PRESET[:8]))
        default_str = ", ".join(str(p) for p in combined_ports)
        ports_text = st.text_input(
            "Daftar Port Gabungan Web & Network (bisa ditambah/ubah):",
            value=default_str,
            key="port_list_combined",
        )
    elif scan_preset == "Custom Port Bebas (Port Apa Saja 1–65535)":
        ports_text = st.text_input(
            "Masukkan Port Bebas (pisahkan dengan koma atau rentang kecil, contoh: 80, 443, 8080, 25565, 50000-50010):",
            value="80, 443, 8000, 8080, 8443, 8501",
            key="port_list_free_custom",
        )
    else:
        c_start, c_end = st.columns(2)
        with c_start:
            start_port = int(
                st.number_input("Port Awal (1–65535):", min_value=1, max_value=65535, value=1, step=1, key="port_start_num")
            )
        with c_end:
            end_port = int(
                st.number_input(
                    "Port Akhir (Maksimal +99 dari Port Awal):",
                    min_value=1,
                    max_value=65535,
                    value=100,
                    step=1,
                    key="port_end_num",
                )
            )
        ports_text = ""

    scan_clicked = st.button(
        "🚀 Mulai Audit Port",
        type="primary",
        key="btn_start_port_scan",
    )

    if scan_clicked:
        with st.spinner(f"Memeriksa port TCP pada {target_host.strip() or '127.0.0.1'}..."):
            try:
                if is_demo:
                    report = _build_demo_report(target_host, scan_preset)
                elif scan_preset == "Rentang Port Bebas (Start–End, Maksimal 100 Port)":
                    report = scanner.scan_ports(
                        target_host=target_host,
                        start_port=start_port,
                        end_port=end_port,
                        is_authorized=is_authorized,
                        save_to_db=True,
                        is_demo=False,
                    )
                else:
                    custom_ports_list = _parse_custom_ports(ports_text)
                    report = scanner.scan_ports(
                        target_host=target_host,
                        custom_ports=custom_ports_list,
                        is_authorized=is_authorized,
                        save_to_db=True,
                        is_demo=False,
                    )
                st.session_state["latest_port_scan_report"] = report
            except ValueError as val_err:
                st.error(f"Validasi pemindaian gagal: {val_err}")
            except Exception as exc:
                st.error(f"Terjadi kesalahan saat memindai port: {exc}")

    latest_report: PortScanReport | None = st.session_state.get("latest_port_scan_report")
    if latest_report is not None:
        st.subheader("📊 Hasil Audit Port Web & Network")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Target & IP", f"{latest_report.target_host} ({latest_report.resolved_ip})")
        m2.metric("Port Diperiksa", f"{latest_report.total_scanned} port ({latest_report.duration_seconds} dtk)")
        m3.metric("Port Terbuka", f"{latest_report.open_ports_count} terbuka")
        m4.metric("Skor Risiko Eksposur", f"{latest_report.risk_score} / 100 ({latest_report.severity})")

        if latest_report.open_ports:
            st.warning(latest_report.summary)
            rows = [
                {
                    "Port": f.port,
                    "Kategori": f.category,
                    "Status": f.state,
                    "Layanan": f.service,
                    "Tingkat Risiko": f.risk_level,
                    "Poin Risiko": f.points,
                    "Rekomendasi Keamanan": f.recommendation,
                }
                for f in latest_report.open_ports
            ]
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        else:
            st.success(latest_report.summary)

        st.subheader("🧰 Rekomendasi Hardening Layanan")
        for rec in latest_report.recommendations:
            st.markdown(f"- {rec}")

    st.divider()
    st.subheader("📜 Riwayat Pemindaian Port (Database Log)")
    try:
        history = scanner.get_scan_history(is_demo=is_demo, limit=15)
        if history:
            st.dataframe(pd.DataFrame(history), use_container_width=True, hide_index=True)
        else:
            st.info("Belum ada riwayat pemindaian port tersimpan di database.")
    except Exception as exc:
        st.error(f"Gagal memuat riwayat pemindaian port: {exc}")