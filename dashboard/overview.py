"""
CYBERGUARD SENTINEL — Page 01: Security Overview (True Real-Time SOC Telemetry)

Menampilkan Vonis Keamanan Perangkat & Jaringan (AMAN / WASPADA / BERBAHAYA),
telemetri real-time dengan interval refresh hingga 5 menit (KB/s RX/TX, CPU/RAM),
6-Axis Radar, dan SOC Console.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import psutil
import streamlit as st
import streamlit.components.v1 as components
from core.risk_engine import classify_severity
from core.security_engine import SecurityEngine, SystemSweepSummary
from dashboard.ui_components import render_mode_banner
from services.monitoring_service import MonitoringService


def _format_interval_human(seconds: int) -> str:
    """Memformat detik menjadi label waktu yang mudah dibaca (Detik / Menit)."""
    if seconds >= 60 and seconds % 60 == 0:
        mins = seconds // 60
        return f"{mins} Menit ({seconds}d)"
    return f"{seconds} Detik"


def _format_interval_short(seconds: int) -> str:
    """Memformat detik menjadi kode singkat untuk badge HUD 3D."""
    if seconds >= 60 and seconds % 60 == 0:
        return f"{seconds // 60}M"
    return f"{float(seconds):.1f}S"


def _render_3d_command_header(
    current_mode: str,
    refresh_interval: int = 10,
    auto_stream: bool = True,
) -> None:
    """Merender hanya header CYBERGUARD COMMAND CENTER dalam bentuk 3D interaktif."""
    is_demo = current_mode == "DEMO"
    short_tag = _format_interval_short(refresh_interval)
    human_tag = (
        f"{refresh_interval // 60} Menit"
        if refresh_interval >= 60 and refresh_interval % 60 == 0
        else f"{refresh_interval} Detik"
    )

    if not auto_stream:
        badge_label = "⏸️ MANUAL MODE • PAUSED"
        badge_accent = "#f59e0b"
        sub_text = "Auto-Polling Paused • Klik 'Refresh' atau aktifkan Auto-Stream"
    elif is_demo:
        badge_label = f"⚡ DEMO STREAM • {short_tag}"
        badge_accent = "#38bdf8"
        sub_text = f"Simulated Security Telemetry • Auto-Polling Sensor Engine ({human_tag} Interval)"
    else:
        badge_label = f"⚡ LIVE STREAM • {short_tag}"
        badge_accent = "#00f0ff"
        sub_text = f"True Real-Time Security Telemetry • Auto-Polling Sensor Engine ({human_tag} Interval)"

    header_html = f"""
    <!DOCTYPE html>
    <html lang="id">
    <head>
    <meta charset="UTF-8" />
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@600;700&family=Orbitron:wght@700;800&display=swap" rel="stylesheet">
    <style>
      * {{ box-sizing: border-box; margin: 0; padding: 0; }}
      body {{
        background: transparent;
        overflow: hidden;
        padding: 4px 2px;
      }}
      .scene {{
        perspective: 1100px;
        width: 100%;
      }}
      .hud-shell {{
        position: relative;
        width: 100%;
        padding: 18px 26px;
        background:
          radial-gradient(circle at 14% 50%, rgba(0, 240, 255, 0.16), transparent 55%),
          linear-gradient(135deg, #050f22 0%, #0a1b36 58%, #040b18 100%);
        border-left: 5px solid #00f0ff;
        border-top: 1px solid rgba(0, 240, 255, 0.42);
        border-right: 1px solid rgba(0, 240, 255, 0.42);
        border-bottom: 1px solid rgba(0, 240, 255, 0.42);
        clip-path: polygon(0 0, calc(100% - 22px) 0, 100% 22px, 100% 100%, 0 100%);
        box-shadow: 0 12px 30px rgba(0, 0, 0, 0.65), inset 0 0 24px rgba(0, 240, 255, 0.08);
        transform-style: preserve-3d;
        transition: transform 0.14s ease-out, box-shadow 0.2s ease;
        animation: float3d 5s ease-in-out infinite;
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 16px;
        overflow: hidden;
      }}
      .hud-shell::before {{
        content: "";
        position: absolute;
        top: 0;
        left: -45%;
        width: 30%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(0, 240, 255, 0.15), transparent);
        transform: skewX(-24deg);
        animation: laserSweep 4.2s linear infinite;
        pointer-events: none;
      }}
      .hud-grid {{
        position: absolute;
        inset: 0;
        background-image:
          linear-gradient(rgba(0, 240, 255, 0.05) 1px, transparent 1px),
          linear-gradient(90deg, rgba(0, 240, 255, 0.05) 1px, transparent 1px);
        background-size: 20px 20px;
        pointer-events: none;
      }}
      .left-group {{
        display: flex;
        align-items: center;
        gap: 16px;
        transform: translateZ(32px);
      }}
      .holo-box {{
        width: 48px;
        height: 48px;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
      }}
      #holoShield3d {{
        width: 48px;
        height: 48px;
        filter: drop-shadow(0 0 9px rgba(0, 240, 255, 0.8));
      }}
      .hud-title {{
        font-family: 'Orbitron', 'Segoe UI', sans-serif;
        font-size: 1.38rem;
        font-weight: 800;
        letter-spacing: 1.8px;
        color: #ffffff;
        text-shadow: 0 0 14px rgba(0, 240, 255, 0.72);
      }}
      .hud-subtitle {{
        font-family: 'Segoe UI', sans-serif;
        font-size: 0.84rem;
        color: #94a3b8;
        margin-top: 4px;
        letter-spacing: 0.3px;
      }}
      .stream-badge {{
        transform: translateZ(40px);
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.78rem;
        font-weight: 700;
        letter-spacing: 1.2px;
        color: {badge_accent};
        background: rgba(4, 18, 34, 0.88);
        border: 1px solid {badge_accent};
        padding: 8px 16px;
        box-shadow: 0 0 14px rgba(0, 240, 255, 0.25);
        animation: pulseNeon 2.2s infinite;
        white-space: nowrap;
      }}
      @keyframes float3d {{
        0%, 100% {{ transform: rotateX(0deg) rotateY(0deg) translateY(0px); }}
        50% {{ transform: rotateX(1.6deg) rotateY(-1.4deg) translateY(-2px); }}
      }}
      @keyframes laserSweep {{
        0% {{ left: -45%; }}
        100% {{ left: 130%; }}
      }}
      @keyframes pulseNeon {{
        0%, 100% {{ box-shadow: 0 0 10px rgba(0, 240, 255, 0.22); }}
        50% {{ box-shadow: 0 0 20px rgba(0, 240, 255, 0.65); }}
      }}
    </style>
    </head>
    <body>
      <div class="scene" id="hudScene">
        <div class="hud-shell" id="hudShell">
          <div class="hud-grid"></div>
          <div class="left-group">
            <div class="holo-box">
              <canvas id="holoShield3d" width="96" height="96"></canvas>
            </div>
            <div>
              <div class="hud-title">CYBERGUARD COMMAND CENTER</div>
              <div class="hud-subtitle">{sub_text}</div>
            </div>
          </div>
          <div class="stream-badge">{badge_label}</div>
        </div>
      </div>

      <script>
        const scene = document.getElementById("hudScene");
        const shell = document.getElementById("hudShell");

        scene.addEventListener("mousemove", (e) => {{
          const rect = scene.getBoundingClientRect();
          const x = (e.clientX - rect.left) / rect.width - 0.5;
          const y = (e.clientY - rect.top) / rect.height - 0.5;
          shell.style.animation = "none";
          shell.style.transform = `rotateY(${{x * 11}}deg) rotateX(${{-y * 11}}deg)`;
        }});

        scene.addEventListener("mouseleave", () => {{
          shell.style.transform = "rotateY(0deg) rotateX(0deg)";
          shell.style.animation = "float3d 5s ease-in-out infinite";
        }});

        const canvas = document.getElementById("holoShield3d");
        const ctx = canvas.getContext("2d");
        const cx = canvas.width / 2;
        const cy = canvas.height / 2;
        const r = 32;
        let t = 0;

        function animateHolo() {{
          ctx.clearRect(0, 0, canvas.width, canvas.height);

          ctx.strokeStyle = "rgba(0, 240, 255, 0.85)";
          ctx.lineWidth = 2.2;
          ctx.beginPath();
          ctx.arc(cx, cy, r, 0, Math.PI * 2);
          ctx.stroke();

          ctx.strokeStyle = "rgba(56, 189, 248, 0.6)";
          ctx.lineWidth = 1.4;
          for (let i = 0; i < 4; i++) {{
            const rot = t + (i * Math.PI) / 4;
            const rx = Math.max(2, Math.abs(Math.cos(rot)) * r);
            ctx.beginPath();
            ctx.ellipse(cx, cy, rx, r, 0, 0, Math.PI * 2);
            ctx.stroke();
          }}

          ctx.beginPath();
          ctx.ellipse(cx, cy, r, r * 0.28, 0, 0, Math.PI * 2);
          ctx.stroke();

          const sx = cx + Math.cos(t * 1.9) * (r + 7);
          const sy = cy + Math.sin(t * 1.9) * 12;
          ctx.fillStyle = "#00ff41";
          ctx.beginPath();
          ctx.arc(sx, sy, 3.4, 0, Math.PI * 2);
          ctx.fill();

          t += 0.028;
          requestAnimationFrame(animateHolo);
        }}
        animateHolo();
      </script>
    </body>
    </html>
    """
    components.html(header_html, height=104)


def _render_verdict_card(sweep_res: SystemSweepSummary) -> None:
    """Menampilkan panel diagnosis tegas apakah device dan jaringan aman atau berbahaya."""
    if sweep_res.overall_verdict == "DANGER":
        border_color = "#ef4444"
        bg_grad = "linear-gradient(90deg, rgba(127, 29, 29, 0.65), rgba(15, 23, 42, 0.95))"
        badge_text = "HIGH THREAT DETECTED"
    elif sweep_res.overall_verdict == "CAUTION":
        border_color = "#f59e0b"
        bg_grad = "linear-gradient(90deg, rgba(120, 53, 15, 0.65), rgba(15, 23, 42, 0.95))"
        badge_text = "MINOR EXPOSURE / WATCH"
    else:
        border_color = "#10b981"
        bg_grad = "linear-gradient(90deg, rgba(6, 78, 59, 0.65), rgba(15, 23, 42, 0.95))"
        badge_text = "SYSTEM & NETWORK SECURE"

    advice_html = "".join(f"<li>{item}</li>" for item in sweep_res.action_advice)

    st.markdown(
        f"""
        <div style="
            background: {bg_grad};
            border: 1px solid {border_color};
            border-left: 7px solid {border_color};
            border-radius: 6px;
            padding: 18px 22px;
            margin: 14px 0 18px 0;
            box-shadow: 0 8px 28px rgba(0, 0, 0, 0.65);
        ">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
                <div style="font-family:'Orbitron',sans-serif; font-size:1.15rem; font-weight:800; color:#ffffff;">
                    {sweep_res.verdict_headline}
                </div>
                <span style="
                    font-family:'JetBrains Mono',monospace;
                    background:rgba(0,0,0,0.45);
                    border:1px solid {border_color};
                    color:{border_color};
                    padding:4px 10px;
                    font-size:0.78rem;
                    font-weight:700;
                ">{badge_text}</span>
            </div>
            <hr style="border-color: rgba(255,255,255,0.12); margin: 12px 0;">
            <div style="font-size:0.98rem; color:#f1f5f9; margin-bottom:6px;">
                <strong>💻 Kondisi Perangkat (Device & Ports):</strong> {sweep_res.device_assessment}
            </div>
            <div style="font-size:0.98rem; color:#f1f5f9; margin-bottom:10px;">
                <strong>🌐 Kondisi Jaringan (Network & IP):</strong> {sweep_res.network_assessment}
            </div>
            <div style="font-size:0.92rem; color:#cbd5e1;">
                <strong>🛡️ Rekomendasi Tindakan:</strong>
                <ul style="margin: 4px 0 0 18px;">{advice_html}</ul>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _sample_true_realtime_telemetry(is_demo: bool) -> dict:
    """Menghitung kecepatan jaringan sesungguhnya (KB/s RX & TX) serta beban CPU/RAM."""
    now_ts = time.time()
    now_label = datetime.now(timezone.utc).strftime("%H:%M:%S")

    if is_demo:
        idx = len(st.session_state.get("rt_stream_buffer", []))
        rx_kbps = [142.5, 580.2, 215.8, 1240.6, 390.4, 845.1, 198.0, 1520.3][idx % 8]
        tx_kbps = [48.2, 195.4, 82.1, 410.5, 134.8, 290.2, 65.4, 512.0][idx % 8]
        cpu_pct = [18.5, 34.2, 22.0, 56.8, 29.4, 41.2, 24.5, 62.1][idx % 8]
        ram_pct = 54.2
        active_conns = 14
    else:
        counters = psutil.net_io_counters()
        prev = st.session_state.get("prev_net_sample")

        if prev is not None:
            dt = max(0.5, now_ts - prev["ts"])
            rx_kbps = round(max(0, counters.bytes_recv - prev["rx"]) / 1024.0 / dt, 2)
            tx_kbps = round(max(0, counters.bytes_sent - prev["tx"]) / 1024.0 / dt, 2)
        else:
            rx_kbps = 0.0
            tx_kbps = 0.0

        st.session_state["prev_net_sample"] = {
            "ts": now_ts,
            "rx": counters.bytes_recv,
            "tx": counters.bytes_sent,
        }

        cpu_pct = psutil.cpu_percent(interval=None)
        ram_pct = psutil.virtual_memory().percent
        try:
            active_conns = sum(
                1 for c in psutil.net_connections(kind="inet") if c.status == "ESTABLISHED"
            )
        except Exception:
            active_conns = 0

    sample = {
        "Time": now_label,
        "RX_KBps": rx_kbps,
        "TX_KBps": tx_kbps,
        "CPU_Pct": cpu_pct,
        "RAM_Pct": ram_pct,
        "Active_Conns": active_conns,
    }

    buffer = st.session_state.setdefault("rt_stream_buffer", [])
    buffer.append(sample)
    st.session_state["rt_stream_buffer"] = buffer[-25:]
    return sample


def _build_realtime_traffic_chart(buffer: list[dict]) -> go.Figure:
    """Merender grafik gelombang kecepatan jaringan real-time (KB/s)."""
    df = pd.DataFrame(buffer)
    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=df["Time"],
            y=df["RX_KBps"],
            mode="lines+markers",
            name="Download / RX (KB/s)",
            line=dict(color="#00f0ff", width=2.5, shape="spline"),
            marker=dict(size=5, color="#00f0ff"),
            fill="tozeroy",
            fillcolor="rgba(0, 240, 255, 0.16)",
        )
    )
    fig.add_trace(
        go.Scatter(
            x=df["Time"],
            y=df["TX_KBps"],
            mode="lines+markers",
            name="Upload / TX (KB/s)",
            line=dict(color="#00ff41", width=2, shape="spline"),
            marker=dict(size=5, color="#00ff41"),
            fill="tozeroy",
            fillcolor="rgba(0, 255, 65, 0.12)",
        )
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(4, 10, 24, 0.85)",
        font=dict(color="#cbd5e1", family="JetBrains Mono", size=10),
        xaxis=dict(gridcolor="rgba(0, 240, 255, 0.12)", title=""),
        yaxis=dict(gridcolor="rgba(0, 240, 255, 0.12)", title="Throughput (KB/s)", rangemode="tozero"),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        margin=dict(t=32, b=20, l=45, r=15),
        height=265,
    )
    return fig


def _build_system_load_chart(buffer: list[dict]) -> go.Figure:
    """Merender grafik telemetri CPU & RAM real-time."""
    df = pd.DataFrame(buffer)
    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=df["Time"],
            y=df["CPU_Pct"],
            mode="lines+markers",
            name="CPU Load (%)",
            line=dict(color="#f59e0b", width=2.5, shape="spline"),
            fill="tozeroy",
            fillcolor="rgba(245, 158, 11, 0.14)",
        )
    )
    fig.add_trace(
        go.Scatter(
            x=df["Time"],
            y=df["RAM_Pct"],
            mode="lines",
            name="RAM Usage (%)",
            line=dict(color="#a855f7", width=2, dash="dot"),
        )
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(4, 10, 24, 0.85)",
        font=dict(color="#cbd5e1", family="JetBrains Mono", size=10),
        xaxis=dict(gridcolor="rgba(0, 240, 255, 0.12)", title=""),
        yaxis=dict(gridcolor="rgba(0, 240, 255, 0.12)", title="Utilization (%)", range=[0, 100]),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        margin=dict(t=32, b=20, l=45, r=15),
        height=265,
    )
    return fig


def _build_threat_gauge(avg_score: float) -> go.Figure:
    """Membuat grafik gauge meteran risiko siber (0-100)."""
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=avg_score,
            number={"font": {"size": 30, "color": "#00f0ff", "family": "Orbitron"}},
            title={
                "text": "THREAT RISK INDEX",
                "font": {"size": 12, "color": "#94a3b8", "family": "JetBrains Mono"},
            },
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#38bdf8"},
                "bar": {"color": "#00f0ff", "thickness": 0.3},
                "bgcolor": "rgba(10, 19, 38, 0.9)",
                "borderwidth": 1,
                "bordercolor": "rgba(0, 240, 255, 0.45)",
                "steps": [
                    {"range": [0, 30], "color": "rgba(16, 185, 129, 0.25)"},
                    {"range": [30, 60], "color": "rgba(245, 158, 11, 0.25)"},
                    {"range": [60, 80], "color": "rgba(249, 115, 22, 0.32)"},
                    {"range": [80, 100], "color": "rgba(239, 68, 68, 0.4)"},
                ],
                "threshold": {"line": {"color": "#ef4444", "width": 3}, "thickness": 0.85, "value": 75},
            },
        )
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        font={"color": "#e2e8f0"},
        margin=dict(t=42, b=10, l=20, r=20),
        height=265,
    )
    return fig


def _build_cyber_defense_radar(metrics: dict) -> go.Figure:
    """Membuat grafik Radar 6-Sumbu pertahanan CYBERGUARD."""
    categories = [
        "NETWORK SHIELD",
        "PORT SENTINEL",
        "SHA-256 INTEGRITY",
        "PHISHING GUARD",
        "INCIDENT OPS",
        "CORE TELEMETRY",
    ]
    values = [
        min(100, 35 + metrics["network_total"] * 12),
        min(100, 35 + metrics["scans_total"] * 12),
        min(100, 35 + metrics["baselines_total"] * 15),
        min(100, 35 + metrics["phishing_total"] * 12),
        min(100, 40 + metrics["incidents_total"] * 10),
        min(100, 45 + metrics["events_total"] * 8),
    ]
    fig = go.Figure(
        go.Scatterpolar(
            r=values + [values[0]],
            theta=categories + [categories[0]],
            fill="toself",
            fillcolor="rgba(0, 240, 255, 0.18)",
            line=dict(color="#00f0ff", width=2.5),
            marker=dict(color="#00ff41", size=6),
        )
    )
    fig.update_layout(
        polar=dict(
            bgcolor="rgba(6, 13, 28, 0.85)",
            radialaxis=dict(visible=True, range=[0, 100], gridcolor="rgba(0, 240, 255, 0.2)"),
            angularaxis=dict(
                gridcolor="rgba(0, 240, 255, 0.25)",
                tickfont=dict(size=10, color="#38bdf8", family="JetBrains Mono"),
            ),
        ),
        showlegend=False,
        paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(t=35, b=25, l=45, r=45),
        height=265,
    )
    return fig


def _render_hacker_terminal_console(
    recent_events: list[dict],
    latest_hw: dict,
    current_mode: str,
    refresh_interval: int = 10,
) -> None:
    """Merender konsol log terminal bergaya matriks hijau fosfor dengan detak sensor langsung."""
    interval_human = (
        f"{refresh_interval // 60} menit"
        if refresh_interval >= 60 and refresh_interval % 60 == 0
        else f"{refresh_interval} detik"
    )
    lines = [
        f"<div style='color:#38bdf8;'>root@cyberguard-sentinel:~# stream-telemetry --mode={current_mode} --interval={refresh_interval}s</div>",
        (
            f"<div style='color:#00ff41;'>[HEARTBEAT {latest_hw['Time']}] "
            f"RX: {latest_hw['RX_KBps']} KB/s | TX: {latest_hw['TX_KBps']} KB/s | "
            f"CPU: {latest_hw['CPU_Pct']}% | RAM: {latest_hw['RAM_Pct']}% | "
            f"ACTIVE SOCKETS: {latest_hw['Active_Conns']}</div>"
        ),
        "<div style='color:#64748b;'>--------------------------------------------------------------------------------</div>",
    ]

    if recent_events:
        for ev in recent_events[:6]:
            sev = ev["Severity"]
            sev_color = (
                "#ef4444"
                if sev in ("HIGH", "CRITICAL")
                else ("#f59e0b" if sev == "MEDIUM" else "#00ff41")
            )
            lines.append(
                f"<div style='margin-bottom:4px;'>"
                f"<span style='color:#64748b;'>[{ev['Waktu (UTC)']}]</span> "
                f"<span style='color:{sev_color}; font-weight:700;'>[{sev}]</span> "
                f"<span style='color:#00f0ff;'>[{ev['Modul']}]</span> "
                f"<span style='color:#e2e8f0;'>{ev['Deskripsi']}</span>"
                f"</div>"
            )
    else:
        lines.append(
            f"<div style='color:#94a3b8;'>[INFO] Menunggu insiden baru. Sensor hardware memantau setiap {interval_human}...</div>"
        )

    terminal_html = f"""
    <div style="
        background-color: #030712;
        border: 1px solid rgba(0, 255, 65, 0.45);
        border-left: 5px solid #00ff41;
        border-radius: 6px;
        padding: 14px 18px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        line-height: 1.55;
        box-shadow: 0 0 24px rgba(0, 255, 65, 0.14), inset 0 0 18px rgba(0, 0, 0, 0.9);
        max-height: 265px;
        overflow-y: auto;
    ">
        {''.join(lines)}
    </div>
    """
    st.markdown(terminal_html, unsafe_allow_html=True)


def _render_telemetry_body(current_mode: str, refresh_interval: int = 10) -> None:
    """Isi panel telemetri yang dapat diperbarui otomatis sesuai interval pilihan pengguna."""
    is_demo = current_mode == "DEMO"
    monitoring_svc = MonitoringService()

    latest_hw = _sample_true_realtime_telemetry(is_demo=is_demo)
    buffer = st.session_state["rt_stream_buffer"]
    metrics = monitoring_svc.get_dashboard_metrics(is_demo=is_demo)
    posture_level = classify_severity(int(metrics["avg_risk_score"]))

    # Baris 1: Kartu Telemetri Real-Time Hardware & Jaringan
    t1, t2, t3, t4 = st.columns(4)
    t1.metric("DOWNLOAD (RX)", f"{latest_hw['RX_KBps']} KB/s")
    t2.metric("UPLOAD (TX)", f"{latest_hw['TX_KBps']} KB/s")
    t3.metric("ACTIVE SOCKETS", f"{latest_hw['Active_Conns']}")
    t4.metric("CPU / RAM LOAD", f"{latest_hw['CPU_Pct']}% | {latest_hw['RAM_Pct']}%")

    # Baris 2: Kartu Metrik Database & Keamanan SOC
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("THREAT POSTURE", posture_level)
    m2.metric("SECURITY EVENTS", metrics["events_total"])
    m3.metric("ACTIVE INCIDENTS", metrics["incidents_open"])
    m4.metric("THREAT SCORE AVG", f"{metrics['avg_risk_score']}")

    st.divider()

    # Baris 3: Grafik Gelombang Jaringan Real-Time + Beban CPU/RAM Real-Time
    w_col1, w_col2 = st.columns(2)
    with w_col1:
        st.markdown("#### 📈 Real-Time Network Throughput (KB/s)")
        st.plotly_chart(_build_realtime_traffic_chart(buffer), use_container_width=True)

    with w_col2:
        st.markdown("#### ⚙️ Real-Time Host CPU & Memory Telemetry (%)")
        st.plotly_chart(_build_system_load_chart(buffer), use_container_width=True)

    st.divider()

    # Baris 4: Radar Pertahanan 6-Sumbu + Threat Gauge + Live Terminal Console
    r_col, g_col, term_col = st.columns([1, 0.95, 1.35])

    with r_col:
        st.markdown("#### 🕸️ 6-Axis Defense Radar")
        st.plotly_chart(_build_cyber_defense_radar(metrics), use_container_width=True)

    with g_col:
        st.markdown("#### 🎯 Threat Index")
        st.plotly_chart(_build_threat_gauge(metrics["avg_risk_score"]), use_container_width=True)

    with term_col:
        st.markdown("#### 💻 Live SOC Terminal Stream")
        _render_hacker_terminal_console(
            metrics["recent_events"],
            latest_hw,
            current_mode,
            refresh_interval=refresh_interval,
        )


def render_overview_page(current_mode: str) -> None:
    """Merender halaman utama Security Operations Center (SOC) Overview."""
    render_mode_banner(current_mode)

    is_demo = current_mode == "DEMO"
    engine = SecurityEngine()

    # Baris Kontrol Atas: Tombol Sweep + Auto-Stream + Pilihan Interval Refresh (Maks 5 Menit)
    ctrl1, ctrl2, ctrl3, ctrl4 = st.columns([1.8, 1.15, 1.35, 0.9])
    with ctrl1:
        sweep_clicked = st.button(
            "⚡ EKSEKUSI DEEP SYSTEM SWEEP",
            type="primary",
            use_container_width=True,
        )
    with ctrl2:
        auto_stream = st.toggle(
            "🟢 AUTO-STREAM",
            value=True,
            help="Aktifkan pembaruan otomatis berkala. Matikan jika ingin tampilan statis hemat resource.",
        )
    with ctrl3:
        refresh_interval = st.selectbox(
            "Interval Refresh",
            options=[5, 10, 15, 30, 60, 120, 180, 300],
            index=1,  # Default 10 detik, maksimal 300 detik (5 menit)
            disabled=not auto_stream,
            label_visibility="collapsed",
            format_func=lambda sec: f"⏱️ Refresh: {_format_interval_human(sec)}",
            help="Atur jeda waktu pembaruan otomatis dari 5 detik hingga paling lama 5 menit (300 detik).",
        )
    with ctrl4:
        st.button(
            "🔄 Refresh",
            use_container_width=True,
            help="Ambil sampel telemetri terbaru secara manual saat ini juga.",
        )

    # Render Header 3D yang menyesuaikan status & interval refresh pilihan pengguna
    _render_3d_command_header(
        current_mode=current_mode,
        refresh_interval=int(refresh_interval),
        auto_stream=auto_stream,
    )

    if sweep_clicked:
        try:
            with st.spinner("MENJALANKAN AUDIT MENYELURUH PERANGKAT & JARINGAN..."):
                sweep_res = engine.run_system_sweep(is_demo=is_demo)
                st.session_state["last_sweep_verdict"] = sweep_res
        except Exception as exc:
            st.error(f"Gagal menjalankan System Sweep: {exc}")

    # Tampilkan Kartu Vonis Keamanan jika sudah pernah dilakukan scanning
    if "last_sweep_verdict" in st.session_state:
        _render_verdict_card(st.session_state["last_sweep_verdict"])

    st.divider()

    # Jalankan mode streaming otomatis sesuai interval pilihan atau mode statis
    if auto_stream:
        @st.fragment(run_every=refresh_interval)
        def _live_streaming_fragment() -> None:
            _render_telemetry_body(current_mode, refresh_interval=int(refresh_interval))

        _live_streaming_fragment()
    else:
        _render_telemetry_body(current_mode, refresh_interval=int(refresh_interval))