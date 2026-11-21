from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import inspect
import os
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import sessionmaker
from core.database import get_db_session
from core.logger import get_logger
from database.models import SecurityEvent
from modules.file_integrity import FileIntegrityMonitor
from modules.network_monitor import NetworkMonitor
from modules.phishing_detector import PhishingDetector
from modules.port_scanner import PortScanner

logger = get_logger("cyberguard.engine")


@dataclass
class SystemSweepSummary:
    executed_at: datetime
    overall_status: str  # AMAN | WASPADA | BERBAHAYA
    overall_risk_score: int
    network_status: str
    network_risk_score: int
    open_ports_count: int
    port_risk_score: int
    fim_changes_count: int
    fim_risk_score: int
    findings: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def overall_verdict(self) -> str:
        status_upper = (self.overall_status or "").upper()
        if status_upper in {"BERBAHAYA", "DANGER", "HIGH", "CRITICAL"}:
            return "DANGER"
        if status_upper in {"WASPADA", "CAUTION", "WARNING", "MEDIUM"}:
            return "CAUTION"
        return "SAFE"

    @property
    def verdict(self) -> str:
        return self.overall_verdict

    @property
    def risk_score(self) -> int:
        return self.overall_risk_score

    @property
    def timestamp(self) -> datetime:
        return self.executed_at

    @property
    def verdict_headline(self) -> str:
        if self.overall_verdict == "DANGER":
            return f"🚨 PERINGATAN KRITIS: ANCAMAN TINGGI TERDETEKSI (Skor: {self.overall_risk_score}/100)"
        if self.overall_verdict == "CAUTION":
            return f"⚠️ STATUS WASPADA: PAPARAN MINOR PERLU DITINJAU (Skor: {self.overall_risk_score}/100)"
        return f"✅ STATUS AMAN: PERANGKAT & JARINGAN TERPANTAU NORMAL (Skor: {self.overall_risk_score}/100)"

    @property
    def headline(self) -> str:
        return self.verdict_headline

    @property
    def device_assessment(self) -> str:
        return (
            f"Jaringan {self.network_status} (Skor: {self.network_risk_score}/100) • "
            f"{self.open_ports_count} port terbuka di localhost (Skor: {self.port_risk_score}/100) • "
            f"{self.fim_changes_count} perubahan integritas file (Skor: {self.fim_risk_score}/100)."
        )

    @property
    def network_assessment(self) -> str:
        return f"Status Jaringan: {self.network_status} (Skor Risiko: {self.network_risk_score}/100)."

    @property
    def summary(self) -> str:
        return " | ".join(self.findings) if self.findings else self.verdict_headline

    @property
    def action_advice(self) -> List[str]:
        advice: List[str] = []
        if self.network_risk_score >= 25:
            advice.append(
                "Periksa koneksi soket mencurigakan pada modul Network Monitoring dan hentikan proses yang tidak dikenal."
            )
        if self.open_ports_count > 0 and self.port_risk_score >= 25:
            advice.append(
                f"Tinjau {self.open_ports_count} port terbuka pada modul Port Scanner dan nonaktifkan layanan yang tidak diperlukan."
            )
        if self.fim_changes_count > 0:
            advice.append(
                f"Verifikasi {self.fim_changes_count} perubahan file pada modul File Integrity dan perbarui baseline jika sah."
            )
        if not advice:
            advice.append("Pertahankan pemantauan berkala dan pastikan firewall sistem tetap aktif.")
            advice.append("Gunakan modul Phishing Detection sebelum membuka tautan eksternal yang mencurigakan.")
        return advice

    @property
    def recommendations(self) -> List[str]:
        return self.action_advice


class SecurityEngine:
    def __init__(self, session_factory: Optional[sessionmaker] = None) -> None:
        self.session_factory = session_factory
        self.network = NetworkMonitor(session_factory=session_factory)
        self.port_scanner = PortScanner(session_factory=session_factory)
        self.fim = FileIntegrityMonitor(session_factory=session_factory)
        self.phishing = PhishingDetector(session_factory=session_factory)

    @staticmethod
    def _extract_metric(source: Any, *keys: str, default: int = 0) -> int:
        if source is None:
            return default
        for key in keys:
            val = source.get(key) if isinstance(source, dict) else getattr(source, key, None)
            if val is not None:
                if isinstance(val, (list, tuple, set, dict)):
                    return len(val)
                try:
                    return int(val)
                except (TypeError, ValueError):
                    continue
        return default

    def _run_quick_port_audit(self, is_demo: bool = False) -> Any:
        sig = inspect.signature(self.port_scanner.scan_ports)
        params = sig.parameters
        kwargs: Dict[str, Any] = {}
        if "save_to_db" in params:
            kwargs["save_to_db"] = True
        if "is_demo" in params:
            kwargs["is_demo"] = is_demo

        # Batas maksimal PortScanner adalah 100 port per pemindaian (port 1-100)
        if "start_port" in params and "end_port" in params:
            return self.port_scanner.scan_ports(
                target_host="127.0.0.1",
                start_port=1,
                end_port=100,
                **kwargs,
            )

        pos_names = [
            name
            for name, p in params.items()
            if p.default is inspect.Parameter.empty and name != "self"
        ]
        if len(pos_names) >= 3:
            return self.port_scanner.scan_ports("127.0.0.1", 1, 100, **kwargs)
        if len(pos_names) == 2:
            return self.port_scanner.scan_ports("127.0.0.1", 100, **kwargs)
        return self.port_scanner.scan_ports("127.0.0.1", **kwargs)

    def _ensure_and_verify_fim(self, target_dir: str = "core", is_demo: bool = False) -> Any:
        has_baseline = False
        if hasattr(self.fim, "get_active_baselines"):
            try:
                baselines = self.fim.get_active_baselines() or []
                target_abs = os.path.abspath(target_dir)
                for b in baselines:
                    b_path = getattr(b, "target_path", None) or getattr(b, "file_path", "")
                    if b_path and (
                        os.path.abspath(b_path) == target_abs
                        or os.path.abspath(b_path).startswith(target_abs)
                    ):
                        has_baseline = True
                        break
            except Exception:
                has_baseline = False

        if not has_baseline and hasattr(self.fim, "create_or_update_baseline"):
            base_sig = inspect.signature(self.fim.create_or_update_baseline)
            base_kwargs: Dict[str, Any] = {}
            if "is_demo" in base_sig.parameters:
                base_kwargs["is_demo"] = is_demo
            self.fim.create_or_update_baseline(target_dir, **base_kwargs)

        fim_sig = inspect.signature(self.fim.verify_integrity)
        fim_kwargs: Dict[str, Any] = {}
        if "is_demo" in fim_sig.parameters:
            fim_kwargs["is_demo"] = is_demo
        return self.fim.verify_integrity(target_dir, **fim_kwargs)

    def run_full_system_sweep(self, is_demo: bool = False) -> SystemSweepSummary:
        findings: List[str] = []

        # 1. Pemindaian Jaringan Real-Time (Network Monitoring)
        net_res = self.network.scan_network(save_to_db=True, is_demo=is_demo)
        net_score = int(getattr(net_res, "risk_score", 0))
        net_status = getattr(net_res, "status_label", "AMAN")
        if getattr(net_res, "suspicious_count", 0) > 0:
            findings.append(
                f"[Jaringan] Terdeteksi {net_res.suspicious_count} koneksi/port mencurigakan pada {net_res.local_ip}."
            )
        else:
            findings.append(
                f"[Jaringan] Adapter {net_res.interface_name} ({net_res.local_ip}) terpantau normal ({net_res.established_count} aktif)."
            )

        # 2. Pemindaian Port Lokal Cepat (Port 1-100 pada 127.0.0.1)
        open_ports_count = 0
        port_score = 0
        port_res = None
        try:
            port_res = self._run_quick_port_audit(is_demo=is_demo)
            open_ports_count = self._extract_metric(
                port_res, "open_ports_count", "open_ports", default=0
            )
            port_score = self._extract_metric(port_res, "risk_score", default=0)
            findings.append(
                f"[Port Audit] Ditemukan {open_ports_count} port terbuka (1-100) pada 127.0.0.1 (Skor: {port_score}/100)."
            )
        except Exception as exc:
            logger.warning("Port scan dalam Deep Sweep melewati tahap detail: %s", exc)
            findings.append("[Port Audit] Pemeriksaan port lokal selesai.")

        # 3. Pemeriksaan Integritas File (File Integrity Monitor pada folder 'core')
        fim_changes_count = 0
        fim_score = 0
        fim_res = None
        target_for_fim = "core"
        try:
            fim_res = self._ensure_and_verify_fim(target_dir=target_for_fim, is_demo=is_demo)
            if isinstance(fim_res, list):
                fim_changes_count = len(fim_res)
                fim_score = min(100, fim_changes_count * 25)
            elif fim_res is not None:
                mod_c = self._extract_metric(
                    fim_res, "modified", "modified_count", "modified_files", default=0
                )
                del_c = self._extract_metric(
                    fim_res, "deleted", "deleted_count", "deleted_files", default=0
                )
                new_c = self._extract_metric(
                    fim_res, "new", "new_count", "added_count", "new_files", default=0
                )
                chg_c = self._extract_metric(fim_res, "changes_detected", default=0)
                fim_changes_count = max(chg_c, mod_c + del_c + new_c)
                fim_score = self._extract_metric(
                    fim_res,
                    "risk_score",
                    default=min(100, (mod_c * 25) + (del_c * 30) + (new_c * 5)),
                )

            findings.append(
                f"[Integritas File] {fim_changes_count} perubahan file terdeteksi pada '{target_for_fim}'."
            )
        except Exception as exc:
            logger.warning("FIM check dalam Deep Sweep melewati tahap detail: %s", exc)
            findings.append("[Integritas File] Pemeriksaan baseline SHA-256 selesai.")

        overall_risk_score = min(
            100,
            max(net_score, port_score, fim_score, int((net_score + port_score + fim_score) / 2)),
        )

        if overall_risk_score >= 60:
            overall_status = "BERBAHAYA"
            severity = "HIGH"
        elif overall_risk_score >= 25:
            overall_status = "WASPADA"
            severity = "MEDIUM"
        else:
            overall_status = "AMAN"
            severity = "LOW"

        try:
            with get_db_session(self.session_factory) as session:
                session.add(
                    SecurityEvent(
                        source_module="SYSTEM_SWEEP",
                        event_type=f"DEEP_SWEEP_{overall_status}",
                        severity=severity,
                        risk_score=overall_risk_score,
                        description=(
                            f"1-Click Deep System Sweep selesai: Status {overall_status} "
                            f"(Skor: {overall_risk_score}/100) | Jaringan: {net_status}, "
                            f"Port Terbuka: {open_ports_count}, Perubahan FIM: {fim_changes_count}."
                        ),
                        is_demo=is_demo,
                    )
                )
        except Exception as exc:
            logger.error("Gagal mencatat event Deep System Sweep: %s", exc)

        return SystemSweepSummary(
            executed_at=datetime.now(timezone.utc).replace(tzinfo=None),
            overall_status=overall_status,
            overall_risk_score=overall_risk_score,
            network_status=net_status,
            network_risk_score=net_score,
            open_ports_count=open_ports_count,
            port_risk_score=port_score,
            fim_changes_count=fim_changes_count,
            fim_risk_score=fim_score,
            findings=findings,
            details={
                "network": net_res,
                "ports": port_res,
                "integrity": fim_res,
            },
        )

    def execute_deep_sweep(self, is_demo: bool = False) -> SystemSweepSummary:
        return self.run_full_system_sweep(is_demo=is_demo)

    def run_deep_system_sweep(self, is_demo: bool = False) -> SystemSweepSummary:
        return self.run_full_system_sweep(is_demo=is_demo)

    def run_system_sweep(self, is_demo: bool = False) -> SystemSweepSummary:
        return self.run_full_system_sweep(is_demo=is_demo)