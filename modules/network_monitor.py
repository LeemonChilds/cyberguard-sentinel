from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import psutil
from sqlalchemy import desc, select
from sqlalchemy.orm import sessionmaker
from core.database import get_db_session
from core.logger import get_logger
from database.models import NetworkSnapshot, SecurityEvent

logger = get_logger("cyberguard.network")

SUSPICIOUS_PORTS = {
    4444: "Metasploit / Reverse Shell Default",
    5555: "Android ADB / Remote Exploit",
    6666: "IRC Botnet / Backdoor",
    6667: "IRC Command & Control",
    1337: "Elite Backdoor / Trojan",
    31337: "Back Orifice Trojan",
    12345: "NetBus Trojan",
    23: "Telnet (Protokol Tidak Terenkripsi)",
    3389: "RDP Terekspos",
    5900: "VNC Remote Desktop",
}


@dataclass
class NetworkInterfaceInfo:
    name: str
    ipv4_address: str = "-"
    is_up: bool = True
    speed_mbps: int = 0
    mtu: int = 1500

    @property
    def ip_address(self) -> str:
        return self.ipv4_address

    @property
    def ipv4(self) -> str:
        return self.ipv4_address

    @property
    def status(self) -> str:
        return "UP" if self.is_up else "DOWN"


@dataclass
class NetworkConnectionInfo:
    protocol: str
    local_address: str
    remote_address: str
    status: str
    process_name: str = "-"
    pid: int = 0
    risk_level: str = "NORMAL"
    is_suspicious: bool = False

    @property
    def risk(self) -> str:
        return self.risk_level


@dataclass
class NetworkSnapshotReport:
    interface_name: str
    local_ip: str
    bytes_sent_mb: float
    bytes_recv_mb: float
    established_count: int
    listening_count: int
    suspicious_count: int
    risk_score: int
    severity: str
    status_label: str
    interfaces: List[NetworkInterfaceInfo] = field(default_factory=list)
    connections: List[NetworkConnectionInfo] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)
    summary_notes: str = ""

    @property
    def primary_local_ip(self) -> str:
        return self.local_ip

    @property
    def primary_ip(self) -> str:
        return self.local_ip

    @property
    def active_connections_count(self) -> int:
        return self.established_count

    @property
    def active_connections(self) -> List[NetworkConnectionInfo]:
        return self.connections

    @property
    def listening_ports_count(self) -> int:
        return self.listening_count

    @property
    def listening_ports(self) -> int:
        return self.listening_count

    @property
    def suspicious_connections_count(self) -> int:
        return self.suspicious_count

    @property
    def suspicious_connections(self) -> List[NetworkConnectionInfo]:
        return [c for c in self.connections if c.is_suspicious]

    @property
    def bytes_sent_total_mb(self) -> float:
        return self.bytes_sent_mb

    @property
    def bytes_recv_total_mb(self) -> float:
        return self.bytes_recv_mb


NetworkScanResult = NetworkSnapshotReport


class NetworkMonitor:
    def __init__(self, session_factory: Optional[sessionmaker] = None) -> None:
        self.session_factory = session_factory

    @staticmethod
    def _detect_primary_interface_and_ip() -> tuple[str, str, List[NetworkInterfaceInfo]]:
        primary_ip = "127.0.0.1"
        interface_name = "Loopback / Localhost"
        interfaces_info: List[NetworkInterfaceInfo] = []

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.5)
                sock.connect(("8.8.8.8", 80))
                primary_ip = sock.getsockname()[0]
        except Exception:
            try:
                primary_ip = socket.gethostbyname(socket.gethostname())
            except Exception:
                primary_ip = "127.0.0.1"

        try:
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()
            for iface, addr_list in addrs.items():
                st_obj = stats.get(iface)
                is_up = bool(st_obj.isup) if st_obj else True
                speed_mbps = int(st_obj.speed) if st_obj and st_obj.speed else 0
                mtu = int(st_obj.mtu) if st_obj and st_obj.mtu else 1500
                ipv4 = "-"
                for addr in addr_list:
                    if addr.family == socket.AF_INET:
                        ipv4 = addr.address
                        break
                info_obj = NetworkInterfaceInfo(
                    name=iface,
                    ipv4_address=ipv4,
                    is_up=is_up,
                    speed_mbps=speed_mbps,
                    mtu=mtu,
                )
                interfaces_info.append(info_obj)
                if is_up and ipv4 == primary_ip:
                    interface_name = iface

            if interface_name == "Loopback / Localhost":
                for item in interfaces_info:
                    if item.is_up and item.ipv4_address != "-" and not item.ipv4_address.startswith("127."):
                        interface_name = item.name
                        primary_ip = item.ipv4_address
                        break
        except Exception as exc:
            logger.debug("Gagal membaca detail antarmuka jaringan: %s", exc)

        return interface_name, primary_ip, interfaces_info

    def scan_network(self, save_to_db: bool = True, is_demo: bool = False) -> NetworkSnapshotReport:
        interface_name, local_ip, interfaces_info = self._detect_primary_interface_and_ip()
        try:
            net_io = psutil.net_io_counters()
            bytes_sent_mb = round(net_io.bytes_sent / (1024 * 1024), 2)
            bytes_recv_mb = round(net_io.bytes_recv / (1024 * 1024), 2)
        except Exception:
            bytes_sent_mb = 0.0
            bytes_recv_mb = 0.0

        established_count = 0
        listening_count = 0
        suspicious_count = 0
        connections_list: List[NetworkConnectionInfo] = []
        anomalies: List[str] = []

        if is_demo:
            interface_name = "Wi-Fi / Ethernet Adapter (Demo)"
            local_ip = "192.168.1.105"
            bytes_sent_mb = 428.5
            bytes_recv_mb = 1920.8
            established_count = 14
            listening_count = 9
            suspicious_count = 1
            anomalies.append(
                "Port 4444 (Metasploit / Reverse Shell Default) terdeteksi dalam status LISTENING."
            )
            interfaces_info = [
                NetworkInterfaceInfo(
                    name="Wi-Fi (Demo)",
                    ipv4_address="192.168.1.105",
                    is_up=True,
                    speed_mbps=1000,
                    mtu=1500,
                ),
                NetworkInterfaceInfo(
                    name="Ethernet (Demo)",
                    ipv4_address="192.168.1.106",
                    is_up=True,
                    speed_mbps=1000,
                    mtu=1500,
                ),
            ]
            connections_list = [
                NetworkConnectionInfo(
                    protocol="TCP",
                    local_address=f"{local_ip}:52410",
                    remote_address="142.250.190.78:443",
                    status="ESTABLISHED",
                    process_name="chrome.exe",
                    pid=4120,
                    risk_level="NORMAL",
                    is_suspicious=False,
                ),
                NetworkConnectionInfo(
                    protocol="TCP",
                    local_address="0.0.0.0:4444",
                    remote_address="-",
                    status="LISTENING",
                    process_name="unknown_svc.exe",
                    pid=9812,
                    risk_level="MENCURIGAKAN",
                    is_suspicious=True,
                ),
            ]
        else:
            try:
                raw_conns = psutil.net_connections(kind="inet")
            except (psutil.AccessDenied, PermissionError):
                raw_conns = []
                anomalies.append("Hak akses terbatas saat membaca seluruh tabel soket OS.")
            except Exception as exc:
                raw_conns = []
                logger.warning("Gagal membaca net_connections: %s", exc)

            proc_cache: Dict[int, str] = {}
            seen_anomaly_keys = set()
            for conn in raw_conns:
                status = str(conn.status or "UNKNOWN")
                if status == "ESTABLISHED":
                    established_count += 1
                elif status == "LISTEN":
                    listening_count += 1

                laddr_str = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
                raddr_str = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
                lport = conn.laddr.port if conn.laddr else 0
                rport = conn.raddr.port if conn.raddr else 0

                is_suspicious = False
                reason = ""
                if lport in SUSPICIOUS_PORTS:
                    is_suspicious = True
                    reason = f"Port lokal {lport} ({SUSPICIOUS_PORTS[lport]}) aktif ({status})."
                elif rport in SUSPICIOUS_PORTS:
                    is_suspicious = True
                    reason = f"Koneksi keluar ke port mencurigakan {rport} ({SUSPICIOUS_PORTS[rport]})."

                if is_suspicious:
                    suspicious_count += 1
                    if reason not in seen_anomaly_keys:
                        seen_anomaly_keys.add(reason)
                        anomalies.append(reason)

                if len(connections_list) < 50:
                    pid = conn.pid or 0
                    proc_name = "-"
                    if pid > 0:
                        if pid not in proc_cache:
                            try:
                                proc_cache[pid] = psutil.Process(pid).name()
                            except Exception:
                                proc_cache[pid] = "system/restricted"
                        proc_name = proc_cache[pid]

                    proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    connections_list.append(
                        NetworkConnectionInfo(
                            protocol=proto,
                            local_address=laddr_str,
                            remote_address=raddr_str,
                            status=status,
                            process_name=proc_name,
                            pid=pid,
                            risk_level="MENCURIGAKAN" if is_suspicious else "NORMAL",
                            is_suspicious=is_suspicious,
                        )
                    )

        risk_score = 0
        if suspicious_count > 0:
            risk_score += min(70, suspicious_count * 35)
        if listening_count > 25:
            risk_score += 15
            anomalies.append(f"Jumlah port LISTENING tinggi ({listening_count} port terbuka).")
        if established_count > 60:
            risk_score += 15
            anomalies.append(f"Lonjakan koneksi aktif ESTABLISHED ({established_count} sesi).")

        risk_score = min(100, max(0, risk_score))
        if risk_score >= 60:
            severity = "HIGH"
            status_label = "BERBAHAYA"
        elif risk_score >= 25:
            severity = "MEDIUM"
            status_label = "WASPADA"
        else:
            severity = "LOW"
            status_label = "AMAN"
            if not anomalies:
                anomalies.append("Tidak ditemukan koneksi backdoor maupun anomali trafik jaringan.")

        summary_notes = " | ".join(anomalies)[:1500]
        report = NetworkSnapshotReport(
            interface_name=interface_name,
            local_ip=local_ip,
            bytes_sent_mb=bytes_sent_mb,
            bytes_recv_mb=bytes_recv_mb,
            established_count=established_count,
            listening_count=listening_count,
            suspicious_count=suspicious_count,
            risk_score=risk_score,
            severity=severity,
            status_label=status_label,
            interfaces=interfaces_info,
            connections=connections_list,
            anomalies=anomalies,
            summary_notes=summary_notes,
        )

        if save_to_db:
            self._persist_snapshot(report, is_demo=is_demo)

        return report

    def capture_snapshot(self, save_to_db: bool = True, is_demo: bool = False) -> NetworkSnapshotReport:
        return self.scan_network(save_to_db=save_to_db, is_demo=is_demo)

    def capture_live_snapshot(self, save_to_db: bool = True, is_demo: bool = False) -> NetworkSnapshotReport:
        return self.scan_network(save_to_db=save_to_db, is_demo=is_demo)

    def _persist_snapshot(self, report: NetworkSnapshotReport, is_demo: bool = False) -> None:
        try:
            with get_db_session(self.session_factory) as session:
                snap = NetworkSnapshot(
                    interface_name=report.interface_name[:128],
                    local_ip=report.local_ip[:64],
                    primary_ip=report.local_ip[:64],
                    bytes_sent_mb=report.bytes_sent_mb,
                    bytes_recv_mb=report.bytes_recv_mb,
                    established_count=report.established_count,
                    listening_count=report.listening_count,
                    suspicious_count=report.suspicious_count,
                    risk_score=report.risk_score,
                    severity=report.severity,
                    summary_notes=report.summary_notes,
                    is_demo=is_demo,
                )
                session.add(snap)

                event = SecurityEvent(
                    source_module="NETWORK_MONITOR",
                    event_type=f"NETWORK_SCAN_{report.status_label}",
                    severity=report.severity,
                    risk_score=report.risk_score,
                    description=(
                        f"Pemindaian jaringan pada {report.interface_name} ({report.local_ip}): "
                        f"{report.established_count} ESTABLISHED, {report.listening_count} LISTENING, "
                        f"{report.suspicious_count} anomali (Skor: {report.risk_score}/100)."
                    ),
                    is_demo=is_demo,
                )
                session.add(event)
        except Exception as exc:
            logger.error("Gagal menyimpan snapshot jaringan ke database: %s", exc)

    def get_snapshot_history(self, is_demo: bool = False, limit: int = 15) -> List[Dict[str, Any]]:
        with get_db_session(self.session_factory) as session:
            stmt = (
                select(NetworkSnapshot)
                .where(NetworkSnapshot.is_demo == is_demo)
                .order_by(desc(NetworkSnapshot.created_at), desc(NetworkSnapshot.id))
                .limit(limit)
            )
            rows = list(session.scalars(stmt).all())
            return [
                {
                    "Waktu (UTC)": r.created_at.strftime("%Y-%m-%d %H:%M:%S") if r.created_at else "-",
                    "Interface": r.interface_name,
                    "IP Lokal": r.local_ip,
                    "Established": r.active_connections_count,
                    "Listening": r.listening_ports_count,
                    "Anomali": r.suspicious_connections_count,
                    "Skor Risiko": f"{r.risk_score}/100",
                    "Severity": r.severity,
                }
                for r in rows
            ]