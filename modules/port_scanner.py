"""
CYBERGUARD SENTINEL — Authorized Web & Network Port Security Scanner (Module 05)

Memindai port TCP (1 - 65535) secara defensif dan terotorisasi untuk layanan Web maupun Network:
- Mendukung target localhost (127.0.0.1), IP jaringan lokal (LAN), maupun domain/URL web terotorisasi
- Mengizinkan pemilihan port bebas dari rentang penuh 1 - 65535 (dibatasi maks 100 port per sesi)
- Rate-limited TCP connect probe (read-only, tanpa payload eksploitasi)
- Identifikasi layanan Web, Network, dan Database beserta skor risiko & mitigasi
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import ipaddress
import json
import socket
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse
from sqlalchemy import desc, select
from sqlalchemy.orm import sessionmaker
from core.database import get_db_session
from core.logger import get_logger
from database.models import ScanHistory, SecurityEvent

logger = get_logger("cyberguard.ports")

MAX_PORTS_PER_SCAN = 100
DEFAULT_CONNECT_TIMEOUT = 0.6

# Pemetaan port Web, Network, dan Database: (Nama Layanan, Kategori, Level Risiko, Poin Risiko, Rekomendasi)
COMMON_PORT_SERVICES: Dict[int, Tuple[str, str, str, int, str]] = {
    # --- WEB & APPLICATION PORTS ---
    80: ("HTTP Web Server", "WEB", "LOW", 10, "Server web tanpa enkripsi TLS; alihkan lalu lintas ke HTTPS (443)."),
    443: ("HTTPS Secure Web", "WEB", "LOW", 5, "Server web terenkripsi TLS/SSL; pastikan sertifikat valid dan TLS 1.2/1.3 aktif."),
    3000: ("Node.js / React Dev Server", "WEB", "MEDIUM", 15, "Port aplikasi web/API pengembangan; pastikan tidak terekspos publik tanpa reverse proxy."),
    3001: ("Web / API Service Alt", "WEB", "MEDIUM", 15, "Layanan web alternatif; batasi akses dengan firewall atau autentikasi."),
    4200: ("Angular Dev Server", "WEB", "MEDIUM", 15, "Server pengembangan frontend; matikan pada lingkungan produksi."),
    5000: ("Flask / Python Web / UPnP", "WEB", "MEDIUM", 15, "Port aplikasi web Python atau UPnP; pastikan mode debug nonaktif."),
    5173: ("Vite Frontend Server", "WEB", "MEDIUM", 15, "Server pengembangan frontend Vite; ikat ke localhost jika hanya untuk lokal."),
    8000: ("HTTP-Alt / Django / FastAPI", "WEB", "LOW", 10, "Server aplikasi web/API; gunakan reverse proxy Nginx/Caddy untuk produksi."),
    8008: ("HTTP-Alt / Management Web", "WEB", "MEDIUM", 15, "Antarmuka web alternatif; periksa kontrol akses halaman admin."),
    8080: ("HTTP-Proxy / Tomcat / Web Alt", "WEB", "MEDIUM", 15, "Port web alternatif atau proxy; pastikan autentikasi aktif."),
    8443: ("HTTPS-Alt Secure Web", "WEB", "LOW", 5, "Port web terenkripsi alternatif; verifikasi konfigurasi SSL/TLS."),
    8501: ("Streamlit Web Dashboard", "WEB", "LOW", 5, "Antarmuka dashboard Streamlit lokal."),
    8888: ("Jupyter Notebook / Web Alt", "WEB", "HIGH", 25, "Sering digunakan Jupyter Notebook; wajib lindungi dengan token/password kuat."),
    9000: ("SonarQube / PHP-FPM / Web App", "WEB", "MEDIUM", 15, "Layanan aplikasi web atau FastCGI; batasi akses hanya dari reverse proxy."),

    # --- NETWORK & INFRASTRUCTURE PORTS ---
    20: ("FTP Data", "NETWORK", "HIGH", 25, "Transfer data FTP tanpa enkripsi; migrasikan ke SFTP (port 22)."),
    21: ("FTP Control", "NETWORK", "HIGH", 25, "Protokol transfer berkas plaintext; rentan penyadapan kredensial."),
    22: ("SSH Remote Shell", "NETWORK", "MEDIUM", 15, "Akses remote aman; gunakan SSH key, nonaktifkan root login, dan batasi IP."),
    23: ("Telnet", "NETWORK", "CRITICAL", 35, "Protokol remote lama tanpa enkripsi; segera matikan dan ganti dengan SSH."),
    25: ("SMTP Mail Transfer", "NETWORK", "MEDIUM", 15, "Server pengiriman email; pastikan tidak dikonfigurasi sebagai open relay."),
    53: ("DNS Service", "NETWORK", "LOW", 10, "Resolusi nama domain; batasi recursive query hanya untuk klien internal."),
    67: ("DHCP Server", "NETWORK", "LOW", 10, "Layanan alokasi IP jaringan lokal; aktifkan DHCP snooping di switch."),
    69: ("TFTP", "NETWORK", "HIGH", 25, "Trivial FTP tanpa autentikasi; isolasi hanya di VLAN manajemen."),
    110: ("POP3 Mail", "NETWORK", "HIGH", 20, "Protokol email tanpa enkripsi; gunakan POP3S (995)."),
    111: ("RPCbind / Portmapper", "NETWORK", "HIGH", 25, "Layanan RPC Unix/Linux; jangan ekspos ke jaringan publik."),
    123: ("NTP Time Sync", "NETWORK", "LOW", 5, "Sinkronisasi waktu jaringan; batasi mode monlist untuk mencegah amplifikasi."),
    135: ("MS-RPC Windows", "NETWORK", "HIGH", 25, "Remote Procedure Call Windows; blokir dari jaringan eksternal."),
    137: ("NetBIOS Name Service", "NETWORK", "HIGH", 20, "Enumerasi nama host Windows lama; nonaktifkan jika tidak dibutuhkan."),
    139: ("NetBIOS Session", "NETWORK", "HIGH", 25, "Berbagi sesi NetBIOS lama; rentan enumerasi jaringan lokal."),
    143: ("IMAP Mail", "NETWORK", "MEDIUM", 15, "Protokol email tanpa enkripsi; gunakan IMAPS (993)."),
    161: ("SNMP Network Mgmt", "NETWORK", "HIGH", 25, "Manajemen perangkat jaringan; gunakan SNMPv3 berenkripsi, hindari community 'public'."),
    389: ("LDAP Directory", "NETWORK", "HIGH", 25, "Layanan direktori tanpa TLS; gunakan LDAPS (636)."),
    445: ("SMB File Sharing", "NETWORK", "CRITICAL", 35, "Berbagi berkas Windows (SMB); target utama lateral movement dan ransomware."),
    514: ("Syslog", "NETWORK", "MEDIUM", 15, "Pengumpulan log jaringan; batasi pengirim log hanya dari perangkat terpercaya."),
    587: ("SMTP Submission", "NETWORK", "LOW", 10, "Pengiriman email terautentikasi; wajibkan STARTTLS."),
    636: ("LDAPS Secure Directory", "NETWORK", "LOW", 10, "Layanan direktori terenkripsi SSL/TLS."),
    993: ("IMAPS Secure Mail", "NETWORK", "LOW", 5, "Akses email IMAP terenkripsi TLS."),
    995: ("POP3S Secure Mail", "NETWORK", "LOW", 5, "Akses email POP3 terenkripsi TLS."),
    1723: ("PPTP VPN", "NETWORK", "HIGH", 25, "Protokol VPN lama dengan enkripsi lemah; ganti ke WireGuard atau OpenVPN."),
    3389: ("RDP Remote Desktop", "NETWORK", "CRITICAL", 35, "Akses desktop jarak jauh Windows; lindungi dengan VPN, NLA, dan firewall."),
    5900: ("VNC Remote Desktop", "NETWORK", "CRITICAL", 35, "Akses layar jarak jauh VNC; bungkus melalui SSH tunnel atau VPN."),
    5985: ("WinRM HTTP", "NETWORK", "HIGH", 25, "Windows Remote Management HTTP; batasi hanya untuk subnet admin."),
    5986: ("WinRM HTTPS", "NETWORK", "MEDIUM", 15, "Windows Remote Management terenkripsi."),

    # --- DATABASE & MESSAGE BROKER PORTS ---
    1433: ("Microsoft SQL Server", "DATABASE", "HIGH", 30, "Database MSSQL; ikat ke localhost atau jaringan privat saja."),
    1521: ("Oracle Database", "DATABASE", "HIGH", 30, "Database Oracle; batasi akses hanya dari server aplikasi."),
    1883: ("MQTT IoT Broker", "NETWORK", "MEDIUM", 15, "Protokol komunikasi IoT; aktifkan autentikasi username/password dan TLS (8883)."),
    3306: ("MySQL / MariaDB", "DATABASE", "HIGH", 30, "Database relasional; jangan ekspos langsung ke internet publik."),
    5432: ("PostgreSQL", "DATABASE", "HIGH", 25, "Database PostgreSQL; perketat aturan host di pg_hba.conf."),
    5672: ("RabbitMQ AMQP", "NETWORK", "MEDIUM", 15, "Message broker; pastikan kredensial default guest/guest diganti."),
    6379: ("Redis In-Memory DB", "DATABASE", "CRITICAL", 35, "Cache/datastore Redis; wajib aktifkan requirepass dan bind 127.0.0.1."),
    9092: ("Apache Kafka", "NETWORK", "MEDIUM", 15, "Platform streaming event; aktifkan SASL/SSL."),
    9200: ("Elasticsearch HTTP", "DATABASE", "CRITICAL", 35, "Mesin pencari/log; pastikan autentikasi X-Pack aktif agar indeks tidak bocor."),
    11211: ("Memcached", "DATABASE", "HIGH", 30, "Cache memori; ikat hanya ke 127.0.0.1 untuk mencegah penyalahgunaan."),
    27017: ("MongoDB NoSQL", "DATABASE", "CRITICAL", 35, "Database MongoDB; wajib aktifkan authorization dan bindIp privat."),
}

# Daftar preset port siap pakai untuk Web dan Network
WEB_PORTS_PRESET: List[int] = [80, 443, 3000, 3001, 4200, 5000, 5173, 8000, 8008, 8080, 8443, 8501, 8888, 9000]
NETWORK_PORTS_PRESET: List[int] = [21, 22, 23, 25, 53, 110, 135, 139, 143, 161, 389, 445, 587, 636, 993, 995, 3389, 5900]
DATABASE_PORTS_PRESET: List[int] = [1433, 1521, 1883, 3306, 5432, 5672, 6379, 9200, 11211, 27017]


@dataclass
class PortFinding:
    port: int
    state: str  # OPEN | CLOSED
    service: str
    category: str  # WEB | NETWORK | DATABASE | CUSTOM
    risk_level: str  # LOW | MEDIUM | HIGH | CRITICAL
    points: int
    recommendation: str

    @property
    def status(self) -> str:
        return self.state

    @property
    def service_name(self) -> str:
        return self.service

    @property
    def severity(self) -> str:
        return self.risk_level

    @property
    def risk_score(self) -> int:
        return self.points

    @property
    def description(self) -> str:
        return self.recommendation


@dataclass
class PortScanResult:
    target_host: str
    resolved_ip: str
    target_scope: str  # LOCALHOST | PRIVATE_NETWORK | AUTHORIZED_WEB_HOST
    port_range_label: str
    total_scanned: int
    open_ports: List[PortFinding] = field(default_factory=list)
    closed_ports_count: int = 0
    duration_seconds: float = 0.0
    risk_score: int = 0
    severity: str = "LOW"
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)

    @property
    def host(self) -> str:
        return self.target_host

    @property
    def target(self) -> str:
        return self.target_host

    @property
    def ip_address(self) -> str:
        return self.resolved_ip

    @property
    def port_range(self) -> str:
        return self.port_range_label

    @property
    def ports_scanned(self) -> int:
        return self.total_scanned

    @property
    def open_ports_count(self) -> int:
        return len(self.open_ports)

    @property
    def open_count(self) -> int:
        return len(self.open_ports)

    @property
    def closed_count(self) -> int:
        return self.closed_ports_count

    @property
    def scan_duration(self) -> float:
        return self.duration_seconds

    @property
    def risk_level(self) -> str:
        return self.severity

    @property
    def findings(self) -> List[PortFinding]:
        return self.open_ports


PortScanReport = PortScanResult


class PortScanner:
    """Mesin pemindai port TCP terotorisasi untuk audit layanan Web dan Network."""

    def __init__(self, session_factory: Optional[sessionmaker] = None) -> None:
        self.session_factory = session_factory

    @staticmethod
    def normalize_target_input(raw_target: str) -> str:
        """Mengekstrak hostname atau IP bersih apabila pengguna menempelkan URL penuh (http/https)."""
        text = (raw_target or "127.0.0.1").strip()
        if not text:
            return "127.0.0.1"

        if "/" in text and "://" not in text and not text.startswith("/"):
            # Cegah notasi CIDR subnet sweep (contoh: 192.168.1.0/24)
            after_slash = text.split("/", 1)[1]
            if after_slash.isdigit():
                raise ValueError(
                    "Notasi subnet CIDR (seperti /24) tidak diizinkan. Masukkan satu alamat IP atau satu domain host."
                )

        if "*" in text:
            raise ValueError("Karakter wildcard (*) tidak diizinkan. Masukkan satu host target yang spesifik.")

        to_parse = text if "://" in text else f"tcp://{text}"
        parsed = urlparse(to_parse)
        hostname = parsed.hostname or text
        return hostname.strip()

    @classmethod
    def _validate_target(cls, target_host: str, is_authorized: bool = False) -> Tuple[str, str, str]:
        """Memvalidasi host target (Localhost, Private Network IP, atau Authorized Web Host)."""
        cleaned = cls.normalize_target_input(target_host)

        try:
            resolved_ip = socket.gethostbyname(cleaned)
            ip_obj = ipaddress.ip_address(resolved_ip)
        except Exception as exc:
            raise ValueError(f"Host atau domain target tidak dapat diresolusi ('{cleaned}'): {exc}") from exc

        if ip_obj.is_loopback or cleaned.lower() in {"localhost", "127.0.0.1", "::1"}:
            return cleaned, resolved_ip, "LOCALHOST"

        if not is_authorized:
            raise ValueError(
                f"Target '{cleaned}' ({resolved_ip}) berada di luar localhost. "
                "Centang kotak konfirmasi otorisasi resmi terlebih dahulu untuk memindai host network atau web tersebut."
            )

        if ip_obj.is_private or ip_obj.is_link_local:
            return cleaned, resolved_ip, "PRIVATE_NETWORK"

        return cleaned, resolved_ip, "AUTHORIZED_WEB_HOST"

    @staticmethod
    def _validate_port_list(
        start_port: int = 1,
        end_port: int = 100,
        custom_ports: Optional[Sequence[int]] = None,
    ) -> Tuple[List[int], str]:
        """Memvalidasi nomor port (1 - 65535) dan membatasi maksimal 100 port per sesi."""
        if custom_ports is not None:
            ports = sorted({int(p) for p in custom_ports})
            if not ports:
                raise ValueError("Daftar port yang dipindai tidak boleh kosong.")
            if any(p < 1 or p > 65535 for p in ports):
                raise ValueError("Setiap nomor port harus berada di rentang valid 1 hingga 65535.")
            if len(ports) > MAX_PORTS_PER_SCAN:
                raise ValueError(
                    f"Jumlah port ({len(ports)}) melebihi batas aman maksimal {MAX_PORTS_PER_SCAN} port per sesi."
                )
            preview = ", ".join(str(p) for p in ports[:8])
            suffix = "..." if len(ports) > 8 else ""
            label = f"Custom ({len(ports)} port: {preview}{suffix})"
            return ports, label

        s_port = int(start_port)
        e_port = int(end_port)
        if s_port < 1 or e_port > 65535 or s_port > e_port:
            raise ValueError("Rentang port tidak valid (port awal harus antara 1 hingga 65535 dan tidak melebihi port akhir).")

        count = e_port - s_port + 1
        if count > MAX_PORTS_PER_SCAN:
            raise ValueError(
                f"Rentang {s_port}-{e_port} berisi {count} port. "
                f"Batasi maksimal {MAX_PORTS_PER_SCAN} port per pemindaian (misalnya {s_port}-{s_port + MAX_PORTS_PER_SCAN - 1})."
            )

        return list(range(s_port, e_port + 1)), f"{s_port}-{e_port}"

    @staticmethod
    def _probe_tcp_port(ip_addr: str, port: int, timeout: float = DEFAULT_CONNECT_TIMEOUT) -> Tuple[int, bool]:
        """Menguji status koneksi TCP tunggal (open/closed) tanpa mengirim payload berbahaya."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex((ip_addr, port))
            return port, (code == 0)

    def scan_ports(
        self,
        target_host: str = "127.0.0.1",
        start_port: int = 1,
        end_port: int = 100,
        custom_ports: Optional[Sequence[int]] = None,
        is_authorized: bool = False,
        timeout: float = DEFAULT_CONNECT_TIMEOUT,
        save_to_db: bool = True,
        is_demo: bool = False,
        **kwargs: Any,
    ) -> PortScanReport:
        """Menjalankan pemindaian port TCP terotorisasi untuk layanan Web maupun Network."""
        effective_host = kwargs.get("host") or kwargs.get("target") or target_host
        effective_auth = bool(kwargs.get("authorized", is_authorized))
        effective_custom = kwargs.get("ports", custom_ports)

        cleaned_host, resolved_ip, target_scope = self._validate_target(
            effective_host,
            is_authorized=effective_auth,
        )
        ports_to_scan, range_label = self._validate_port_list(
            start_port=start_port,
            end_port=end_port,
            custom_ports=effective_custom,
        )

        started = time.perf_counter()
        open_findings: List[PortFinding] = []
        closed_count = 0

        # Batasi worker thread agar laju paket tetap terkendali dan tidak membebani target
        worker_cap = 20 if target_scope == "LOCALHOST" else 10
        max_workers = min(worker_cap, max(1, len(ports_to_scan)))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._probe_tcp_port, resolved_ip, port, timeout): port
                for port in ports_to_scan
            }
            for future in as_completed(futures):
                port_num, is_open = future.result()
                if is_open:
                    svc_name, category, risk_lvl, pts, rec = COMMON_PORT_SERVICES.get(
                        port_num,
                        (
                            f"Custom TCP Service (Port {port_num})",
                            "CUSTOM",
                            "MEDIUM",
                            15,
                            f"Verifikasi aplikasi yang mendengarkan pada port {port_num} dan batasi akses dengan firewall.",
                        ),
                    )
                    open_findings.append(
                        PortFinding(
                            port=port_num,
                            state="OPEN",
                            service=svc_name,
                            category=category,
                            risk_level=risk_lvl,
                            points=pts,
                            recommendation=rec,
                        )
                    )
                else:
                    closed_count += 1

        open_findings.sort(key=lambda item: item.port)
        elapsed = round(time.perf_counter() - started, 2)

        raw_risk = sum(item.points for item in open_findings)
        risk_score = min(100, raw_risk)

        if risk_score >= 80:
            severity = "CRITICAL"
        elif risk_score >= 60:
            severity = "HIGH"
        elif risk_score >= 30:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        if open_findings:
            open_summary_str = ", ".join(f"{f.port}/{f.service}" for f in open_findings)
            summary = (
                f"Ditemukan {len(open_findings)} port terbuka pada {cleaned_host} ({resolved_ip}) "
                f"dari {len(ports_to_scan)} port yang diperiksa: {open_summary_str}."
            )
            recommendations = [
                f"Port {f.port} [{f.category}] ({f.service} — {f.risk_level}): {f.recommendation}"
                for f in open_findings
            ]
        else:
            summary = (
                f"Tidak ditemukan port terbuka pada {cleaned_host} ({resolved_ip}) "
                f"untuk {len(ports_to_scan)} port yang diperiksa ({range_label})."
            )
            recommendations = [
                "Tidak ada port terbuka pada daftar/rentang yang diperiksa; pertahankan kebijakan firewall default-deny."
            ]

        result = PortScanReport(
            target_host=cleaned_host,
            resolved_ip=resolved_ip,
            target_scope=target_scope,
            port_range_label=range_label,
            total_scanned=len(ports_to_scan),
            open_ports=open_findings,
            closed_ports_count=closed_count,
            duration_seconds=elapsed,
            risk_score=risk_score,
            severity=severity,
            summary=summary,
            recommendations=recommendations,
        )

        if save_to_db:
            self._persist_scan(result, is_demo=is_demo)

        return result

    def scan(self, *args: Any, **kwargs: Any) -> PortScanReport:
        return self.scan_ports(*args, **kwargs)

    @staticmethod
    def _is_integer_column(col: Any) -> bool:
        col_type_str = str(getattr(col, "type", "")).upper()
        return "INT" in col_type_str

    def _persist_scan(self, result: PortScanReport, is_demo: bool = False) -> None:
        """Menyimpan riwayat pemindaian secara dinamis menyesuaikan kolom model ScanHistory."""
        try:
            open_ports_payload = [
                {"port": f.port, "service": f.service, "category": f.category, "risk": f.risk_level}
                for f in result.open_ports
            ]
            open_ports_json_str = json.dumps(open_ports_payload)
            open_ports_text = (
                ", ".join(f"{f.port} ({f.service})" for f in result.open_ports)
                if result.open_ports
                else "Tidak ada port terbuka"
            )

            columns = ScanHistory.__table__.columns
            col_names = set(columns.keys())
            record_kwargs: Dict[str, Any] = {}

            if "scan_type" in col_names:
                record_kwargs["scan_type"] = "PORT_SCAN"
            if "target" in col_names:
                record_kwargs["target"] = result.target_host
            if "target_host" in col_names:
                record_kwargs["target_host"] = result.target_host
            if "host" in col_names:
                record_kwargs["host"] = result.target_host
            if "port_range" in col_names:
                record_kwargs["port_range"] = result.port_range_label
            if "ports_scanned" in col_names:
                record_kwargs["ports_scanned"] = (
                    result.total_scanned
                    if self._is_integer_column(columns["ports_scanned"])
                    else result.port_range_label
                )
            if "open_ports_json" in col_names:
                record_kwargs["open_ports_json"] = open_ports_json_str
            if "open_ports" in col_names:
                record_kwargs["open_ports"] = (
                    len(result.open_ports)
                    if self._is_integer_column(columns["open_ports"])
                    else open_ports_json_str
                )
            if "open_ports_count" in col_names:
                record_kwargs["open_ports_count"] = len(result.open_ports)
            if "closed_ports_count" in col_names:
                record_kwargs["closed_ports_count"] = result.closed_ports_count
            if "risk_score" in col_names:
                record_kwargs["risk_score"] = result.risk_score
            if "severity" in col_names:
                record_kwargs["severity"] = result.severity
            if "status" in col_names:
                record_kwargs["status"] = "COMPLETED"
            if "summary" in col_names:
                record_kwargs["summary"] = result.summary[:1000]
            if "details" in col_names:
                record_kwargs["details"] = f"{open_ports_text} | {result.summary}"[:1000]
            if "is_demo" in col_names:
                record_kwargs["is_demo"] = is_demo

            with get_db_session(self.session_factory) as session:
                session.add(ScanHistory(**record_kwargs))
                session.add(
                    SecurityEvent(
                        source_module="PORT_SCANNER",
                        event_type="PORT_SCAN_COMPLETED",
                        severity=result.severity,
                        risk_score=result.risk_score,
                        description=result.summary[:1000],
                        is_demo=is_demo,
                    )
                )
        except Exception as exc:
            logger.error("Gagal menyimpan riwayat pemindaian port: %s", exc)

    @staticmethod
    def _extract_open_ports_display(row: Any) -> str:
        """Membaca daftar port terbuka secara aman dari kolom mana pun yang tersedia pada ScanHistory."""
        for attr_name in (
            "open_ports_json",
            "open_ports",
            "results_json",
            "details_json",
            "details",
            "summary",
        ):
            raw_val = getattr(row, attr_name, None)
            if raw_val is None:
                continue

            if isinstance(raw_val, int):
                return f"{raw_val} port terbuka"

            if isinstance(raw_val, list):
                if not raw_val:
                    return "Tidak ada (0 terbuka)"
                formatted = [
                    f"{item['port']}/{item.get('service', '?')}" if isinstance(item, dict) and "port" in item else str(item)
                    for item in raw_val
                ]
                return ", ".join(formatted)

            if isinstance(raw_val, str) and raw_val.strip():
                text = raw_val.strip()
                try:
                    parsed = json.loads(text)
                    if isinstance(parsed, list):
                        if not parsed:
                            return "Tidak ada (0 terbuka)"
                        formatted = [
                            f"{item['port']}/{item.get('service', '?')}" if isinstance(item, dict) and "port" in item else str(item)
                            for item in parsed
                        ]
                        return ", ".join(formatted)
                except Exception:
                    return text[:120]

        return "-"

    def get_scan_history(self, is_demo: bool = False, limit: int = 15) -> List[Dict[str, Any]]:
        """Mengambil riwayat pemindaian port dari database."""
        with get_db_session(self.session_factory) as session:
            stmt = select(ScanHistory)
            if hasattr(ScanHistory, "is_demo"):
                stmt = stmt.where(ScanHistory.is_demo == is_demo)
            if hasattr(ScanHistory, "scan_type"):
                stmt = stmt.where(ScanHistory.scan_type == "PORT_SCAN")

            order_cols = []
            if hasattr(ScanHistory, "created_at"):
                order_cols.append(desc(ScanHistory.created_at))
            if hasattr(ScanHistory, "id"):
                order_cols.append(desc(ScanHistory.id))
            if order_cols:
                stmt = stmt.order_by(*order_cols)

            stmt = stmt.limit(limit)
            rows = list(session.scalars(stmt).all())

            history_records: List[Dict[str, Any]] = []
            for r in rows:
                ts = getattr(r, "created_at", None) or getattr(r, "timestamp", None)
                ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if hasattr(ts, "strftime") else (str(ts) if ts else "-")

                target_val = (
                    getattr(r, "target", None)
                    or getattr(r, "target_host", None)
                    or getattr(r, "host", None)
                    or "127.0.0.1"
                )
                range_val = (
                    getattr(r, "port_range", None)
                    or getattr(r, "ports_scanned", None)
                    or "-"
                )
                risk_val = getattr(r, "risk_score", None)
                risk_str = f"{risk_val}/100" if risk_val is not None else "-"
                open_str = self._extract_open_ports_display(r)

                history_records.append(
                    {
                        "Waktu (UTC)": ts_str,
                        "Target Host": str(target_val),
                        "Rentang Port": str(range_val),
                        "Port Terbuka": open_str,
                        "Skor Risiko": risk_str,
                    }
                )

            return history_records