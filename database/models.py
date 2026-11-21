"""
CYBERGUARD SENTINEL — Database ORM Models (TiDB Cloud & SQLite Compatible)

Mendefinisikan 7 entitas utama platform sesuai standar arsitektur:
1. SecurityEvent
2. ScanHistory
3. FileBaseline
4. FileChange
5. SecurityIncident
6. NetworkSnapshot
7. PhishingHistory

Catatan kompatibilitas TiDB/MySQL & Backward-Compatibility:
- Seluruh kolom String memiliki panjang eksplisit (<= 768 untuk kolom terindeks utf8mb4).
- Penghitung byte jaringan menggunakan BigInteger agar tidak overflow di atas 2 GB.
- Menyediakan kolom, relasi ORM (events, incident, baseline, changes), dan properti alias
  agar seluruh modul berjalan selaras tanpa bentrok skema.
"""

from __future__ import annotations

from datetime import datetime
from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """Base class deklaratif SQLAlchemy untuk seluruh model CYBERGUARD SENTINEL."""


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(
        Integer,
        ForeignKey("security_incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    source_module = Column(String(100), nullable=False, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(32), nullable=False, default="LOW")
    risk_score = Column(Integer, nullable=False, default=0)
    description = Column(Text, nullable=False)
    target = Column(String(512), nullable=True)
    details = Column(Text, nullable=True)
    is_demo = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)

    incident = relationship("SecurityIncident", back_populates="events")

    @property
    def timestamp(self) -> datetime:
        return self.created_at


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_type = Column(String(64), nullable=False, default="PORT_SCAN", index=True)
    target = Column(String(255), nullable=False)
    target_host = Column(String(255), nullable=True)
    port_range = Column(String(128), nullable=True)
    ports_scanned = Column(Integer, nullable=False, default=0)
    open_ports_count = Column(Integer, nullable=False, default=0)
    closed_ports_count = Column(Integer, nullable=False, default=0)
    open_ports_json = Column(Text, nullable=True)
    open_ports = Column(Text, nullable=True)
    risk_score = Column(Integer, nullable=False, default=0)
    severity = Column(String(32), nullable=False, default="LOW")
    status = Column(String(32), nullable=False, default="COMPLETED")
    summary = Column(Text, nullable=True)
    summary_notes = Column(Text, nullable=True)
    details = Column(Text, nullable=True)
    is_demo = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)

    @property
    def timestamp(self) -> datetime:
        return self.created_at

    @property
    def host(self) -> str:
        return self.target_host or self.target


class FileBaseline(Base):
    __tablename__ = "file_baselines"

    id = Column(Integer, primary_key=True, autoincrement=True)
    file_path = Column(String(768), nullable=False, index=True)
    file_name = Column(String(255), nullable=True)
    sha256_hash = Column(String(64), nullable=False)
    file_size = Column(BigInteger, nullable=False, default=0)
    status = Column(String(32), nullable=False, default="BASELINE")
    is_demo = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    changes = relationship("FileChange", back_populates="baseline", lazy="selectin")

    @property
    def file_hash(self) -> str:
        return self.sha256_hash


class FileChange(Base):
    __tablename__ = "file_changes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    baseline_id = Column(Integer, ForeignKey("file_baselines.id", ondelete="SET NULL"), nullable=True)
    file_path = Column(String(768), nullable=False)
    file_name = Column(String(255), nullable=True)
    change_type = Column(String(32), nullable=False)  # UNCHANGED | MODIFIED | NEW FILE | DELETED FILE
    old_hash = Column(String(64), nullable=True)
    new_hash = Column(String(64), nullable=True)
    severity = Column(String(32), nullable=False, default="MEDIUM")
    risk_score = Column(Integer, nullable=False, default=0)
    details = Column(Text, nullable=True)
    is_demo = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)

    baseline = relationship("FileBaseline", back_populates="changes")

    @property
    def timestamp(self) -> datetime:
        return self.created_at


class SecurityIncident(Base):
    __tablename__ = "security_incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_code = Column(String(64), nullable=True, index=True)
    title = Column(String(255), nullable=False)
    category = Column(String(64), nullable=False, default="NETWORK ANOMALY")
    severity = Column(String(32), nullable=False, default="MEDIUM")
    risk_score = Column(Integer, nullable=False, default=50)
    status = Column(String(32), nullable=False, default="OPEN", index=True)
    source_module = Column(String(100), nullable=True)
    target = Column(String(512), nullable=True)
    correlated_events_count = Column(Integer, nullable=False, default=1)
    description = Column(Text, nullable=False)
    mitigation = Column(Text, nullable=True)
    recommended_mitigation = Column(Text, nullable=True)
    mitigation_notes = Column(Text, nullable=True)
    timeline_json = Column(Text, nullable=True)
    is_demo = Column(Boolean, nullable=False, default=False)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    events = relationship(
        "SecurityEvent",
        back_populates="incident",
        lazy="selectin",
    )

    @property
    def timestamp(self) -> datetime:
        return self.created_at


class NetworkSnapshot(Base):
    __tablename__ = "network_snapshots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hostname = Column(String(255), nullable=True)
    local_ip = Column(String(64), nullable=True)
    primary_ip = Column(String(64), nullable=True)
    interface_name = Column(String(128), nullable=True)
    active_connections = Column(Integer, nullable=False, default=0)
    established_connections = Column(Integer, nullable=False, default=0)
    established_count = Column(Integer, nullable=False, default=0)
    listening_ports = Column(Integer, nullable=False, default=0)
    listening_count = Column(Integer, nullable=False, default=0)
    bytes_sent = Column(BigInteger, nullable=False, default=0)
    bytes_recv = Column(BigInteger, nullable=False, default=0)
    bytes_sent_mb = Column(Float, nullable=False, default=0.0)
    bytes_recv_mb = Column(Float, nullable=False, default=0.0)
    suspicious_count = Column(Integer, nullable=False, default=0)
    risk_score = Column(Integer, nullable=False, default=0)
    severity = Column(String(32), nullable=False, default="LOW")
    connections_json = Column(Text, nullable=True)
    summary = Column(Text, nullable=True)
    summary_notes = Column(Text, nullable=True)
    is_demo = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)

    @property
    def active_connections_count(self) -> int:
        if self.established_count is not None:
            return int(self.established_count)
        if self.established_connections is not None:
            return int(self.established_connections)
        return int(self.active_connections or 0)

    @active_connections_count.setter
    def active_connections_count(self, value: int) -> None:
        val = int(value or 0)
        self.established_count = val
        self.established_connections = val
        self.active_connections = val

    @property
    def listening_ports_count(self) -> int:
        if self.listening_count is not None:
            return int(self.listening_count)
        return int(self.listening_ports or 0)

    @listening_ports_count.setter
    def listening_ports_count(self, value: int) -> None:
        val = int(value or 0)
        self.listening_count = val
        self.listening_ports = val

    @property
    def suspicious_connections_count(self) -> int:
        return int(self.suspicious_count or 0)

    @suspicious_connections_count.setter
    def suspicious_connections_count(self, value: int) -> None:
        self.suspicious_count = int(value or 0)

    @property
    def timestamp(self) -> datetime:
        return self.created_at


class PhishingHistory(Base):
    __tablename__ = "phishing_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(Text, nullable=False)
    domain = Column(String(255), nullable=True, index=True)
    scheme = Column(String(16), nullable=True)
    classification = Column(String(32), nullable=False, default="SAFE")
    verdict = Column(String(32), nullable=True)
    risk_score = Column(Integer, nullable=False, default=0)
    severity = Column(String(32), nullable=False, default="LOW")
    indicators_json = Column(Text, nullable=True)
    reasons_json = Column(Text, nullable=True)
    explanation = Column(Text, nullable=True)
    is_demo = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)

    @property
    def timestamp(self) -> datetime:
        return self.created_at