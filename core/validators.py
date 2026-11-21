"""
CYBERGUARD SENTINEL — Strict Input Validators & Security Guardrails

Menyediakan validasi ketat untuk seluruh input pengguna (URL, Target Host,
Port Range, dan File Path) sebelum diproses oleh modul keamanan.
"""

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse
import config


class ValidationError(ValueError):
    """Exception khusus ketika input gagal melewati validasi keamanan."""


def validate_url(raw_url: str) -> str:
    """
    Memvalidasi format dan skema URL untuk Phishing Detection Engine.
    Hanya mengizinkan skema http dan https.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ValidationError("URL tidak boleh kosong.")

    cleaned = raw_url.strip()
    if len(cleaned) > 2048:
        raise ValidationError("Panjang URL melebihi batas aman (maksimal 2048 karakter).")

    if any(char in cleaned for char in ("\n", "\r", "\x00", " ")):
        raise ValidationError("URL mengandung spasi atau karakter kontrol yang tidak valid.")

    parsed = urlparse(cleaned)
    if parsed.scheme.lower() not in config.ALLOWED_URL_SCHEMES:
        raise ValidationError(
            f"Skema URL '{parsed.scheme}' ditolak. Hanya skema HTTP/HTTPS yang diizinkan."
        )

    if not parsed.netloc:
        raise ValidationError("URL tidak memiliki nama domain atau host yang valid.")

    return cleaned


def validate_scan_target(target: str, explicit_authorization: bool = False) -> str:
    """
    Memvalidasi target host untuk Port Security Scanner.
    - Default terkunci pada 127.0.0.1 / localhost.
    - Host jaringan lokal/privat lain hanya diizinkan dengan otorisasi eksplisit.
    - Pemindaian alamat IP publik diblokir demi kepatuhan etika defensif.
    """
    if not target or not isinstance(target, str):
        raise ValidationError("Target host tidak boleh kosong.")

    cleaned = target.strip().lower()

    if cleaned in ("localhost", "127.0.0.1", "::1"):
        return "127.0.0.1"

    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except ValueError as exc:
        raise ValidationError(
            f"Format alamat IP '{target}' tidak valid. Gunakan format IPv4 yang benar (contoh: 127.0.0.1)."
        ) from exc

    if ip_obj.is_loopback:
        return str(ip_obj)

    if ip_obj.is_private:
        if not explicit_authorization:
            raise ValidationError(
                "Otorisasi eksplisit wajib dicentang untuk memindai alamat IP jaringan privat selain 127.0.0.1."
            )
        return str(ip_obj)

    raise ValidationError(
        "Akses ditolak: Pemindaian terhadap alamat IP publik dilarang oleh kebijakan keamanan sistem."
    )


def validate_port_range(start_port: int, end_port: int) -> tuple[int, int]:
    """
    Memvalidasi rentang port untuk mencegah pemindaian massal berlebihan.
    """
    if not isinstance(start_port, int) or not isinstance(end_port, int):
        raise ValidationError("Nomor port harus berupa bilangan bulat.")

    if start_port < config.MIN_PORT_NUMBER or end_port > config.MAX_PORT_NUMBER:
        raise ValidationError(
            f"Port harus berada dalam rentang {config.MIN_PORT_NUMBER} hingga {config.MAX_PORT_NUMBER}."
        )

    if start_port > end_port:
        raise ValidationError("Port awal tidak boleh lebih besar dari port akhir.")

    total_ports = (end_port - start_port) + 1
    if total_ports > config.MAX_PORTS_PER_SCAN:
        raise ValidationError(
            f"Jumlah port ({total_ports}) melebihi batas maksimal ({config.MAX_PORTS_PER_SCAN} port per pemindaian)."
        )

    return start_port, end_port


def validate_local_path(raw_path: str, must_exist: bool = True) -> Path:
    """
    Menormalisasi dan memvalidasi path lokal untuk File Integrity Monitor.
    Mencegah path traversal dan melindungi folder sensitif sistem operasi.
    """
    if not raw_path or not isinstance(raw_path, str):
        raise ValidationError("Path file atau folder tidak boleh kosong.")

    cleaned = raw_path.strip()
    if "\x00" in cleaned:
        raise ValidationError("Path mengandung karakter null yang tidak valid.")

    try:
        resolved_path = Path(cleaned).expanduser().resolve()
    except (OSError, RuntimeError) as exc:
        raise ValidationError(f"Path tidak dapat diproses: {exc}") from exc

    # Lindungi direktori inti Windows dari pemindaian masif yang tidak disengaja
    restricted_prefixes = (
        Path("C:/Windows").resolve(),
        Path("C:/Program Files").resolve(),
        Path("C:/Program Files (x86)").resolve(),
    )
    for restricted in restricted_prefixes:
        if resolved_path == restricted or restricted in resolved_path.parents:
            raise ValidationError(
                f"Akses dibatasi: Path berada di dalam direktori sistem operasi ({restricted})."
            )

    if must_exist and not resolved_path.exists():
        raise ValidationError(f"Target file atau folder tidak ditemukan: {resolved_path}")

    return resolved_path


def validate_mode(mode: str) -> str:
    """Memastikan mode operasi sistem hanya LIVE atau DEMO."""
    if not mode or not isinstance(mode, str):
        raise ValidationError("Mode sistem harus ditentukan.")
    upper_mode = mode.strip().upper()
    if upper_mode not in config.VALID_MODES:
        raise ValidationError(
            f"Mode '{mode}' tidak valid. Pilihan yang tersedia: {config.VALID_MODES}"
        )
    return upper_mode


def sanitize_text_input(text: str, max_length: int = 500) -> str:
    """Membersihkan teks input umum (seperti catatan insiden) dari karakter kontrol berbahaya."""
    if text is None:
        return ""
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(text)).strip()
    return cleaned[:max_length]