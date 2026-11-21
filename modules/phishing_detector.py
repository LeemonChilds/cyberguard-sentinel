"""
CYBERGUARD SENTINEL — Multi-Category Hybrid AI Phishing & Scam Detection Engine

Mendeteksi ancaman tautan lintas kategori secara real-time:
1. Perbankan & Fintech (BRI, BCA, Mandiri, BNI, BSI, DANA, OVO, GoPay, dll.)
2. Ekspedisi & Paket Palsu (JNE, J&T, SiCepat, Pos Indonesia, Ninja Xpress, dll.)
3. Pemerintah & Bansos (Komdigi, DJP Pajak, BPJS, PLN, Kemensos, BKN/CPNS, E-Tilang)
4. E-Commerce & Travel (Shopee, Tokopedia, Lazada, Blibli, Traveloka, KAI)
5. Media Sosial & Komunikasi (WhatsApp, Telegram, Instagram, Facebook, TikTok, Zoom)
6. Gaming & Digital Goods (Roblox, Steam, Mobile Legends, Free Fire, Valorant)
7. Kripto & Dompet Web3 (Indodax, Tokocrypto, Pintu, Binance, MetaMask, PayPal)
8. Cloud, Email & Malware Lure (Google, Microsoft, Apple, GitHub, cPanel, file .APK)
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
import os
import re
import socket
import unicodedata
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlunparse
from sqlalchemy import desc, select
from sqlalchemy.orm import sessionmaker
from core.database import get_db_session
from core.logger import get_logger
from database.models import PhishingHistory, SecurityEvent

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore[assignment]

logger = get_logger("cyberguard.phishing")

MULTI_PART_TLDS = {
    "co.id",
    "or.id",
    "ac.id",
    "sch.id",
    "go.id",
    "mil.id",
    "web.id",
    "my.id",
    "biz.id",
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.jp",
    "ne.jp",
    "com.sg",
    "com.my",
}

TRUSTED_INSTITUTIONAL_TLDS = {
    "go.id",
    "ac.id",
    "sch.id",
    "mil.id",
    "gov",
    "edu",
    "mil",
}

HIGH_RISK_TLDS = {
    "xyz",
    "top",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "click",
    "loan",
    "buzz",
    "icu",
    "vip",
    "site",
    "online",
    "shop",
    "live",
    "work",
    "support",
    "club",
    "rest",
    "cam",
    "monster",
    "cfd",
    "sbs",
    "cyou",
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "s.id",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "tiny.cc",
    "rb.gy",
    "wa.link",
}

# Format: keyword -> (Nama Entitas Resmi, Kategori Layanan, Daftar Domain Resmi)
PROTECTED_ENTITIES: Dict[str, Tuple[str, str, List[str]]] = {
    # 1. Perbankan & Fintech
    "bri": ("Bank Rakyat Indonesia (BRI)", "Perbankan & Fintech", ["bri.co.id", "bri.id"]),
    "brimo": ("BRImo / Bank Rakyat Indonesia", "Perbankan & Fintech", ["bri.co.id", "bri.id"]),
    "bca": ("Bank Central Asia (BCA)", "Perbankan & Fintech", ["bca.co.id", "klikbca.com"]),
    "klikbca": ("KlikBCA / Bank Central Asia", "Perbankan & Fintech", ["bca.co.id", "klikbca.com"]),
    "mybca": ("myBCA / Bank Central Asia", "Perbankan & Fintech", ["bca.co.id", "klikbca.com"]),
    "mandiri": ("Bank Mandiri", "Perbankan & Fintech", ["bankmandiri.co.id", "mandiri.co.id"]),
    "livin": ("Livin' by Mandiri", "Perbankan & Fintech", ["bankmandiri.co.id"]),
    "bni": ("Bank Negara Indonesia (BNI)", "Perbankan & Fintech", ["bni.co.id"]),
    "wondr": ("wondr by BNI", "Perbankan & Fintech", ["bni.co.id"]),
    "bsi": ("Bank Syariah Indonesia (BSI)", "Perbankan & Fintech", ["bankbsi.co.id"]),
    "seabank": ("SeaBank Indonesia", "Perbankan & Fintech", ["seabank.co.id"]),
    "dana": ("DANA Dompet Digital", "Perbankan & Fintech", ["dana.id"]),
    "ovo": ("OVO", "Perbankan & Fintech", ["ovo.id"]),
    "gopay": ("GoPay / GoTo", "Perbankan & Fintech", ["gopay.co.id", "gojek.com"]),
    "shopeepay": ("ShopeePay", "Perbankan & Fintech", ["shopee.co.id", "shopeepay.co.id"]),
    "linkaja": ("LinkAja", "Perbankan & Fintech", ["linkaja.id"]),
    "paypal": ("PayPal", "Perbankan & Fintech", ["paypal.com"]),
    # 2. Ekspedisi & Logistik
    "jne": ("JNE Express", "Ekspedisi & Logistik", ["jne.co.id"]),
    "jnt": ("J&T Express", "Ekspedisi & Logistik", ["jet.co.id", "jtexpress.id"]),
    "sicepat": ("SiCepat Ekspres", "Ekspedisi & Logistik", ["sicepat.com"]),
    "anteraja": ("AnterAja", "Ekspedisi & Logistik", ["anteraja.id"]),
    "posindonesia": ("Pos Indonesia", "Ekspedisi & Logistik", ["posindonesia.co.id"]),
    "ninjaxpress": ("Ninja Xpress", "Ekspedisi & Logistik", ["ninjaxpress.co"]),
    "dhl": ("DHL Express", "Ekspedisi & Logistik", ["dhl.com"]),
    "fedex": ("FedEx", "Ekspedisi & Logistik", ["fedex.com"]),
    # 3. Pemerintah & Layanan Publik
    "komdigi": ("Kementerian Komunikasi dan Digital", "Pemerintah & Layanan Publik", ["komdigi.go.id", "kominfo.go.id"]),
    "kominfo": ("Kementerian Komunikasi dan Informatika", "Pemerintah & Layanan Publik", ["kominfo.go.id", "komdigi.go.id"]),
    "djp": ("Direktorat Jenderal Pajak", "Pemerintah & Layanan Publik", ["pajak.go.id"]),
    "pajak": ("Direktorat Jenderal Pajak", "Pemerintah & Layanan Publik", ["pajak.go.id"]),
    "coretax": ("Coretax DJP Pajak", "Pemerintah & Layanan Publik", ["pajak.go.id", "coretaxdjp.pajak.go.id"]),
    "bpjs": ("BPJS Kesehatan / Ketenagakerjaan", "Pemerintah & Layanan Publik", ["bpjs-kesehatan.go.id", "bpjsketenagakerjaan.go.id"]),
    "pln": ("PT PLN (Persero)", "Pemerintah & Layanan Publik", ["pln.co.id"]),
    "pertamina": ("PT Pertamina (Persero)", "Pemerintah & Layanan Publik", ["pertamina.com", "mypertamina.id"]),
    "kemensos": ("Kementerian Sosial (Bansos)", "Pemerintah & Layanan Publik", ["kemensos.go.id", "cekbansos.kemensos.go.id"]),
    "bansos": ("Program Bantuan Sosial Pemerintah", "Pemerintah & Layanan Publik", ["kemensos.go.id", "cekbansos.kemensos.go.id"]),
    "sscasn": ("SSCASN / BKN CPNS", "Pemerintah & Layanan Publik", ["sscasn.bkn.go.id", "bkn.go.id"]),
    "etilang": ("E-Tilang / ETLE Korlantas Polri", "Pemerintah & Layanan Publik", ["etilang.info", "etle-pmj.info", "polri.go.id"]),
    # 4. E-Commerce & Travel
    "shopee": ("Shopee Indonesia", "E-Commerce & Travel", ["shopee.co.id", "shopee.com"]),
    "tokopedia": ("Tokopedia", "E-Commerce & Travel", ["tokopedia.com"]),
    "lazada": ("Lazada", "E-Commerce & Travel", ["lazada.co.id", "lazada.com"]),
    "blibli": ("Blibli", "E-Commerce & Travel", ["blibli.com"]),
    "traveloka": ("Traveloka", "E-Commerce & Travel", ["traveloka.com"]),
    "tiket": ("tiket.com", "E-Commerce & Travel", ["tiket.com"]),
    # 5. Media Sosial & Komunikasi
    "whatsapp": ("WhatsApp", "Media Sosial & Komunikasi", ["whatsapp.com", "wa.me"]),
    "telegram": ("Telegram", "Media Sosial & Komunikasi", ["telegram.org", "t.me"]),
    "instagram": ("Instagram", "Media Sosial & Komunikasi", ["instagram.com"]),
    "facebook": ("Facebook / Meta", "Media Sosial & Komunikasi", ["facebook.com", "fb.com", "meta.com"]),
    "tiktok": ("TikTok", "Media Sosial & Komunikasi", ["tiktok.com"]),
    "discord": ("Discord", "Media Sosial & Komunikasi", ["discord.com", "discord.gg"]),
    "zoom": ("Zoom Video Communications", "Media Sosial & Komunikasi", ["zoom.us", "zoom.com"]),
    "netflix": ("Netflix", "Media Sosial & Komunikasi", ["netflix.com"]),
    "spotify": ("Spotify", "Media Sosial & Komunikasi", ["spotify.com"]),
    # 6. Gaming & Digital Goods
    "roblox": ("Roblox", "Gaming & Digital Goods", ["roblox.com"]),
    "steam": ("Steam / Valve", "Gaming & Digital Goods", ["steampowered.com", "steamcommunity.com"]),
    "steamcommunity": ("Steam Community", "Gaming & Digital Goods", ["steamcommunity.com", "steampowered.com"]),
    "mobilelegends": ("Mobile Legends / Moonton", "Gaming & Digital Goods", ["mobilelegends.com", "moonton.com"]),
    "freefire": ("Free Fire / Garena", "Gaming & Digital Goods", ["ff.garena.com", "garena.co.id"]),
    "valorant": ("Valorant / Riot Games", "Gaming & Digital Goods", ["playvalorant.com", "riotgames.com"]),
    # 7. Kripto & Web3
    "indodax": ("Indodax", "Kripto & Web3", ["indodax.com"]),
    "tokocrypto": ("Tokocrypto", "Kripto & Web3", ["tokocrypto.com"]),
    "binance": ("Binance", "Kripto & Web3", ["binance.com"]),
    "metamask": ("MetaMask Wallet", "Kripto & Web3", ["metamask.io"]),
    # 8. Teknologi, Cloud & Email
    "google": ("Google", "Teknologi & Cloud", ["google.com", "google.co.id", "accounts.google.com"]),
    "gmail": ("Gmail / Google", "Teknologi & Cloud", ["mail.google.com", "google.com"]),
    "microsoft": ("Microsoft", "Teknologi & Cloud", ["microsoft.com", "live.com", "office.com", "outlook.com"]),
    "office365": ("Microsoft 365", "Teknologi & Cloud", ["office.com", "microsoft.com"]),
    "apple": ("Apple", "Teknologi & Cloud", ["apple.com", "icloud.com"]),
    "icloud": ("Apple iCloud", "Teknologi & Cloud", ["icloud.com", "apple.com"]),
    "github": ("GitHub", "Teknologi & Cloud", ["github.com"]),
    "canva": ("Canva", "Teknologi & Cloud", ["canva.com"]),
}

SOCIAL_ENGINEERING_KEYWORDS = {
    "login",
    "signin",
    "sign-in",
    "verifikasi",
    "verify",
    "verification",
    "akun",
    "account",
    "update",
    "pembaruan",
    "blokir",
    "terblokir",
    "suspend",
    "suspended",
    "hadiah",
    "undian",
    "klaim",
    "claim",
    "refund",
    "secure",
    "security",
    "keamanan",
    "otp",
    "pin",
    "password",
    "sandi",
    "reset",
    "confirm",
    "konfirmasi",
    "e-tilang",
    "etilang",
    "tilang",
    "paket",
    "resi",
    "kurir",
    "ekspedisi",
    "tracking",
    "tertahan",
    "undangan",
    "pernikahan",
    "nikah",
    "bansos",
    "subsidi",
    "bantuan",
    "beasiswa",
    "cpns",
    "webmail",
    "cpanel",
    "auth",
    "wallet",
    "airdrop",
    "gift",
    "nitro",
    "robux",
    "diamond",
    "voucher",
}

NON_BANK_SCAM_PATTERNS: List[Tuple[str, str, str, int]] = [
    (
        r"(undangan|nikah|pernikahan|walimah|resepsi)",
        "Modus Undangan Digital Palsu (APK Malware Lure)",
        "Tautan memakai kata kunci undangan acara yang sering dipakai menyebarkan file instalasi berbahaya (.APK).",
        35,
    ),
    (
        r"(resi|paket|kurir|ekspedisi|tracking|kiriman|tertahan)",
        "Modus Paket / Kurir Ekspedisi Palsu",
        "Tautan memakai pola pelacakan paket/resi palsu untuk memancing korban mengunduh aplikasi atau mengisi data pribadi.",
        30,
    ),
    (
        r"(bansos|subsidi|bantuan|pkh|blt|prakerja|cpns|beasiswa|tilang)",
        "Modus Bantuan Sosial / Layanan Publik Palsu",
        "Tautan menjanjikan bantuan/layanan publik di luar domain resmi pemerintah (.go.id).",
        35,
    ),
    (
        r"(airdrop|wallet|seed|phrase|metamask|usdt|crypto|token-claim)",
        "Modus Crypto Wallet Drainer / Airdrop Palsu",
        "Tautan mengarah pada klaim aset kripto/dompet Web3 yang berisiko menguras saldo dompet digital.",
        35,
    ),
    (
        r"(robux|diamond|nitro|skin-gratis|free-gift|voucher-gratis|topup-gratis)",
        "Modus Hadiah / Top-Up Game Palsu",
        "Tautan menawarkan item/mata uang game gratis untuk mencuri kredensial akun game atau media sosial.",
        30,
    ),
    (
        r"(webmail|cpanel|mailbox|quota-full|admin-verify|sso-login)",
        "Modus Pencurian Kredensial Email / Korporat",
        "Tautan meniru halaman masuk email/server internal untuk memanen username dan kata sandi.",
        30,
    ),
]

DANGEROUS_EXTENSIONS = (
    ".apk",
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".msi",
    ".jar",
    ".zip",
    ".rar",
)


@dataclass
class ThreatIndicator:
    code: str
    points: int
    severity: str
    description: str


@dataclass
class PhishingAnalysisResult:
    raw_url: str
    normalized_url: str
    scheme: str
    hostname: str
    registered_domain: str
    subdomain: str
    tld: str
    path: str
    is_defanged: bool
    is_https: bool
    impersonated_brand: Optional[str]
    official_domains: List[str] = field(default_factory=list)
    attack_category: str = "Umum / Tidak Terkategorisasi"
    dns_resolved: bool = False
    resolved_ips: List[str] = field(default_factory=list)
    dns_status_text: str = "TIDAK DIPERIKSA"
    http_status: Optional[int] = None
    http_status_text: str = "OFFLINE / TIDAK TERJANGKAU"
    redirect_hops: int = 0
    redirect_chain: List[str] = field(default_factory=list)
    final_url: str = ""
    risk_score: int = 0
    classification: str = "SAFE"  # SAFE | SUSPICIOUS | PHISHING
    severity: str = "LOW"  # LOW | MEDIUM | HIGH | CRITICAL
    verdict_title: str = ""
    verdict_explanation: str = ""
    mitigation_steps: List[str] = field(default_factory=list)
    indicators: List[ThreatIndicator] = field(default_factory=list)
    # Hybrid AI Threat Intelligence Attributes
    ai_engine_mode: str = "LOCAL ML LEXICAL AI (REAL-TIME)"
    ai_phishing_probability: float = 0.0
    ai_verdict: str = "SAFE"
    ai_confidence: str = "HIGH"
    ai_reasoning: str = ""
    ai_red_flags: List[str] = field(default_factory=list)
    ai_feature_weights: List[Dict[str, Any]] = field(default_factory=list)


class PhishingDetector:
    """Mesin deteksi phishing multi-kategori dengan Local ML + Gemini Cloud AI Auditor."""

    def __init__(self, session_factory: Optional[sessionmaker] = None) -> None:
        self.session_factory = session_factory

    @staticmethod
    def _normalize_url(raw_url: str) -> Tuple[str, bool]:
        cleaned = (raw_url or "").strip()
        if not cleaned:
            raise ValueError("URL tidak boleh kosong.")

        is_defanged = False
        lowered = cleaned.lower()
        if (
            lowered.startswith("hxxp://")
            or lowered.startswith("hxxps://")
            or "[.]" in cleaned
            or "(.)" in cleaned
            or "[:]" in cleaned
        ):
            is_defanged = True

        normalized = re.sub(r"^hxxps://", "https://", cleaned, flags=re.IGNORECASE)
        normalized = re.sub(r"^hxxp://", "http://", normalized, flags=re.IGNORECASE)
        normalized = normalized.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")

        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", normalized):
            normalized = f"http://{normalized}"

        parsed = urlparse(normalized)
        if not parsed.hostname:
            raise ValueError(f"Format URL tidak valid atau nama host tidak ditemukan: '{raw_url}'")

        rebuilt = urlunparse(
            (
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path or "/",
                parsed.params,
                parsed.query,
                "",
            )
        )
        return rebuilt, is_defanged

    @staticmethod
    def _split_domain_parts(hostname: str) -> Tuple[str, str, str]:
        """Memisahkan hostname menjadi (registered_domain, subdomain, tld)."""
        host = hostname.strip(".").lower()
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) or ":" in host:
            return host, "", "IP"

        labels = [p for p in host.split(".") if p]
        if len(labels) < 2:
            return host, "", ""

        last_two = ".".join(labels[-2:])
        if last_two in MULTI_PART_TLDS and len(labels) >= 3:
            reg_domain = ".".join(labels[-3:])
            subdomain = ".".join(labels[:-3])
            tld = last_two
        else:
            reg_domain = last_two
            subdomain = ".".join(labels[:-2])
            tld = labels[-1]

        return reg_domain, subdomain, tld

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        freq: Dict[str, int] = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return PhishingDetector._levenshtein_distance(s2, s1)
        if not s2:
            return len(s1)
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def _detect_brand_spoofing(
        self,
        hostname: str,
        registered_domain: str,
        subdomain: str,
        path: str,
    ) -> Tuple[Optional[str], str, List[str], Optional[ThreatIndicator]]:
        """Mendeteksi penyamaran merek resmi lintas kategori maupun homograph/typosquatting."""
        for _, (brand_label, category, official_list) in PROTECTED_ENTITIES.items():
            if registered_domain in official_list:
                return brand_label, category, official_list, None

        nfkc_host = unicodedata.normalize("NFKC", hostname)
        homograph_normalized = (
            nfkc_host.replace("I", "l")
            .lower()
            .replace("0", "o")
            .replace("1", "l")
            .replace("3", "e")
            .replace("4", "a")
            .replace("5", "s")
            .replace("@", "a")
        )
        homograph_i = (
            nfkc_host.lower()
            .replace("1", "i")
            .replace("0", "o")
            .replace("3", "e")
            .replace("4", "a")
            .replace("5", "s")
        )

        for _, (brand_label, category, official_list) in PROTECTED_ENTITIES.items():
            for off_dom in official_list:
                if off_dom in homograph_normalized or off_dom in homograph_i:
                    if registered_domain != off_dom:
                        return (
                            brand_label,
                            f"Homograph / Lookalike ({category})",
                            official_list,
                            ThreatIndicator(
                                code="HOMOGRAPH_LOOKALIKE_DOMAIN",
                                points=45,
                                severity="CRITICAL",
                                description=(
                                    f"Domain tiruan/homograph terdeteksi! '{hostname}' meniru visual domain resmi "
                                    f"'{off_dom}' ({brand_label}) menggunakan substitusi karakter."
                                ),
                            ),
                        )

        tokens = set(re.split(r"[^a-z0-9]+", f"{subdomain}.{registered_domain}{path}".lower()))
        combined_alpha = re.sub(r"[^a-z]", "", f"{subdomain}{registered_domain}".lower())

        for brand_key, (brand_label, category, official_list) in PROTECTED_ENTITIES.items():
            if len(brand_key) >= 3 and (
                brand_key in tokens or (len(brand_key) >= 4 and brand_key in combined_alpha)
            ):
                location_note = (
                    f"pada subdomain '{subdomain}'"
                    if brand_key in subdomain.lower()
                    else f"pada domain/path '{registered_domain}{path}'"
                )
                return (
                    brand_label,
                    f"Penyamaran {category}",
                    official_list,
                    ThreatIndicator(
                        code="BRAND_IMPERSONATION",
                        points=45,
                        severity="CRITICAL",
                        description=(
                            f"Penyamaran entitas resmi terdeteksi! Tautan mencatut identitas {brand_label} ({category}) "
                            f"{location_note}, padahal domain asli terdaftarnya adalah '{registered_domain}' "
                            f"(situs resmi: {', '.join(official_list)})."
                        ),
                    ),
                )

        reg_base = registered_domain.split(".")[0]
        if len(reg_base) >= 5:
            for _, (brand_label, category, official_list) in PROTECTED_ENTITIES.items():
                for off_dom in official_list:
                    off_base = off_dom.split(".")[0]
                    if len(off_base) >= 5 and abs(len(reg_base) - len(off_base)) <= 1:
                        dist = self._levenshtein_distance(reg_base, off_base)
                        if 1 <= dist <= 2:
                            return (
                                brand_label,
                                f"Typosquatting ({category})",
                                official_list,
                                ThreatIndicator(
                                    code="TYPOSQUATTING_DOMAIN",
                                    points=40,
                                    severity="HIGH",
                                    description=(
                                        f"Indikasi typosquatting terhadap {brand_label}: '{registered_domain}' "
                                        f"hanya berbeda {dist} karakter dari domain resmi '{off_dom}'."
                                    ),
                                ),
                            )

        return None, "Umum / Tidak Terkategorisasi", [], None

    @staticmethod
    def _resolve_dns(hostname: str) -> Tuple[bool, List[str], str]:
        try:
            infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
            ips = sorted({str(info[4][0]) for info in infos if info[4]})
            if ips:
                return True, ips, f"AKTIF ({', '.join(ips[:3])})"
            return False, [], "TIDAK ADA RECORD IP"
        except socket.gaierror:
            return False, [], "NXDOMAIN / DOMAIN TIDAK TERDAFTAR DI DNS"
        except Exception as exc:
            return False, [], f"GAGAL RESOLUSI DNS ({exc})"

    @staticmethod
    def _inspect_live_http(
        url: str, timeout: float = 5.0
    ) -> Tuple[Optional[int], str, List[str], str, List[ThreatIndicator]]:
        extra_indicators: List[ThreatIndicator] = []
        chain: List[str] = [url]
        current_url = url
        last_status: Optional[int] = None

        if requests is None:
            return None, "PUSTAKA HTTP TIDAK TERSEDIA", chain, current_url, extra_indicators

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
            )
        }

        try:
            for _ in range(5):
                resp = requests.get(
                    current_url,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=False,
                    stream=True,
                )
                last_status = resp.status_code
                content_type = (resp.headers.get("Content-Type") or "").lower()
                content_disp = (resp.headers.get("Content-Disposition") or "").lower()

                if (
                    "application/vnd.android.package-archive" in content_type
                    or ".apk" in content_disp
                    or ".exe" in content_disp
                ):
                    extra_indicators.append(
                        ThreatIndicator(
                            code="MALICIOUS_PAYLOAD_DOWNLOAD",
                            points=40,
                            severity="CRITICAL",
                            description="Server mengirimkan file instalasi berbahaya (.APK / .EXE) secara langsung.",
                        )
                    )

                if resp.is_redirect or resp.is_permanent_redirect or last_status in {301, 302, 303, 307, 308}:
                    loc = resp.headers.get("Location")
                    resp.close()
                    if not loc:
                        break
                    next_url = urljoin(current_url, loc)
                    if next_url in chain:
                        break
                    chain.append(next_url)
                    current_url = next_url
                    continue

                try:
                    snippet = resp.raw.read(16384, decode_content=True).decode("utf-8", errors="ignore").lower()
                    if 'type="password"' in snippet or "type='password'" in snippet:
                        extra_indicators.append(
                            ThreatIndicator(
                                code="CREDENTIAL_FORM_DETECTED",
                                points=20,
                                severity="HIGH",
                                description="Halaman web memuat formulir input kata sandi (type='password').",
                            )
                        )
                except Exception:
                    pass
                finally:
                    resp.close()
                break

            start_host = urlparse(url).hostname or ""
            end_host = urlparse(current_url).hostname or ""
            if start_host and end_host and start_host != end_host:
                extra_indicators.append(
                    ThreatIndicator(
                        code="CROSS_DOMAIN_REDIRECT",
                        points=20,
                        severity="HIGH",
                        description=f"Tautan mengalihkan pengunjung lintas domain dari '{start_host}' ke '{end_host}'.",
                    )
                )

            status_text = f"HTTP {last_status}" if last_status is not None else "TERHUBUNG"
            return last_status, status_text, chain, current_url, extra_indicators

        except requests.exceptions.SSLError:
            extra_indicators.append(
                ThreatIndicator(
                    code="INVALID_SSL_CERTIFICATE",
                    points=25,
                    severity="HIGH",
                    description="Sertifikat SSL/TLS server tidak valid atau kedaluwarsa.",
                )
            )
            return None, "SSL/TLS ERROR", chain, current_url, extra_indicators
        except requests.exceptions.Timeout:
            return None, "TIMEOUT (>5 DETIK)", chain, current_url, extra_indicators
        except requests.exceptions.ConnectionError:
            return None, "SERVER OFFLINE / MENOLAK KONEKSI", chain, current_url, extra_indicators
        except Exception as exc:
            return None, f"ERROR KONEKSI ({type(exc).__name__})", chain, current_url, extra_indicators

    def _run_local_ml_classifier(
        self,
        *,
        normalized_url: str,
        hostname: str,
        registered_domain: str,
        subdomain: str,
        tld: str,
        is_https: bool,
        is_defanged: bool,
        is_official_brand: bool,
        indicator_codes: set[str],
        matched_keywords_count: int,
    ) -> Tuple[float, str, str, str, List[Dict[str, Any]]]:
        """
        Model AI Klasifikasi Leksikal & Struktural Lokal Multi-Kategori (Real-Time Offline).
        Mampu mendeteksi phishing perbankan MAUPUN modus non-bank (kurir, bansos, game, kripto, APK).
        """
        reg_base = registered_domain.split(".")[0]
        entropy_norm = min(1.0, max(0.0, (self._shannon_entropy(reg_base) - 2.2) / 2.2))
        length_norm = min(1.0, max(0.0, (len(normalized_url) - 25) / 90.0))
        digit_ratio = sum(ch.isdigit() for ch in hostname) / max(1, len(hostname))
        hyphen_norm = min(1.0, hostname.count("-") / 3.0)
        sub_depth_norm = min(1.0, len([s for s in subdomain.split(".") if s]) / 3.0)
        kw_density = min(1.0, matched_keywords_count / 2.5)
        has_scam_archetype = 1.0 if "NON_BANK_SCAM_PATTERN" in indicator_codes else 0.0
        has_high_risk_tld = 1.0 if tld in HIGH_RISK_TLDS else 0.0
        combo_lure_tld = 1.0 if (has_high_risk_tld > 0 and (matched_keywords_count >= 1 or has_scam_archetype > 0)) else 0.0

        features: List[Tuple[str, float, float]] = [
            ("Penyamaran Entitas / Merek Resmi", 1.0 if "BRAND_IMPERSONATION" in indicator_codes else 0.0, 3.85),
            ("Homograph / Typosquatting Domain", 1.0 if ({"HOMOGRAPH_LOOKALIKE_DOMAIN", "TYPOSQUATTING_DOMAIN"} & indicator_codes) else 0.0, 4.05),
            ("Pola Modus Penipuan Non-Bank (Kurir/Bansos/Game/APK)", has_scam_archetype, 3.45),
            ("Kombinasi TLD Berisiko + Kata Kunci Jebakan", combo_lure_tld, 2.50),
            ("Domain Resmi Terdaftar (Whitelist)", 1.0 if is_official_brand else 0.0, -4.40),
            ("TLD Institusional Terpercaya (.go.id/.ac.id/.edu)", 1.0 if tld in TRUSTED_INSTITUTIONAL_TLDS else 0.0, -1.75),
            ("Kepadatan Kata Kunci Rekayasa Sosial", kw_density, 2.35),
            ("Ekstensi Domain Berisiko Tinggi (TLD)", has_high_risk_tld, 1.45),
            ("Penggunaan Alamat IP Mentah", 1.0 if tld == "IP" else 0.0, 2.75),
            ("Berkas Eksekusi / Paket Berbahaya (.APK/.EXE)", 1.0 if ({"DANGEROUS_FILE_EXTENSION", "MALICIOUS_PAYLOAD_DOWNLOAD"} & indicator_codes) else 0.0, 4.10),
            ("Format Tautan Disamarkan (hxxp/[.])", 1.0 if is_defanged else 0.0, 1.15),
            ("Tanpa Enkripsi HTTPS (Plain HTTP)", 0.0 if is_https else 1.0, 0.90),
            ("Kepadatan Tanda Hubung ('-') Domain", hyphen_norm, 0.85),
            ("Kedalaman Subdomain Bertingkat", sub_depth_norm, 0.80),
            ("Entropi Acak & Rasio Digit Domain", min(1.0, entropy_norm * 0.7 + digit_ratio * 1.5 + length_norm * 0.3), 0.70),
            ("Anomali Sesi Live HTTP / Redirect / SSL", 1.0 if ({"CROSS_DOMAIN_REDIRECT", "CREDENTIAL_FORM_DETECTED", "INVALID_SSL_CERTIFICATE"} & indicator_codes) else 0.0, 1.65),
        ]

        bias = -2.00
        logit = bias + sum(val * weight for _, val, weight in features)
        prob = 1.0 / (1.0 + math.exp(-max(-20.0, min(20.0, logit))))
        prob_pct = round(prob * 100.0, 1)

        if prob_pct >= 68.0:
            ai_verdict = "PHISHING"
        elif prob_pct >= 32.0:
            ai_verdict = "SUSPICIOUS"
        else:
            ai_verdict = "SAFE"

        distance_from_boundary = abs(prob_pct - 50.0)
        if distance_from_boundary >= 28.0:
            confidence = "HIGH (Tinggi)"
        elif distance_from_boundary >= 14.0:
            confidence = "MEDIUM (Sedang)"
        else:
            confidence = "LOW (Perbatasan)"

        feature_rows: List[Dict[str, Any]] = []
        active_drivers: List[str] = []
        for fname, fval, fweight in features:
            contrib = round(fval * fweight, 2)
            if abs(contrib) >= 0.15:
                feature_rows.append(
                    {
                        "Fitur AI": fname,
                        "Nilai Fitur": round(fval, 2),
                        "Bobot Model": f"{fweight:+.2f}",
                        "Kontribusi Logit": f"{contrib:+.2f}",
                    }
                )
                if contrib > 0:
                    active_drivers.append(f"{fname} ({contrib:+.2f})")

        feature_rows.sort(key=lambda r: abs(float(r["Kontribusi Logit"])), reverse=True)

        if ai_verdict == "PHISHING":
            reasoning = (
                f"Model AI Leksikal menghitung probabilitas phishing sebesar {prob_pct}% ({confidence}). "
                f"Pemicu dominan: {', '.join(active_drivers[:3]) if active_drivers else 'kombinasi struktur URL berisiko'}."
            )
        elif ai_verdict == "SUSPICIOUS":
            reasoning = (
                f"Model AI Leksikal mendeteksi anomali moderat dengan probabilitas phishing {prob_pct}% ({confidence}). "
                f"Faktor utama: {', '.join(active_drivers[:2]) if active_drivers else 'struktur domain tidak lazim'}."
            )
        else:
            if is_official_brand:
                reasoning = (
                    f"Model AI Leksikal memverifikasi domain '{registered_domain}' sebagai domain resmi terdaftar "
                    f"dengan probabilitas phishing sangat rendah ({prob_pct}%)."
                )
            else:
                reasoning = (
                    f"Model AI Leksikal tidak menemukan pola penyamaran entitas maupun struktur rekayasa sosial "
                    f"(probabilitas phishing {prob_pct}%)."
                )

        return prob_pct, ai_verdict, confidence, reasoning, feature_rows

    @staticmethod
    def _run_cloud_gemini_audit(
        *,
        api_key: str,
        raw_url: str,
        normalized_url: str,
        registered_domain: str,
        subdomain: str,
        dns_status_text: str,
        http_status_text: str,
        indicators: List[ThreatIndicator],
    ) -> Optional[Dict[str, Any]]:
        """
        Memanggil Google Gemini REST API secara real-time untuk audit semantik mendalam lintas semua jenis tautan
        (perbankan, ekspedisi/paket, pemerintah/bansos, game, media sosial, kripto, webmail, malware, atau situs resmi).
        """
        if requests is None or not api_key or not api_key.strip():
            return None

        ind_summary = "; ".join(f"{i.code}: {i.description}" for i in indicators) or "Tidak ada indikator statis"
        prompt = (
            "Anda adalah Senior SOC & Cyber Threat Intelligence Analyst. Tugas Anda menganalisis SEMUA JENIS URL "
            "(bukan hanya perbankan, melainkan juga ekspedisi/paket, pemerintah/bansos/e-tilang/CPNS, e-commerce, "
            "media sosial, game online, kripto/Web3, login email/perusahaan, undangan/APK malware, dan situs resmi).\n\n"
            "Data Telemetri URL:\n"
            f"- URL Mentah: {raw_url}\n"
            f"- URL Ternormalisasi: {normalized_url}\n"
            f"- Subdomain: {subdomain or '(tidak ada)'}\n"
            f"- Domain Utama Terdaftar (eTLD+1): {registered_domain}\n"
            f"- Status DNS: {dns_status_text}\n"
            f"- Status HTTP: {http_status_text}\n"
            f"- Indikator Forensik Awal: {ind_summary}\n\n"
            "Instruksi Evaluasi:\n"
            "1. Periksa apakah domain utama terdaftar benar-benar milik organisasi resmi, atau merupakan domain palsu/tiruan/scam.\n"
            "2. Jika tautan adalah penipuan/phishing/scam (baik bank maupun non-bank seperti paket JNE/J&T, bansos Kemensos, "
            "akun Steam/Roblox/IG/WA, crypto drainer, atau undangan APK), tentukan kategori modusnya, entitas yang dipalsukan, "
            "dan sebutkan domain resmi yang benar.\n"
            "3. Jika tautan benar-benar situs resmi/sah yang aman, beri verdict SAFE dengan probabilitas rendah.\n\n"
            "Balas HANYA dalam JSON valid dengan skema persis berikut:\n"
            "{\n"
            '  "verdict": "SAFE | SUSPICIOUS | PHISHING",\n'
            '  "phishing_probability": 0-100,\n'
            '  "confidence": "HIGH | MEDIUM | LOW",\n'
            '  "attack_category": "Kategori singkat modus (misal: Penipuan Ekspedisi/Paket, Penyamaran Pemerintah/Bansos, Pencurian Akun Game, Perbankan/Fintech, Crypto Drainer, Malware APK Lure, atau Situs Resmi/Aman)",\n'
            '  "impersonated_entity": "Nama merek/instansi/layanan yang ditiru atau null jika tidak meniru entitas tertentu",\n'
            '  "official_domains": ["domainresmi1.com", "domainresmi2.go.id"],\n'
            '  "red_flags": ["poin temuan 1", "poin temuan 2"],\n'
            '  "reasoning": "Penjelasan analisis tegas 2-3 kalimat dalam Bahasa Indonesia mengapa link ini palsu/berbahaya atau asli/aman."\n'
            "}"
        )

        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json",
            },
        }

        models_to_try = ["gemini-2.5-flash", "gemini-2.0-flash"]
        for model_name in models_to_try:
            endpoint = (
                f"https://generativelanguage.googleapis.com/v1beta/models/"
                f"{model_name}:generateContent?key={api_key.strip()}"
            )
            try:
                resp = requests.post(endpoint, json=payload, timeout=8.0)
                if resp.status_code != 200:
                    logger.warning("Gemini model %s mengembalikan HTTP %s", model_name, resp.status_code)
                    continue
                data = resp.json()
                text_out = (
                    data.get("candidates", [{}])[0]
                    .get("content", {})
                    .get("parts", [{}])[0]
                    .get("text", "")
                )
                parsed_json = json.loads(text_out)
                verdict = str(parsed_json.get("verdict", "")).upper().strip()
                if verdict not in {"SAFE", "SUSPICIOUS", "PHISHING"}:
                    continue
                prob = float(parsed_json.get("phishing_probability", 50.0))
                prob = round(min(100.0, max(0.0, prob)), 1)
                conf = str(parsed_json.get("confidence", "MEDIUM")).upper().strip()
                attack_cat = str(parsed_json.get("attack_category", "")).strip()
                raw_entity = parsed_json.get("impersonated_entity")
                entity = (
                    str(raw_entity).strip()
                    if raw_entity and str(raw_entity).strip().lower() not in {"null", "none", "tidak ada", "-"}
                    else None
                )
                raw_officials = parsed_json.get("official_domains") or []
                official_domains = [
                    str(d).strip().lower()
                    for d in raw_officials
                    if isinstance(d, str) and "." in d and len(d.strip()) >= 4
                ]
                raw_flags = parsed_json.get("red_flags") or []
                red_flags = [str(f).strip() for f in raw_flags if isinstance(f, str) and f.strip()]
                reasoning = str(parsed_json.get("reasoning", "")).strip()
                return {
                    "model": model_name,
                    "verdict": verdict,
                    "probability": prob,
                    "confidence": conf,
                    "attack_category": attack_cat,
                    "impersonated_entity": entity,
                    "official_domains": official_domains,
                    "red_flags": red_flags,
                    "reasoning": reasoning,
                }
            except Exception as exc:
                logger.debug("Gagal menghubungi model %s: %s", model_name, exc)
                continue

        return None

    def analyze_url(
        self,
        raw_url: str,
        perform_live_http: bool = True,
        save_to_db: bool = True,
        is_demo: bool = False,
        gemini_api_key: Optional[str] = None,
    ) -> PhishingAnalysisResult:
        """Menjalankan analisis keamanan menyeluruh lintas kategori (Heuristik + DNS/HTTP + Hybrid AI)."""
        normalized_url, is_defanged = self._normalize_url(raw_url)
        parsed = urlparse(normalized_url)
        scheme = (parsed.scheme or "http").lower()
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        is_https = scheme == "https"

        registered_domain, subdomain, tld = self._split_domain_parts(hostname)
        indicators: List[ThreatIndicator] = []

        if is_defanged:
            indicators.append(
                ThreatIndicator(
                    code="DEFANGED_URL_FORMAT",
                    points=15,
                    severity="MEDIUM",
                    description=(
                        "Tautan menggunakan format samaran ('hxxp://' atau '[.]') yang umum digunakan "
                        "untuk membagikan indikator tautan phishing/berbahaya."
                    ),
                )
            )

        if not is_https:
            indicators.append(
                ThreatIndicator(
                    code="NO_HTTPS_ENCRYPTION",
                    points=15,
                    severity="MEDIUM",
                    description="Tautan tidak menggunakan protokol keamanan HTTPS; komunikasi tidak terenkripsi.",
                )
            )

        if tld == "IP":
            indicators.append(
                ThreatIndicator(
                    code="RAW_IP_HOST",
                    points=35,
                    severity="HIGH",
                    description=f"Tautan menggunakan alamat IP mentah ({hostname}) sebagai pengganti nama domain resmi.",
                )
            )

        if "@" in parsed.netloc:
            indicators.append(
                ThreatIndicator(
                    code="AT_SYMBOL_OBFUSCATION",
                    points=35,
                    severity="HIGH",
                    description="Tautan menggunakan simbol '@' untuk menyembunyikan tujuan server sebenarnya.",
                )
            )

        if "xn--" in hostname:
            indicators.append(
                ThreatIndicator(
                    code="PUNYCODE_IDN_HOMOGRAPH",
                    points=35,
                    severity="HIGH",
                    description="Domain menggunakan encoding Punycode ('xn--') yang berisiko serangan homograph karakter Unicode.",
                )
            )

        if registered_domain in URL_SHORTENERS:
            indicators.append(
                ThreatIndicator(
                    code="URL_SHORTENER_SERVICE",
                    points=20,
                    severity="MEDIUM",
                    description=f"Tautan menggunakan pemendek URL ('{registered_domain}') yang menyembunyikan tujuan akhir.",
                )
            )

        if tld in HIGH_RISK_TLDS:
            indicators.append(
                ThreatIndicator(
                    code="HIGH_RISK_TLD",
                    points=20,
                    severity="MEDIUM",
                    description=f"Ekstensi domain '.{tld}' sering dimanfaatkan untuk kampanye phishing/spam berbiaya murah.",
                )
            )

        hyphen_count = hostname.count("-")
        if hyphen_count >= 2:
            indicators.append(
                ThreatIndicator(
                    code="EXCESSIVE_HYPHENS",
                    points=15,
                    severity="MEDIUM",
                    description=f"Domain menggunakan {hyphen_count} tanda hubung ('-') yang umum pada domain tiruan.",
                )
            )

        if subdomain:
            sub_levels = [s for s in subdomain.split(".") if s]
            if len(sub_levels) >= 2:
                indicators.append(
                    ThreatIndicator(
                        code="MULTI_LEVEL_SUBDOMAIN",
                        points=20,
                        severity="HIGH",
                        description=(
                            f"Struktur subdomain bertingkat ({len(sub_levels)} level: '{subdomain}') "
                            f"digunakan untuk mengecoh pengguna dari domain utama '{registered_domain}'."
                        ),
                    )
                )

        impersonated_brand, attack_category, official_domains, brand_indicator = self._detect_brand_spoofing(
            hostname=hostname,
            registered_domain=registered_domain,
            subdomain=subdomain,
            path=path,
        )
        is_official_brand = bool(impersonated_brand and registered_domain in official_domains)
        if brand_indicator is not None:
            indicators.append(brand_indicator)

        # Deteksi pola penipuan non-bank (Undangan APK, Paket/Kurir, Bansos, Crypto, Game, Webmail)
        full_lower = f"{hostname}{path}".lower()
        if not is_official_brand and tld not in TRUSTED_INSTITUTIONAL_TLDS:
            for pattern, cat_label, desc_text, pts in NON_BANK_SCAM_PATTERNS:
                if re.search(pattern, full_lower):
                    if attack_category == "Umum / Tidak Terkategorisasi":
                        attack_category = cat_label
                    indicators.append(
                        ThreatIndicator(
                            code="NON_BANK_SCAM_PATTERN",
                            points=pts,
                            severity="HIGH",
                            description=f"[{cat_label}] {desc_text}",
                        )
                    )
                    break

        url_words = set(re.split(r"[^a-z0-9-]+", full_lower))
        sub_tokens = set(re.split(r"[^a-z0-9]+", full_lower))
        matched_keywords = sorted((url_words | sub_tokens) & SOCIAL_ENGINEERING_KEYWORDS)
        if matched_keywords and not is_official_brand:
            indicators.append(
                ThreatIndicator(
                    code="SOCIAL_ENGINEERING_KEYWORDS",
                    points=min(30, 10 + len(matched_keywords) * 5),
                    severity="HIGH" if len(matched_keywords) >= 2 else "MEDIUM",
                    description=(
                        f"Tautan mengandung kata kunci rekayasa sosial pemancing korban: "
                        f"{', '.join(repr(k) for k in matched_keywords[:5])}."
                    ),
                )
            )

        if any(path.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS):
            if attack_category == "Umum / Tidak Terkategorisasi":
                attack_category = "Distribusi Malware / APK Berbahaya"
            indicators.append(
                ThreatIndicator(
                    code="DANGEROUS_FILE_EXTENSION",
                    points=40,
                    severity="CRITICAL",
                    description="Tautan mengarah langsung ke unduhan berkas eksekusi/paket aplikasi berbahaya.",
                )
            )

        if len(normalized_url) >= 85:
            indicators.append(
                ThreatIndicator(
                    code="EXCESSIVE_URL_LENGTH",
                    points=10,
                    severity="LOW",
                    description=f"Panjang URL tidak lazim ({len(normalized_url)} karakter) untuk menyamarkan parameter.",
                )
            )

        if (
            self._shannon_entropy(registered_domain.split(".")[0]) >= 3.9
            and len(registered_domain.split(".")[0]) >= 12
        ):
            indicators.append(
                ThreatIndicator(
                    code="HIGH_DOMAIN_ENTROPY",
                    points=15,
                    severity="MEDIUM",
                    description="Nama domain memiliki pola karakter acak berentropi tinggi (mirip domain DGA).",
                )
            )

        # Resolusi DNS Real-Time & Inspeksi HTTP Langsung
        dns_resolved, resolved_ips, dns_status_text = self._resolve_dns(hostname)
        http_status: Optional[int] = None
        http_status_text = "TIDAK DIPERIKSA (MODE STATIS)"
        redirect_chain: List[str] = [normalized_url]
        final_url = normalized_url

        if perform_live_http:
            if not dns_resolved:
                http_status_text = "OFFLINE / DOMAIN TIDAK TERDAFTAR DI DNS"
            else:
                http_status, http_status_text, redirect_chain, final_url, live_inds = self._inspect_live_http(
                    normalized_url
                )
                indicators.extend(live_inds)

        # Layer 1 AI: Local ML Lexical & Structural Classifier
        indicator_codes = {ind.code for ind in indicators}
        ai_prob, ai_verdict, ai_conf, ai_reasoning, ai_feature_rows = self._run_local_ml_classifier(
            normalized_url=normalized_url,
            hostname=hostname,
            registered_domain=registered_domain,
            subdomain=subdomain,
            tld=tld,
            is_https=is_https,
            is_defanged=is_defanged,
            is_official_brand=is_official_brand,
            indicator_codes=indicator_codes,
            matched_keywords_count=len(matched_keywords) if not is_official_brand else 0,
        )
        ai_engine_mode = "LOCAL ML LEXICAL AI (REAL-TIME OFFLINE)"
        ai_red_flags: List[str] = []

        # Layer 2 AI: Real-Time Cloud Gemini Semantic Auditor (Multi-Category)
        effective_api_key = (gemini_api_key or os.getenv("GEMINI_API_KEY") or "").strip()
        if effective_api_key and not is_demo:
            cloud_ai = self._run_cloud_gemini_audit(
                api_key=effective_api_key,
                raw_url=raw_url,
                normalized_url=normalized_url,
                registered_domain=registered_domain,
                subdomain=subdomain,
                dns_status_text=dns_status_text,
                http_status_text=http_status_text,
                indicators=indicators,
            )
            if cloud_ai is not None:
                ai_engine_mode = f"HYBRID AI (LOCAL ML + {cloud_ai['model'].upper()})"
                cloud_prob = float(cloud_ai["probability"])
                cloud_verdict = cloud_ai["verdict"]

                # Jika Gemini menemukan ancaman yang belum ada di kamus lokal, jangan turunkan skornya
                if cloud_verdict == "PHISHING":
                    ai_prob = round(max(cloud_prob, (0.35 * ai_prob) + (0.65 * cloud_prob)), 1)
                    ai_verdict = "PHISHING"
                elif cloud_verdict == "SUSPICIOUS":
                    ai_prob = round(max(cloud_prob * 0.9, (0.40 * ai_prob) + (0.60 * cloud_prob)), 1)
                    ai_verdict = "PHISHING" if ai_prob >= 70.0 else "SUSPICIOUS"
                else:
                    ai_prob = round((0.40 * ai_prob) + (0.60 * cloud_prob), 1)
                    if ai_prob >= 70.0:
                        ai_verdict = "PHISHING"
                    elif ai_prob >= 35.0:
                        ai_verdict = "SUSPICIOUS"
                    else:
                        ai_verdict = "SAFE"

                if cloud_ai.get("attack_category"):
                    attack_category = cloud_ai["attack_category"]
                if cloud_ai.get("impersonated_entity") and not impersonated_brand:
                    impersonated_brand = cloud_ai["impersonated_entity"]
                if cloud_ai.get("official_domains") and not official_domains:
                    official_domains = cloud_ai["official_domains"]
                    if registered_domain in official_domains:
                        is_official_brand = True

                ai_red_flags = cloud_ai.get("red_flags") or []
                ai_conf = f"{cloud_ai['confidence']} (GEMINI VERIFIED)"
                ai_reasoning = (
                    f"[Gemini AI]: {cloud_ai['reasoning']} | "
                    f"[Local ML]: {ai_reasoning}"
                )

        # Fusi Skor Heuristik + Probabilitas AI
        heuristic_raw = sum(ind.points for ind in indicators)
        has_critical_spoof = bool(
            {
                "BRAND_IMPERSONATION",
                "HOMOGRAPH_LOOKALIKE_DOMAIN",
                "MALICIOUS_PAYLOAD_DOWNLOAD",
                "DANGEROUS_FILE_EXTENSION",
            }
            & indicator_codes
        )
        if has_critical_spoof and heuristic_raw < 85:
            heuristic_raw = 85

        if is_official_brand and not has_critical_spoof and ai_verdict == "SAFE":
            risk_score = min(15, int(round(ai_prob)))
            if attack_category == "Umum / Tidak Terkategorisasi":
                attack_category = "Situs Resmi Terverifikasi"
        else:
            fused_score = max(heuristic_raw, int(round((0.45 * heuristic_raw) + (0.55 * ai_prob))))
            if ai_verdict == "PHISHING" and fused_score < 75:
                fused_score = max(75, int(round(ai_prob)))
            elif ai_verdict == "SUSPICIOUS" and fused_score < 38:
                fused_score = max(38, int(round(ai_prob)))
            risk_score = min(100, max(0, fused_score))

        if risk_score >= 60:
            classification = "PHISHING"
            severity = "CRITICAL" if risk_score >= 80 else "HIGH"
        elif risk_score >= 30:
            classification = "SUSPICIOUS"
            severity = "MEDIUM"
        else:
            classification = "SAFE"
            severity = "LOW"
            if attack_category == "Umum / Tidak Terkategorisasi":
                attack_category = "Tautan Normal / Aman"

        if classification == "PHISHING":
            verdict_title = f"BAHAYA TERDETEKSI: TAUTAN PHISHING / SCAM ({risk_score}/100)"
            if impersonated_brand and official_domains:
                verdict_explanation = (
                    f"JANGAN KLIK ATAU MASUKKAN DATA! Sistem Forensik & AI ({ai_prob}% probabilitas phishing) "
                    f"mendeteksi modus {attack_category} yang mencatut identitas {impersonated_brand}. "
                    f"Domain utama sebenarnya adalah '{registered_domain}', bukan situs resmi ({', '.join(official_domains)})."
                )
            elif impersonated_brand:
                verdict_explanation = (
                    f"JANGAN KLIK ATAU MASUKKAN DATA! Sistem Forensik & AI ({ai_prob}% probabilitas phishing) "
                    f"mendeteksi modus {attack_category} yang mencatut {impersonated_brand} melalui domain palsu '{registered_domain}'."
                )
            else:
                verdict_explanation = (
                    f"JANGAN KLIK ATAU MASUKKAN DATA! Tautan pada domain '{registered_domain}' teridentifikasi sebagai "
                    f"{attack_category} dengan probabilitas AI phishing sebesar {ai_prob}%."
                )
            mitigation_steps = [
                "Segera tutup halaman dan JANGAN memasukkan Username, Password, PIN, maupun kode OTP.",
                "Jangan mengunduh atau memasang file apa pun (terutama .APK / .EXE) dari tautan ini.",
                f"Blokir domain '{registered_domain}' pada firewall, DNS filter, atau peramban.",
                "Laporkan tautan berbahaya ke Aduan Konten Komdigi (aduankonten.id) atau tim keamanan terkait.",
            ]
        elif classification == "SUSPICIOUS":
            verdict_title = f"PERINGATAN WASPADA: TAUTAN MENCURIGAKAN ({risk_score}/100)"
            verdict_explanation = (
                f"Tautan menuju '{registered_domain}' terindikasi memiliki pola {attack_category} "
                f"(Probabilitas AI Phishing: {ai_prob}%). Pastikan keaslian sumber sebelum berinteraksi."
            )
            mitigation_steps = [
                "Verifikasi ulang sumber pengirim pesan melalui kanal resmi sebelum membuka tautan.",
                "Hindari mengunduh lampiran atau mengisi formulir kredensial pada halaman ini.",
            ]
        else:
            verdict_title = f"TAUTAN TERVERIFIKASI AMAN ({risk_score}/100)"
            if impersonated_brand and is_official_brand:
                verdict_explanation = (
                    f"Domain '{registered_domain}' terverifikasi cocok dengan situs resmi milik {impersonated_brand} "
                    f"(Probabilitas AI Phishing: {ai_prob}%)."
                )
            else:
                verdict_explanation = (
                    f"Tidak ditemukan indikator phishing maupun penyamaran entitas pada domain '{registered_domain}' "
                    f"(Probabilitas AI Phishing: {ai_prob}%)."
                )
            mitigation_steps = [
                "Tetap pastikan ikon gembok HTTPS aktif di bilah alamat peramban sebelum memasukkan data sensitif.",
            ]

        result = PhishingAnalysisResult(
            raw_url=raw_url.strip(),
            normalized_url=normalized_url,
            scheme=scheme,
            hostname=hostname,
            registered_domain=registered_domain,
            subdomain=subdomain,
            tld=tld,
            path=path,
            is_defanged=is_defanged,
            is_https=is_https,
            impersonated_brand=impersonated_brand,
            official_domains=official_domains,
            attack_category=attack_category,
            dns_resolved=dns_resolved,
            resolved_ips=resolved_ips,
            dns_status_text=dns_status_text,
            http_status=http_status,
            http_status_text=http_status_text,
            redirect_hops=max(1, len(redirect_chain)),
            redirect_chain=redirect_chain,
            final_url=final_url,
            risk_score=risk_score,
            classification=classification,
            severity=severity,
            verdict_title=verdict_title,
            verdict_explanation=verdict_explanation,
            mitigation_steps=mitigation_steps,
            indicators=indicators,
            ai_engine_mode=ai_engine_mode,
            ai_phishing_probability=ai_prob,
            ai_verdict=ai_verdict,
            ai_confidence=ai_conf,
            ai_reasoning=ai_reasoning,
            ai_red_flags=ai_red_flags,
            ai_feature_weights=ai_feature_rows,
        )

        if save_to_db:
            self._persist_analysis(result, is_demo=is_demo)

        return result

    def _persist_analysis(self, result: PhishingAnalysisResult, is_demo: bool = False) -> None:
        try:
            summary_codes = ", ".join(ind.code for ind in result.indicators) or "CLEAN"
            ai_tag = f"AI:{result.ai_phishing_probability}% | {result.attack_category}"
            with get_db_session(self.session_factory) as session:
                session.add(
                    PhishingHistory(
                        analyzed_url=result.raw_url[:1024],
                        classification=result.classification,
                        risk_score=result.risk_score,
                        http_status=result.http_status,
                        indicators_summary=f"{ai_tag} | {summary_codes}"[:1000],
                        is_demo=is_demo,
                    )
                )
                session.add(
                    SecurityEvent(
                        source_module="PHISHING_DETECTOR",
                        event_type=f"URL_SCAN_{result.classification}",
                        severity=result.severity,
                        risk_score=result.risk_score,
                        description=(
                            f"Analisis Hybrid AI URL '{result.raw_url}' -> {result.classification} "
                            f"[{result.attack_category}] (Skor: {result.risk_score}/100, "
                            f"Probabilitas AI: {result.ai_phishing_probability}%, Domain Asli: {result.registered_domain})."
                        ),
                        is_demo=is_demo,
                    )
                )
        except Exception as exc:
            logger.error("Gagal menyimpan riwayat analisis phishing: %s", exc)

    def get_recent_history(self, is_demo: bool = False, limit: int = 15) -> List[Dict[str, Any]]:
        with get_db_session(self.session_factory) as session:
            stmt = (
                select(PhishingHistory)
                .where(PhishingHistory.is_demo == is_demo)
                .order_by(desc(PhishingHistory.created_at), desc(PhishingHistory.id))
                .limit(limit)
            )
            rows = list(session.scalars(stmt).all())
            return [
                {
                    "Waktu (UTC)": r.created_at.strftime("%Y-%m-%d %H:%M:%S") if r.created_at else "-",
                    "URL Dianalisis": r.analyzed_url,
                    "Klasifikasi": r.classification,
                    "Skor Risiko": f"{r.risk_score}/100",
                    "HTTP Status": r.http_status if r.http_status is not None else "OFFLINE / N/A",
                    "Kategori & Indikator AI": r.indicators_summary,
                }
                for r in rows
            ]