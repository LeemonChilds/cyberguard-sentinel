"""
CYBERGUARD SENTINEL — Secure Centralized Logger

Menyediakan logger terpusat dengan rotasi file otomatis dan filter penyensoran
untuk mencegah kebocoran informasi sensitif (seperti password atau token) ke file log.
"""

import logging
import re
from logging.handlers import RotatingFileHandler
import config


class SensitiveDataFilter(logging.Filter):
    """
    Filter logging untuk menyensor pola kata sandi atau kredensial
    sebelum ditulis ke file log maupun konsol.
    """

    SENSITIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
        re.compile(r"(password\s*[=:]\s*)([^\s,;\"']+)", re.IGNORECASE),
        re.compile(r"(passwd\s*[=:]\s*)([^\s,;\"']+)", re.IGNORECASE),
        re.compile(r"(pwd\s*[=:]\s*)([^\s,;\"']+)", re.IGNORECASE),
        re.compile(r"(secret\s*[=:]\s*)([^\s,;\"']+)", re.IGNORECASE),
        re.compile(r"(token\s*[=:]\s*)([^\s,;\"']+)", re.IGNORECASE),
    )

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            sanitized = record.msg
            for pattern in self.SENSITIVE_PATTERNS:
                sanitized = pattern.sub(r"\1[REDACTED]", sanitized)
            record.msg = sanitized

        if record.args:
            sanitized_args = []
            for arg in record.args:
                if isinstance(arg, str):
                    clean_arg = arg
                    for pattern in self.SENSITIVE_PATTERNS:
                        clean_arg = pattern.sub(r"\1[REDACTED]", clean_arg)
                    sanitized_args.append(clean_arg)
                else:
                    sanitized_args.append(arg)
            record.args = tuple(sanitized_args)

        return True


def get_logger(name: str = "cyberguard") -> logging.Logger:
    """
    Mengembalikan instance logger yang sudah terkonfigurasi dengan aman.
    Mencegah duplikasi handler saat Streamlit melakukan rerun.
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    numeric_level = getattr(logging, config.LOG_LEVEL, logging.INFO)
    logger.setLevel(numeric_level)
    logger.propagate = False

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Pastikan folder log tersedia
    config.LOG_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Rotating File Handler: maksimal 2 MB per file, simpan hingga 3 cadangan
    file_handler = RotatingFileHandler(
        filename=config.LOG_FILE_PATH,
        maxBytes=2 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setLevel(numeric_level)
    file_handler.setFormatter(formatter)
    file_handler.addFilter(SensitiveDataFilter())

    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(SensitiveDataFilter())

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger