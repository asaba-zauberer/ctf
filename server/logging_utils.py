"""Logging helpers for the Flask application."""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

from logging import NullHandler

FLAG_PATTERN = re.compile(r"flag\{[^}]*\}", re.IGNORECASE)


def mask_sensitive(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return FLAG_PATTERN.sub("flag{***}", value)


def configure_logging(log_dir: Path, enable: bool = True) -> logging.Logger:
    logger = logging.getLogger("ctf_app")
    if logger.handlers:
        return logger

    if not enable:
        logger.addHandler(NullHandler())
        return logger

    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "app.log"

    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(log_path, encoding="utf-8")
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger
