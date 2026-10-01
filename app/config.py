"""Loads config.toml (falls back to config.example.toml defaults)."""
import tomllib
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = Path(os.environ.get("SCRUBBR_DB_PATH", ROOT / "scrubbr.db")).expanduser().resolve()


def load_config() -> dict:
    path = ROOT / "config.toml"
    if not path.exists():
        path = ROOT / "config.example.toml"
    with open(path, "rb") as f:
        config = tomllib.load(f)
    if os.environ.get("SCRUBBR_MANUAL_ONLY") == "1":
        for section in ("imap", "smtp"):
            config.setdefault(section, {})["enabled"] = False
    return config
