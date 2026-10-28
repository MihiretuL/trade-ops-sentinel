"""Environment-based application configuration with local-safe defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    sqlite_db_path: str = "tradeops_oms.db"
    meta_api_key: str = ""
    meta_base_url: str = ""
    baseten_api_key: str = ""
    baseten_model_id: str = "meta-models/muse-spark-open-1026"
    fireworks_api_key: str = ""
    fireworks_model_id: str = ""
    tcp_harness_host: str = "127.0.0.1"
    tcp_harness_port: int = 0


def get_settings() -> Settings:
    """Read settings on demand so tests can safely monkeypatch environment values."""
    try:
        port = int(os.getenv("TCP_HARNESS_PORT", "0"))
    except ValueError as exc:
        raise ValueError("TCP_HARNESS_PORT must be an integer") from exc
    if not 0 <= port <= 65535:
        raise ValueError("TCP_HARNESS_PORT must be between 0 and 65535")
    return Settings(
        sqlite_db_path=os.getenv("SQLITE_DB_PATH", "tradeops_oms.db"),
        meta_api_key=os.getenv("META_API_KEY", ""),
        meta_base_url=os.getenv("META_BASE_URL", ""),
        baseten_api_key=os.getenv("BASETEN_API_KEY", ""),
        baseten_model_id=os.getenv("BASETEN_MODEL_ID", "meta-models/muse-spark-open-1026"),
        fireworks_api_key=os.getenv("FIREWORKS_API_KEY", ""),
        fireworks_model_id=os.getenv("FIREWORKS_MODEL_ID", ""),
        tcp_harness_host=os.getenv("TCP_HARNESS_HOST", "127.0.0.1"),
        tcp_harness_port=port,
    )


settings = get_settings()
