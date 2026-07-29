from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse

from dotenv import load_dotenv


load_dotenv()


def _normalize_base_url(value: str | None) -> str | None:
    if not value:
        return None
    normalized = value.rstrip("/")
    if urlparse(normalized).path in {"", "/"}:
        return f"{normalized}/v1"
    return normalized


@dataclass(frozen=True)
class Settings:
    api_key: str | None = os.getenv("AI_API_KEY")
    base_url: str | None = _normalize_base_url(os.getenv("AI_BASE_URL"))
    model: str | None = os.getenv("AI_MODEL_NAME")
    host: str = os.getenv("AGENT_HOST", "127.0.0.1")
    port: int = int(os.getenv("AGENT_PORT", "8000"))

    @property
    def llm_enabled(self) -> bool:
        return bool(self.api_key and self.model)


settings = Settings()
