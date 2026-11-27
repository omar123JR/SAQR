"""SAQR Engine configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


@dataclass
class EngineConfig:
    database_url: str = field(default_factory=lambda: os.getenv("DATABASE_URL", ""))
    sqlite_path: Path = field(default_factory=lambda: Path(os.getenv("SAQR_SQLITE_PATH", "/tmp/saqr_rework/saqr.db")))
    evidence_dir: Path = field(default_factory=lambda: Path(os.getenv("SAQR_EVIDENCE_DIR", "/tmp/saqr_rework/evidence")))

    webhook_secret: str = field(default_factory=lambda: os.getenv("SAQR_WEBHOOK_SECRET", "saqr-dev-webhook-secret-change-me"))
    jwt_secret: str = field(default_factory=lambda: os.getenv("SAQR_JWT_SECRET", "saqr-dev-jwt-secret-change-me"))
    analyst_password: str = field(default_factory=lambda: os.getenv("SAQR_ANALYST_PASSWORD", "SaqrAnalyst!2026"))

    # Wazuh Manager v4.14.11 REST API
    wazuh_api_url: str = field(default_factory=lambda: os.getenv("WAZUH_API_URL", "https://wazuh.manager:55000"))
    wazuh_api_user: str = field(default_factory=lambda: os.getenv("WAZUH_API_USER", "wazuh-wui"))
    wazuh_api_password: str = field(default_factory=lambda: os.getenv("WAZUH_API_PASSWORD", ""))
    wazuh_verify_tls: bool = field(default_factory=lambda: os.getenv("WAZUH_VERIFY_TLS", "false").lower() == "true")
    wazuh_dry_run: bool = field(default_factory=lambda: os.getenv("WAZUH_DRY_RUN", "true").lower() == "true")

    # Pluggable AI Reporting: gemini | ollama | offline
    llm_provider: str = field(default_factory=lambda: os.getenv("LLM_PROVIDER", "gemini"))
    gemini_api_key: str = field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""))
    gemini_model: str = field(default_factory=lambda: os.getenv("GEMINI_MODEL", "gemini-2.5-flash"))
    ollama_base_url: str = field(default_factory=lambda: os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434"))
    ollama_model: str = field(default_factory=lambda: os.getenv("OLLAMA_MODEL", "qwen2.5:7b-instruct-q4_K_M"))

    # Telegram Bot
    telegram_bot_token: str = field(default_factory=lambda: os.getenv("TELEGRAM_BOT_TOKEN", ""))
    telegram_chat_id: str = field(default_factory=lambda: os.getenv("TELEGRAM_CHAT_ID", ""))

    # Protected brand domains (Scenario 2: Phishing)
    protected_domains: List[str] = field(
        default_factory=lambda: [
            d.strip().lower()
            for d in os.getenv(
                "PROTECTED_DOMAINS",
                "saqr-bank.ly,ministry-health.gov.ly,saraya.edu.ly",
            ).split(",")
            if d.strip()
        ]
    )
