"""Telegram Bot instant alerting service with persistent database retry outbox on offline failure."""

from __future__ import annotations

import json
import urllib.request
from typing import Optional, Tuple

from app.config import EngineConfig
from app.database import SAQRDatabase


class TelegramService:
    def __init__(self, config: EngineConfig, db: SAQRDatabase) -> None:
        self.token = config.telegram_bot_token.strip()
        self.chat_id = config.telegram_chat_id.strip()
        self.db = db

    def send_alert(self, incident_id: str, sanitized: dict) -> Tuple[bool, Optional[str]]:
        text = (
            f"🦅 تنبيه صَقْر (SAQR) — [{sanitized['scenario'].upper()}]\n"
            f"الحادثة: {sanitized['incident_id']} | الجهاز: {sanitized['host_alias']}\n"
            f"الخطورة: {sanitized['risk_score']}/100 | MITRE: {', '.join(sanitized.get('mitre_ids', [])) or 'N/A'}\n"
            f"العزل الشبكي: {'مفعّل ✅' if sanitized.get('quarantined') else 'غير مفعّل'}\n"
            f"SHA-256: {(sanitized.get('evidence_sha256') or 'pending')[:24]}"
        )
        payload = {"chat_id": self.chat_id, "text": text}
        if not self.token or not self.chat_id:
            jid = self.db.enqueue_outbox(incident_id, "telegram", payload, error="telegram_unconfigured_or_offline")
            return False, jid

        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                if 200 <= resp.status < 300:
                    return True, None
                err = f"http_{resp.status}"
        except Exception as exc:
            err = str(exc)

        jid = self.db.enqueue_outbox(incident_id, "telegram", payload, error=err)
        return False, jid
