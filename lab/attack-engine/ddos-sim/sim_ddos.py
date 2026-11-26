"""Scenario 3 Lab Verification — DDoS Botnet Flood vs. Legitimate Flash Crowd."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List


def _sign(secret: str, method: str, path: str, body: bytes) -> Dict[str, str]:
    ts = str(int(time.time()))
    nonce = secrets.token_hex(16)
    sig = hmac.new(secret.encode(), f"{ts}.{nonce}.{method}.{path}.".encode() + body, hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-SAQR-Timestamp": ts,
        "X-SAQR-Nonce": nonce,
        "X-SAQR-Signature": sig,
    }


def _hit(url: str, ip: str, ua: str) -> int:
    req = urllib.request.Request(url, headers={"X-Forwarded-For": ip, "User-Agent": ua}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
            return resp.status
    except urllib.error.HTTPError as exc:
        exc.read()
        return exc.code


def run_ddos_test(engine_url: str, webhook_secret: str) -> Dict[str, Any]:
    base = engine_url.rstrip("/")

    # 1. Legitimate High-Diversity Flash Crowd (60 distinct IPs, diverse URIs & UAs -> 0 bans!)
    flash_events = [
        {
            "src_ip": f"198.51.100.{(i % 60) + 1}",
            "uri": f"/articles/{i % 25}",
            "user_agent": f"Mozilla/5.0 Browser/{i % 20}",
            "status_code": 200,
        }
        for i in range(60)
    ]
    raw = json.dumps({"events": flash_events}, separators=(",", ":")).encode()
    hdrs = _sign(webhook_secret, "POST", "/api/v1/scenarios/ddos", raw)
    req = urllib.request.Request(f"{base}/api/v1/scenarios/ddos", data=raw, headers=hdrs, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        flash_res = json.loads(resp.read().decode("utf-8"))

    # 2. Concentrated Botnet Flood against live /api/v1/demo/web-target
    bot_ips = ["203.0.113.10", "203.0.113.11", "203.0.113.12"]
    statuses: List[int] = []
    for i in range(96):
        statuses.append(_hit(f"{base}/api/v1/demo/web-target", bot_ips[i % 3], "BotFlood/1.0"))

    bot_after = _hit(f"{base}/api/v1/demo/web-target", bot_ips[0], "BotFlood/1.0")
    benign_after = _hit(f"{base}/api/v1/demo/web-target", "192.0.2.77", "Mozilla/5.0 Citizen/122")

    return {
        "flash_crowd_verdict": flash_res["evaluation"]["verdict"],
        "flash_crowd_is_flash": flash_res["evaluation"]["is_flash_crowd"],
        "flash_crowd_banned": len(flash_res["actions_taken"]),
        "botnet_403_count": sum(1 for s in statuses if s == 403),
        "botnet_post_ban_http": bot_after,
        "benign_user_http": benign_after,
    }
