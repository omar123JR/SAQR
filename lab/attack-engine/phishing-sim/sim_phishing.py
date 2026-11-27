"""Scenario 2 Lab Verification — Targeted Phishing (GoPhish-compatible payload -> DNS Block + JWT Revocation)."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict


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


def _http_json(url: str, method: str = "GET", body: bytes | None = None, headers: dict | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def run_phishing_test(engine_url: str, webhook_secret: str) -> Dict[str, Any]:
    base = engine_url.rstrip("/")

    # 1. Employee logs in and gets an active JWT session
    login_raw = json.dumps({"username": "employee", "password": "Employee!2026"}).encode()
    st_login, login_data = _http_json(f"{base}/api/v1/iam/login", "POST", login_raw, {"Content-Type": "application/json"})
    assert st_login == 200, f"Login failed: {login_data}"
    jwt_tok = login_data["access_token"]
    jti = login_data["jti"]

    st_pre, _ = _http_json(f"{base}/api/v1/iam/me", "GET", headers={"Authorization": f"Bearer {jwt_tok}"})

    # 2. Look-alike Cyrillic homoglyph domain ("sаqr-bank.ly" -> punycode xn--sqr-bank-16g.ly)
    spoof_domain = "s\u0430qr-bank.ly".encode("idna").decode("ascii")
    payload = {
        "agent_id": "001",
        "hostname": "win10-vm",
        "username": "employee",
        "sender_email": f"alerts@{spoof_domain}",
        "domain": spoof_domain,
        "url": f"https://{spoof_domain}/login",
        "subject": "Urgent: Verify your SAQR Bank session",
        "spf_pass": False,
        "dkim_pass": False,
        "dmarc_pass": False,
        "credential_submitted": True,
        "session_jti": jti,
    }
    raw = json.dumps(payload, separators=(",", ":")).encode()
    hdrs = _sign(webhook_secret, "POST", "/api/v1/scenarios/phishing", raw)
    st_eval, eval_res = _http_json(f"{base}/api/v1/scenarios/phishing", "POST", raw, hdrs)

    # 3. Verify JWT session is IMMEDIATELY revoked (HTTP 401) and domain is sinkholed
    st_post, post_data = _http_json(f"{base}/api/v1/iam/me", "GET", headers={"Authorization": f"Bearer {jwt_tok}"})
    _, domains = _http_json(f"{base}/api/v1/controls/blocked-domains", "GET")

    return {
        "spoof_domain": spoof_domain,
        "pre_session_http": st_pre,
        "eval_http": st_eval,
        "incident_id": eval_res.get("incident_id"),
        "score": eval_res.get("evaluation", {}).get("score"),
        "mitre_ids": eval_res.get("evaluation", {}).get("mitre_ids"),
        "post_session_http": st_post,
        "post_detail": post_data.get("detail"),
        "domain_blocked": any(d["domain"] == spoof_domain for d in domains),
    }
