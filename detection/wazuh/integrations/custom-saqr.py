#!/usr/bin/env python3
"""SAQR Wazuh Integratord Real-Time Webhook Forwarder (custom-saqr.py).

Invoked automatically by wazuh-integratord whenever a level >= 12 alert fires:
    custom-saqr.py <alert_json_file> <api_key> <hook_url> [debug]

Security Design:
  - Uses ONLY Python 3.12 stdlib (zero external pip dependencies inside the
    Wazuh Manager container).
  - Signs every outbound HTTP POST with HMAC-SHA256 over:
        "{timestamp}.{nonce}.POST.{path}.".encode("utf-8") + raw_body_bytes
    preventing alert spoofing and replay attacks against SAQR Engine (:5000).
  - Falls back to the SAQR_WEBHOOK_SECRET environment variable if ossec.conf
    still holds the default placeholder, keeping secrets out of XML configs.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple

DEFAULT_HOOK_URL = "http://saqr-engine:5000/api/v1/webhooks/wazuh"
PLACEHOLDER_KEY = "REPLACE_WITH_SAQR_WEBHOOK_SECRET"
DEFAULT_LOG_PATH = Path("/var/ossec/logs/integrations.log")


def _log(message: str, log_path: Path = DEFAULT_LOG_PATH) -> None:
    """Append a concise UTC log line without ever exposing secrets."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"{ts} custom-saqr: {message}\n"
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        # Fallback cleanly when tested outside /var/ossec (e.g., local unit tests)
        sys.stderr.write(line)


def resolve_api_key(cli_api_key: str) -> str:
    """Resolve HMAC signing secret from CLI argument or SAQR_WEBHOOK_SECRET env."""
    candidate = (cli_api_key or "").strip()
    if candidate and candidate != PLACEHOLDER_KEY:
        return candidate
    return os.getenv("SAQR_WEBHOOK_SECRET", "").strip()


def sign_request(
    body: bytes,
    api_key: str,
    path: str,
    timestamp: Optional[str] = None,
    nonce: Optional[str] = None,
) -> Dict[str, str]:
    """Build anti-replay HMAC-SHA256 headers matching SAQR FastAPI verification.

    Signing string:
        f"{ts}.{nonce}.POST.{path}.".encode("utf-8") + body
    """
    if not api_key:
        raise ValueError("SAQR webhook HMAC secret is empty; set SAQR_WEBHOOK_SECRET or <api_key>.")

    ts = timestamp if timestamp is not None else str(int(time.time()))
    req_nonce = nonce if nonce is not None else secrets.token_hex(16)  # 32 hex chars
    prefix = f"{ts}.{req_nonce}.POST.{path}.".encode("utf-8")
    digest = hmac.new(api_key.encode("utf-8"), prefix + body, hashlib.sha256).hexdigest()

    return {
        "Content-Type": "application/json",
        "X-SAQR-Timestamp": ts,
        "X-SAQR-Nonce": req_nonce,
        "X-SAQR-Signature": digest,
    }


def forward_alert(
    alert_file: str | Path,
    api_key: str,
    hook_url: str = DEFAULT_HOOK_URL,
    timeout: float = 5.0,
) -> Tuple[int, str]:
    """Read raw Wazuh alert JSON bytes, sign them, and POST to SAQR Engine."""
    target_url = (hook_url or "").strip() or DEFAULT_HOOK_URL
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"Refusing invalid webhook URL: {target_url!r}")

    secret = resolve_api_key(api_key)
    raw_body = Path(alert_file).read_bytes()
    path = parsed.path or "/"
    headers = sign_request(body=raw_body, api_key=secret, path=path)

    req = urllib.request.Request(target_url, data=raw_body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        resp_body = resp.read().decode("utf-8", errors="replace")
        return resp.status, resp_body


def main(argv: list[str]) -> int:
    """Entrypoint invoked by wazuh-integratord."""
    if len(argv) < 2:
        _log("Usage: custom-saqr.py <alert_file> [api_key] [hook_url]")
        return 1

    alert_file = argv[1]
    cli_api_key = argv[2] if len(argv) >= 3 else ""
    hook_url = argv[3] if len(argv) >= 4 and argv[3].strip() else DEFAULT_HOOK_URL

    try:
        status, _ = forward_alert(alert_file, cli_api_key, hook_url)
        _log(f"Delivered alert {Path(alert_file).name} -> {hook_url} (HTTP {status})")
        return 0
    except urllib.error.HTTPError as exc:
        _log(f"HTTP error {exc.code} delivering alert to {hook_url}")
        return 1
    except Exception as exc:  # noqa: BLE001
        _log(f"Failed delivering alert to {hook_url}: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
