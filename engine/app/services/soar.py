"""Layer 4 SOAR Dispatcher — Calls Wazuh Manager v4.14.11 REST API (`PUT /active-response`).

Replaces ad-hoc WinRM/SSH with Wazuh's native encrypted port-1514 Active Response channel.
Supports `WAZUH_DRY_RUN=true` for clean automated testing without requiring VMware/Wazuh live.
"""

from __future__ import annotations

import base64
import json
import ssl
import urllib.request
from typing import Any, Dict, List, Optional

from app.config import EngineConfig


class WazuhSOARClient:
    """Dispatches stateless `saqr-contain` and `saqr-unquarantine` Active Responses to Windows agents."""

    def __init__(self, config: EngineConfig) -> None:
        self.config = config
        self.dispatched_history: List[Dict[str, Any]] = []

    def _ssl_context(self) -> Optional[ssl.SSLContext]:
        if self.config.wazuh_verify_tls:
            return None
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _authenticate(self) -> str:
        url = f"{self.config.wazuh_api_url.rstrip('/')}/security/user/authenticate?raw=true"
        creds = f"{self.config.wazuh_api_user}:{self.config.wazuh_api_password}".encode("utf-8")
        headers = {"Authorization": f"Basic {base64.b64encode(creds).decode('ascii')}"}
        req = urllib.request.Request(url, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5, context=self._ssl_context()) as resp:
            return resp.read().decode("utf-8").strip()

    def trigger_containment(
        self,
        agent_id: str,
        incident_id: str,
        target_pid: Optional[int],
        parent_pid: Optional[int],
        upload_token: str,
    ) -> Dict[str, Any]:
        """Dispatch stateless `saqr-contain` over Wazuh Active Response API."""
        payload = {
            "command": "saqr-contain",
            "custom": True,
            "arguments": [
                "--incident-id", incident_id,
                "--agent-id", agent_id,
                "--target-pid", str(target_pid or 0),
                "--parent-pid", str(parent_pid or 0),
                "--upload-token", upload_token,
            ],
        }
        return self._dispatch(agent_id, payload)

    def trigger_unquarantine(self, agent_id: str, incident_id: str) -> Dict[str, Any]:
        """Dispatch stateless `saqr-unquarantine` to lift SAQR-Quarantine Windows Firewall rules."""
        payload = {
            "command": "saqr-unquarantine",
            "custom": True,
            "arguments": ["--incident-id", incident_id, "--agent-id", agent_id],
        }
        return self._dispatch(agent_id, payload)

    def _dispatch(self, agent_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        record = {"agent_id": agent_id, "payload": payload, "dry_run": self.config.wazuh_dry_run}
        if self.config.wazuh_dry_run:
            record["status"] = "dry_run_dispatched"
            self.dispatched_history.append(record)
            return record

        token = self._authenticate()
        url = f"{self.config.wazuh_api_url.rstrip('/')}/active-response?agents_list={agent_id}"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            method="PUT",
        )
        with urllib.request.urlopen(req, timeout=5, context=self._ssl_context()) as resp:
            result = json.loads(resp.read().decode("utf-8"))
        record["status"] = "dispatched"
        record["wazuh_response"] = result
        self.dispatched_history.append(record)
        return record
