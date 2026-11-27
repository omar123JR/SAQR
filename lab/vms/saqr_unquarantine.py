#!/usr/bin/env python3
"""SAQR Windows Active Response — 1-Click Quarantine Rollback (saqr_unquarantine.py).

Dispatched by Wazuh Manager v4.14.11 (`saqr-unquarantine`) when a SOC analyst
clicks "Lift Quarantine" in the Streamlit RTL dashboard after verification.

Removes ONLY firewall rules in `-Group "SAQR-Quarantine"` and restores the
Windows Firewall default outbound policy to `Allow`, leaving default inbound
protection (`Block`) untouched.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

FIREWALL_GROUP = "SAQR-Quarantine"
DEFAULT_AR_LOG = (
    Path(r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log")
    if sys.platform == "win32"
    else Path("/tmp/saqr_rework/active-responses.log")
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_unquarantine_command() -> List[str]:
    """Build injection-safe PowerShell command to remove SAQR-Quarantine rules."""
    ps_script = (
        f"Remove-NetFirewallRule -Group '{FIREWALL_GROUP}' -ErrorAction SilentlyContinue; "
        f"Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow"
    )
    return [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        ps_script,
    ]


def lift_quarantine(dry_run: bool = False) -> Tuple[bool, str]:
    """Remove SAQR-Quarantine firewall rules and restore outbound connectivity."""
    argv = build_unquarantine_command()
    if dry_run or sys.platform != "win32":
        return True, "unquarantine_dry_run_ok"
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=15, check=False)
    if proc.returncode == 0:
        return True, "unquarantine_ok"
    return False, f"unquarantine_failed:rc={proc.returncode}"


def append_ar_log(record: Dict[str, Any], log_path: Path = DEFAULT_AR_LOG) -> None:
    line = json.dumps(record, ensure_ascii=False) + "\n"
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        sys.stderr.write(line)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SAQR Windows Firewall Quarantine Rollback")
    parser.add_argument("--incident-id", default="", help="SAQR incident ID")
    parser.add_argument("--agent-id", default="001", help="Wazuh agent ID")
    parser.add_argument("--log-file", default=os.getenv("SAQR_AR_LOG", str(DEFAULT_AR_LOG)))
    parser.add_argument("--dry-run", action="store_true", help="Simulate rollback without modifying firewall")
    return parser


def parse_invocation(argv: Sequence[str], stdin_line: Optional[str] = None) -> argparse.Namespace:
    parser = build_arg_parser()
    if argv:
        return parser.parse_args(list(argv))

    raw = stdin_line
    if raw is None and not sys.stdin.isatty():
        raw = sys.stdin.readline()

    if not raw or not raw.strip():
        return parser.parse_args([])

    msg = json.loads(raw)
    params = msg.get("parameters", {}) if isinstance(msg, dict) else {}
    extra_args = params.get("extra_args", [])
    if not isinstance(extra_args, list):
        extra_args = []
    ns, _ = parser.parse_known_args([str(x) for x in extra_args])
    return ns


def run_unquarantine(ns: argparse.Namespace) -> Dict[str, Any]:
    ok, note = lift_quarantine(dry_run=ns.dry_run)
    record = {
        "timestamp_utc": utc_now_iso(),
        "command": "saqr-unquarantine",
        "incident_id": ns.incident_id,
        "agent_id": ns.agent_id,
        "restored": ok,
        "detail": note,
    }
    append_ar_log(record, log_path=Path(ns.log_file))
    return record


def main(argv: Sequence[str] | None = None) -> int:
    ns = parse_invocation(list(sys.argv[1:] if argv is None else argv))
    run_unquarantine(ns)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
