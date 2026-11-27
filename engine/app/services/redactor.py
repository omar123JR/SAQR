"""Mandatory pre-flight PII, secret, and prompt-injection redactor before any external LLM call."""

from __future__ import annotations

import hashlib
import html
import re
from typing import Any, Dict, List, Optional, Tuple

from app.models import resolve_mitre

_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"\b(?:AIza[0-9A-Za-z_-]{20,}|sk-[0-9A-Za-z_-]{16,}|ghp_[0-9A-Za-z]{20,})\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"(?i)(--?(?:password|passwd|secret|token|api[-_]?key)\s*(?:=|\s)\s*)([^\s\"']+)"), r"\1[REDACTED_SECRET]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
    (re.compile(r"(?i)([A-Z]:\\Users\\)([^\\/\s\"']+)"), r"\1<REDACTED_USER>"),
    (re.compile(r"(/home/)([^/\s\"']+)"), r"\1<REDACTED_USER>"),
    (re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), "[REDACTED_IP]"),
    (re.compile(r"(?i)</?UNTRUSTED_TELEMETRY>|ignore\s+(?:all\s+)?previous\s+instructions?"), "[NEUTRALIZED]"),
]


def redact_text(value: Optional[str]) -> Tuple[Optional[str], int]:
    if value is None:
        return None, 0
    text, total = value, 0
    for pattern, repl in _PATTERNS:
        text, n = pattern.subn(repl, text)
        total += n
    if "<script" in text.lower():
        text = html.escape(text)
        total += 1
    return text, total


def sanitize_incident_for_llm(inc: Dict[str, Any]) -> Dict[str, Any]:
    """Produce a strictly allowlisted, PII-redacted incident summary for Gemini or Ollama."""
    redactions = 0
    proc_img, n1 = redact_text(inc.get("process_image"))
    cmdline, n2 = redact_text(inc.get("command_line"))
    redactions += n1 + n2

    clean_signals: List[Dict[str, Any]] = []
    for s in inc.get("signals") or []:
        ev, n = redact_text(str(s.get("evidence", "")))
        redactions += n
        clean_signals.append({**s, "evidence": ev or ""})

    clean_actions: List[str] = []
    for a in inc.get("actions_taken") or []:
        ca, n = redact_text(str(a))
        redactions += n
        if ca:
            clean_actions.append(ca)

    host_hash = hashlib.sha256(str(inc.get("hostname", "win10-vm")).encode("utf-8")).hexdigest()[:8].upper()
    mitre_ids = list(inc.get("mitre_ids") or [])

    return {
        "incident_id": inc["incident_id"],
        "scenario": inc["scenario"],
        "host_alias": f"HOST-{host_hash}",
        "status": inc["status"],
        "risk_score": inc["risk_score"],
        "rule_id": inc["rule_id"],
        "mitre_ids": mitre_ids,
        "mitre_details": resolve_mitre(mitre_ids),
        "t0_attack_utc": inc.get("t0_attack_utc"),
        "t1_detected_utc": inc.get("t1_detected_utc"),
        "t2_decided_utc": inc.get("t2_decided_utc"),
        "t3_dumped_utc": inc.get("t3_dumped_utc"),
        "t4_contained_utc": inc.get("t4_contained_utc"),
        "mttd_ms": inc.get("mttd_ms"),
        "mttc_ms": inc.get("mttc_ms"),
        "process_image": proc_img,
        "command_line": cmdline,
        "signals": clean_signals,
        "actions_taken": clean_actions,
        "affected_files": inc.get("affected_files", 0),
        "quarantined": inc.get("quarantined", False),
        "evidence_sha256": inc.get("evidence_sha256"),
        "evidence_integrity_ok": inc.get("evidence_integrity_ok"),
        "redactions_applied": redactions,
    }
