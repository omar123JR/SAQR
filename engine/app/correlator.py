"""Layer 3 Deterministic Correlator — Handles ALL 3 Proposal Scenarios cleanly and transparently.

1. Ransomware (Sem 1): Parses Wazuh rules 100201/100202/100203, resolves parent PID when triggered
   by ephemeral shadow-delete child (`vssadmin.exe`), extracts deterministic MITRE IDs, and returns
   a containment verdict with zero LLM involvement.
2. Targeted Phishing (Sem 2): Detects IDN/punycode Cyrillic/Greek homoglyphs, typosquatting,
   brand-in-subdomain spoofing, and SPF/DKIM/DMARC + credential harvest -> DNS block + JWT revoke.
3. DDoS Flooding (Sem 2): Sliding-window per-IP RPS + source-IP entropy + conditional per-burst-IP
   URI/UA entropy -> bans botnet IPs while leaving legitimate high-diversity flash crowds untouched.
"""

from __future__ import annotations

import math
import threading
import unicodedata
from collections import Counter, deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple

from app.models import DDoSRequestItem, PhishingAlert

_EPHEMERAL_SHADOW_BINS = ("vssadmin.exe", "wmic.exe", "wbadmin.exe", "bcdedit.exe")

_CONFUSABLES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0455": "s", "\u03b1": "a",
    "\u03bf": "o", "\u03b5": "e", "\u03c1": "p", "0": "o", "1": "l", "3": "e", "5": "s",
}


def _to_int(val: Any) -> Optional[int]:
    try:
        return int(val) if val is not None else None
    except (TypeError, ValueError):
        return None


def _skeleton(domain: str) -> str:
    raw = domain.strip().lower().rstrip(".")
    labels = []
    for lbl in raw.split("."):
        if lbl.startswith("xn--"):
            try:
                lbl = lbl.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        labels.append(lbl)
    decoded = unicodedata.normalize("NFKC", ".".join(labels))
    mapped = "".join(_CONFUSABLES.get(ch, ch) for ch in decoded)
    return mapped.replace("rn", "m").replace("vv", "w")


def _edit_dist(a: str, b: str) -> int:
    la, lb = len(a), len(b)
    dp = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        dp[i][0] = i
    for j in range(lb + 1):
        dp[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)
    return dp[la][lb]


def parse_wazuh_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Extract normalized fields, target root PID, and deterministic MITRE IDs from a Wazuh JSON alert."""
    rule = alert.get("rule") or {}
    rule_id = str(rule.get("id") or "0")
    rule_level = int(rule.get("level") or 0)
    mitre_ids = list((rule.get("mitre") or {}).get("id") or [])

    agent = alert.get("agent") or {}
    agent_id = str(agent.get("id") or "001")
    hostname = str(agent.get("name") or "win10-vm")

    win = (alert.get("data") or {}).get("win") or {}
    ev = win.get("eventdata") or {}
    sys_node = win.get("system") or {}
    syscheck = alert.get("syscheck") or {}

    pid = (
        _to_int(ev.get("processId"))
        or _to_int(((syscheck.get("audit") or {}).get("process") or {}).get("id"))
        or _to_int((sys_node.get("execution") or {}).get("processID"))
    )
    parent_pid = _to_int(ev.get("parentProcessId"))
    image = str(ev.get("image") or ((syscheck.get("audit") or {}).get("process") or {}).get("name") or "")
    cmdline = str(ev.get("commandLine") or ev.get("scriptBlockText") or "")
    t1_utc = str(alert.get("timestamp") or datetime.now(timezone.utc).isoformat())

    # Wrong-PID Fix: if triggered by ephemeral vssadmin.exe/wmic.exe, contain the PARENT encryptor!
    effective_pid = pid
    if image.lower().endswith(_EPHEMERAL_SHADOW_BINS) and parent_pid and parent_pid > 4:
        effective_pid = parent_pid

    scenario = "ransomware"
    if rule_id == "100205":
        scenario = "phishing"
    elif rule_id == "100206":
        scenario = "ddos"

    should_contain = rule_level >= 12 or rule_id in {"100201", "100202", "100203", "100205", "100206", "100207"}
    risk_score = min(100, max(rule_level * 7, 85 if should_contain else 35))
    actor_key = f"pid:{effective_pid}" if effective_pid else f"rule:{rule_id}"

    if not mitre_ids:
        if rule_id in {"100201", "100203"}:
            mitre_ids = ["T1486"]
        elif rule_id in {"100202", "100207"}:
            mitre_ids = ["T1490"]
        elif rule_id == "100204":
            mitre_ids = ["T1021.002"]
        elif rule_id == "100205":
            mitre_ids = ["T1566.002"]
        elif rule_id == "100206":
            mitre_ids = ["T1498", "T1499"]

    return {
        "agent_id": agent_id,
        "hostname": hostname,
        "scenario": scenario,
        "rule_id": rule_id,
        "rule_level": rule_level,
        "rule_description": str(rule.get("description") or "Wazuh security alert"),
        "should_contain": should_contain,
        "risk_score": risk_score,
        "actor_key": actor_key,
        "target_pid": effective_pid,
        "parent_pid": parent_pid,
        "process_image": image or None,
        "command_line": cmdline or None,
        "mitre_ids": mitre_ids,
        "t1_detected_utc": t1_utc,
        "t0_attack_utc": (alert.get("data") or {}).get("saqr_t0_utc"),
        "signals": [
            {
                "signal_id": f"WAZUH-{rule_id}",
                "name": str(rule.get("description") or f"Wazuh Rule {rule_id}"),
                "mitre_id": mitre_ids[0] if mitre_ids else "T1486",
                "weight": risk_score,
                "evidence": f"Rule {rule_id} (level {rule_level}) on {hostname} PID={effective_pid} image={image}",
            }
        ],
    }


def evaluate_phishing(event: PhishingAlert, protected_domains: List[str]) -> Dict[str, Any]:
    """Deterministic Scenario 2 scorer: IDN/homoglyph + typosquatting + SPF/DKIM/DMARC + credential post."""
    raw_dom = event.domain.strip().lower().rstrip(".")
    is_idn = "xn--" in raw_dom or any(ord(c) > 127 for c in raw_dom)
    skel = _skeleton(raw_dom)

    signals: List[Dict[str, Any]] = []
    mitre: List[str] = []
    matched_brand: Optional[str] = None
    score = 0

    exact_legit = any(raw_dom == p or raw_dom.endswith("." + p) for p in protected_domains) and not is_idn
    if not exact_legit:
        for brand in protected_domains:
            b_skel = _skeleton(brand)
            b_sld = brand.split(".")[0]
            if skel == b_skel:
                matched_brand = brand
                w = 60 if is_idn else 55
                score += w
                signals.append({"signal_id": "P1", "name": "Homoglyph / IDN Brand Spoof", "mitre_id": "T1566.002", "weight": w, "evidence": f"{raw_dom} mimics {brand}"})
                mitre.append("T1566.002")
                break
            if b_sld in raw_dom and not raw_dom.endswith(brand):
                matched_brand = brand
                score += 45
                signals.append({"signal_id": "P2", "name": "Brand-in-Subdomain Spoof", "mitre_id": "T1566.002", "weight": 45, "evidence": f"{raw_dom} embeds {b_sld}"})
                mitre.append("T1566.002")
                break
            if _edit_dist(skel.split(".")[0], b_skel.split(".")[0]) <= 2:
                matched_brand = brand
                score += 45
                signals.append({"signal_id": "P3", "name": "Typosquatting Look-Alike Domain", "mitre_id": "T1566.002", "weight": 45, "evidence": f"{raw_dom} near {brand}"})
                mitre.append("T1566.002")
                break

    failed_auth = [k for k, ok in [("SPF", event.spf_pass), ("DKIM", event.dkim_pass), ("DMARC", event.dmarc_pass)] if not ok]
    if failed_auth:
        w = min(25, 10 * len(failed_auth))
        score += w
        signals.append({"signal_id": "P4", "name": "Email Auth Failure", "mitre_id": "T1566.002", "weight": w, "evidence": f"Failed: {', '.join(failed_auth)}"})
        if "T1566.002" not in mitre:
            mitre.append("T1566.002")

    if event.credential_submitted:
        score += 35
        signals.append({"signal_id": "P5", "name": "Credential Submitted to Phishing Page", "mitre_id": "T1078", "weight": 35, "evidence": f"User submitted credentials on {raw_dom}"})
        mitre.append("T1078")

    score = min(100, score)
    return {
        "score": score,
        "should_contain": score >= 70,
        "matched_brand": matched_brand,
        "mitre_ids": list(dict.fromkeys(mitre)),
        "signals": signals,
    }


def _entropy(counts: Counter[str], total: int) -> float:
    if total <= 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


class DDoSCorrelator:
    """Deterministic Scenario 3 DDoS vs. Flash-Crowd classifier (strictly honors Golden Rule!)."""

    def __init__(self, window_s: float = 10.0, per_ip_rps_limit: float = 2.5) -> None:
        self.window_s = window_s
        self.per_ip_rps_limit = per_ip_rps_limit
        self._lock = threading.Lock()
        self._window: Deque[Tuple[float, DDoSRequestItem]] = deque()

    def ingest(self, items: List[DDoSRequestItem], now_ts: Optional[float] = None) -> Dict[str, Any]:
        ts = now_ts if now_ts is not None else datetime.now(timezone.utc).timestamp()
        with self._lock:
            for item in items:
                self._window.append((ts, item))
            cutoff = ts - self.window_s
            while self._window and self._window[0][0] < cutoff:
                self._window.popleft()
            events = [e for _, e in self._window]

        total = len(events)
        if total < 40:
            return {"score": 0, "verdict": "BENIGN", "is_flash_crowd": False, "offending_ips": [], "mitre_ids": [], "signals": []}

        ip_counts = Counter(e.src_ip for e in events)
        uri_counts = Counter(e.uri for e in events)
        ua_counts = Counter(e.user_agent or "<empty>" for e in events)

        h_ip = _entropy(ip_counts, total)
        h_ip_norm = h_ip / math.log2(total)
        h_uri = _entropy(uri_counts, total)
        h_ua = _entropy(ua_counts, total)
        peak_ip, peak_cnt = ip_counts.most_common(1)[0]
        peak_rps = peak_cnt / self.window_s

        # Legitimate high-diversity Flash Crowd -> BENIGN (zero false bans!)
        if h_ip >= 4.5 and h_ip_norm >= 0.72 and peak_rps < self.per_ip_rps_limit and h_ua >= 1.4:
            return {
                "score": 10,
                "verdict": "BENIGN",
                "is_flash_crowd": True,
                "offending_ips": [],
                "mitre_ids": [],
                "signals": [{"signal_id": "D0", "name": "Benign Flash Crowd", "mitre_id": "T1498", "weight": 10, "evidence": f"High diversity H(ip)={h_ip:.2f}, peak_rps={peak_rps:.1f}"}],
            }

        burst_ips = [ip for ip, c in ip_counts.items() if (c / self.window_s) >= self.per_ip_rps_limit]
        score = 0
        signals: List[Dict[str, Any]] = []
        mitre: List[str] = []

        if burst_ips:
            w = 35 if peak_rps >= self.per_ip_rps_limit * 2 else 25
            score += w
            signals.append({"signal_id": "D1", "name": "Per-IP Flood Burst", "mitre_id": "T1498", "weight": w, "evidence": f"Peak {peak_ip} at {peak_rps:.1f} RPS ({len(burst_ips)} burst IPs)"})
            mitre.append("T1498")

        if h_ip <= 2.5 or h_ip_norm <= 0.45:
            score += 30
            signals.append({"signal_id": "D2", "name": "Source-IP Entropy Collapse", "mitre_id": "T1498", "weight": 30, "evidence": f"H(ip)={h_ip:.2f} norm={h_ip_norm:.2f}"})
            if "T1498" not in mitre:
                mitre.append("T1498")
        elif h_ip_norm <= 0.68:
            score += 18
            signals.append({"signal_id": "D2", "name": "Source-IP Concentration", "mitre_id": "T1498", "weight": 18, "evidence": f"H(ip)={h_ip:.2f} norm={h_ip_norm:.2f}"})

        # Conditional per-burst-IP URI/UA entropy (catches botnets hiding inside mixed/flash traffic!)
        if burst_ips:
            b_events = [e for e in events if e.src_ip in burst_ips]
            b_share = len(b_events) / total
            b_h_uri = _entropy(Counter(e.uri for e in b_events), len(b_events))
            b_h_ua = _entropy(Counter(e.user_agent or "<empty>" for e in b_events), len(b_events))
            if (h_uri <= 0.8 and h_ua <= 1.0) or (b_share >= 0.35 and b_h_uri <= 0.6 and b_h_ua <= 0.6):
                score += 35
                signals.append({"signal_id": "D3", "name": "Robotic URI/UA Flood Signature", "mitre_id": "T1499", "weight": 35, "evidence": f"Burst share={b_share:.0%}, H(uri|burst)={b_h_uri:.2f}, H(ua|burst)={b_h_ua:.2f}"})
                mitre.append("T1499")

        score = min(100, score)
        verdict = "CRITICAL_CONTAIN" if score >= 70 else ("SUSPICIOUS" if score >= 40 else "BENIGN")
        return {
            "score": score,
            "verdict": verdict,
            "is_flash_crowd": False,
            "offending_ips": sorted(burst_ips) if verdict == "CRITICAL_CONTAIN" else [],
            "mitre_ids": list(dict.fromkeys(mitre)),
            "signals": signals,
        }
