"""SAQR Layer 3 — Lean FastAPI Core Orchestrator (Port 5000).

Receives real-time HMAC-signed Wazuh alerts, enforces atomic idempotency, dispatches
Wazuh Active Response containment (`saqr-contain`), verifies SHA-256 forensic dumps,
and triggers post-containment Arabic AI reporting (Gemini API or Local Ollama) + Telegram.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.config import EngineConfig
from app.correlator import DDoSCorrelator, evaluate_phishing, parse_wazuh_alert
from app.database import SAQRDatabase
from app.models import ContainmentCallback, DDoSBatch, DDoSRequestItem, LoginRequest, PhishingAlert, RevokeRequest, utc_now_iso
from app.services.llm import LLMReportService
from app.services.redactor import sanitize_incident_for_llm
from app.services.soar import WazuhSOARClient
from app.services.telegram import TelegramService

_SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{3,64}$")


# ---------------------------------------------------------------------------
# Compact Security Helpers (HMAC Anti-Replay, HS256 JWT, Single-Use Tokens)
# ---------------------------------------------------------------------------

def sign_hmac_headers(secret: str, method: str, path: str, body: bytes) -> Dict[str, str]:
    ts = str(int(time.time()))
    nonce = secrets.token_hex(16)
    canonical = f"{ts}.{nonce}.{method.upper()}.{path}.".encode("utf-8") + body
    sig = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    return {"X-SAQR-Timestamp": ts, "X-SAQR-Nonce": nonce, "X-SAQR-Signature": sig}


class ReplayGuard:
    def __init__(self, skew_s: int = 30) -> None:
        self.skew_s = skew_s
        self._lock = threading.Lock()
        self._nonces: Dict[str, float] = {}

    def verify(self, secret: str, method: str, path: str, body: bytes, ts: Optional[str], nonce: Optional[str], sig: Optional[str]) -> Tuple[bool, str]:
        if not ts or not nonce or not sig:
            return False, "missing_hmac_headers"
        try:
            req_ts = int(ts)
        except ValueError:
            return False, "invalid_timestamp"
        now = time.time()
        if abs(now - req_ts) > self.skew_s:
            return False, "timestamp_drift"
        canonical = f"{ts}.{nonce}.{method.upper()}.{path}.".encode("utf-8") + body
        expected = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return False, "invalid_signature"
        with self._lock:
            for k in [k for k, exp in self._nonces.items() if exp <= now]:
                del self._nonces[k]
            if nonce in self._nonces:
                return False, "replayed_nonce"
            self._nonces[nonce] = now + 120.0
        return True, "ok"


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def issue_jwt(secret: str, sub: str, role: str, ttl_s: int = 3600) -> Tuple[str, str]:
    now = int(time.time())
    jti = secrets.token_hex(12)
    h = _b64e(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    p = _b64e(json.dumps({"sub": sub, "role": role, "jti": jti, "iat": now, "exp": now + ttl_s}, separators=(",", ":")).encode())
    sig = _b64e(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}", jti


def verify_jwt(secret: str, token: str, is_revoked_fn) -> Tuple[bool, Optional[dict], str]:
    try:
        h, p, s = token.split(".")
        expected = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64d(s)):
            return False, None, "bad_signature"
        payload = json.loads(_b64d(p))
    except Exception:
        return False, None, "malformed_jwt"
    if int(time.time()) >= int(payload.get("exp", 0)):
        return False, None, "expired"
    if is_revoked_fn(str(payload.get("jti", ""))):
        return False, None, "token_revoked"
    return True, payload, "ok"


def _delta_ms(start_iso: Optional[str], end_iso: Optional[str]) -> Optional[float]:
    if not start_iso or not end_iso:
        return None
    try:
        a = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
        b = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
        if a.tzinfo is None:
            a = a.replace(tzinfo=timezone.utc)
        if b.tzinfo is None:
            b = b.replace(tzinfo=timezone.utc)
        return round(max(0.0, (b - a).total_seconds() * 1000.0), 2)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# FastAPI Application Factory
# ---------------------------------------------------------------------------

def create_app(config: Optional[EngineConfig] = None) -> FastAPI:
    cfg = config or EngineConfig()
    cfg.evidence_dir.mkdir(parents=True, exist_ok=True)

    db = SAQRDatabase(database_url=cfg.database_url, sqlite_path=cfg.sqlite_path)
    soar = WazuhSOARClient(cfg)
    llm = LLMReportService(cfg)
    telegram = TelegramService(cfg, db)
    ddos = DDoSCorrelator()
    replay = ReplayGuard()

    # Single-use scoped evidence upload tokens: token -> (incident_id, agent_id, exp_ts, used)
    upload_lock = threading.Lock()
    upload_tokens: Dict[str, Dict[str, Any]] = {}

    def issue_upload_token(incident_id: str, agent_id: str) -> str:
        tok = secrets.token_urlsafe(32)
        with upload_lock:
            upload_tokens[tok] = {"incident_id": incident_id, "agent_id": agent_id, "exp": time.time() + 180, "used": False}
        return tok

    def consume_upload_token(tok: str, incident_id: str, agent_id: str, mark_used: bool = True) -> Tuple[bool, str]:
        with upload_lock:
            rec = upload_tokens.get(tok)
            if not rec:
                return False, "unknown_token"
            if rec["used"]:
                return False, "token_already_used"
            if time.time() > rec["exp"]:
                return False, "token_expired"
            if rec["incident_id"] != incident_id or rec["agent_id"] != agent_id:
                return False, "token_scope_mismatch"
            if mark_used:
                rec["used"] = True
            return True, "ok"

    def finalize_report_and_notify(incident_id: str) -> Dict[str, Any]:
        inc = db.get_incident(incident_id)
        if not inc:
            return {}
        sanitized = sanitize_incident_for_llm(inc)
        rep = llm.generate_arabic_report(sanitized)
        rep_id = db.save_report(
            incident_id=incident_id,
            provider=rep.provider,
            model_name=rep.model_name,
            language="ar",
            redacted_input=sanitized,
            report_markdown=rep.markdown,
            latency_ms=rep.latency_ms,
        )
        if rep.used_fallback:
            db.enqueue_outbox(incident_id, "llm_report", {"sanitized": sanitized}, error=rep.error)
        tg_ok, tg_job = telegram.send_alert(incident_id, sanitized)
        return {"report_id": rep_id, "provider": rep.provider, "used_fallback": rep.used_fallback, "telegram_sent": tg_ok, "telegram_job": tg_job}

    app = FastAPI(title="SAQR — Security Automated Quick Response Engine", version="1.0.0")
    app.state.cfg = cfg
    app.state.db = db
    app.state.soar = soar
    app.state.llm = llm

    async def require_hmac(request: Request) -> bytes:
        body = await request.body()
        ok, reason = replay.verify(
            cfg.webhook_secret,
            request.method,
            request.url.path,
            body,
            request.headers.get("X-SAQR-Timestamp"),
            request.headers.get("X-SAQR-Nonce"),
            request.headers.get("X-SAQR-Signature"),
        )
        if not ok:
            raise HTTPException(status_code=401, detail=f"HMAC rejected: {reason}")
        return body

    def require_role(allowed: List[str]):
        async def _dep(request: Request) -> dict:
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                raise HTTPException(status_code=401, detail="Missing Bearer JWT")
            ok, payload, reason = verify_jwt(cfg.jwt_secret, auth[7:].strip(), db.is_session_revoked)
            if not ok or not payload:
                raise HTTPException(status_code=401, detail=f"JWT rejected: {reason}")
            if allowed and payload.get("role") not in allowed:
                raise HTTPException(status_code=403, detail="Insufficient role")
            return payload
        return _dep

    # ---- Health & Stats ----
    @app.get("/health")
    async def health() -> Dict[str, Any]:
        return {"status": "ok", "db_backend": db.backend, "llm_provider": cfg.llm_provider, "wazuh_dry_run": cfg.wazuh_dry_run}

    @app.get("/api/v1/stats")
    async def get_stats() -> Dict[str, Any]:
        return db.stats()

    # ---- Layer 2 -> Layer 3: Real-Time Wazuh Webhook ----
    @app.post("/api/v1/webhooks/wazuh")
    async def wazuh_webhook(alert: Dict[str, Any], _body: bytes = Depends(require_hmac)) -> Dict[str, Any]:
        parsed = parse_wazuh_alert(alert)
        t2_utc = utc_now_iso()
        if not parsed["should_contain"]:
            return {"status": "logged_only", "rule_id": parsed["rule_id"], "risk_score": parsed["risk_score"]}

        mttd_ms = _delta_ms(parsed["t0_attack_utc"], parsed["t1_detected_utc"])
        incident_id, created = db.create_or_get_incident(
            {
                **parsed,
                "status": "CONTAINING",
                "t2_decided_utc": t2_utc,
                "mttd_ms": mttd_ms,
                "actions_taken": ["wazuh_active_response_dispatched"],
            }
        )
        if not created:
            return {"status": "deduplicated", "incident_id": incident_id}

        upload_token = issue_upload_token(incident_id, parsed["agent_id"])
        ar_res = soar.trigger_containment(
            agent_id=parsed["agent_id"],
            incident_id=incident_id,
            target_pid=parsed["target_pid"],
            parent_pid=parsed["parent_pid"],
            upload_token=upload_token,
        )
        db.write_audit("saqr-engine", "CONTAIN_DISPATCH", parsed["agent_id"], f"incident={incident_id} pid={parsed['target_pid']}")
        return {"status": "containing", "incident_id": incident_id, "upload_token": upload_token, "active_response": ar_res}

    # ---- Layer 4 -> Layer 3: Forensic Dump Upload (SHA-256 Re-Verified) ----
    @app.post("/api/v1/evidence/{incident_id}")
    async def upload_evidence(incident_id: str, request: Request) -> Dict[str, Any]:
        if not _SAFE_ID.match(incident_id):
            raise HTTPException(status_code=400, detail="Invalid incident_id")
        req_fname = request.headers.get("X-SAQR-Filename", "dump.dmp")
        if "/" in req_fname or "\\" in req_fname or ".." in req_fname:
            raise HTTPException(status_code=400, detail="Path traversal rejected")

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing upload Bearer token")
        tok = auth[7:].strip()
        agent_id = request.headers.get("X-SAQR-Agent-ID", "").strip()
        sha_agent = request.headers.get("X-SAQR-SHA256", "").strip().lower()
        if not agent_id or not sha_agent:
            raise HTTPException(status_code=400, detail="Missing X-SAQR-Agent-ID or X-SAQR-SHA256")

        ok, reason = consume_upload_token(tok, incident_id, agent_id, mark_used=True)
        if not ok:
            raise HTTPException(status_code=410 if reason == "token_already_used" else 403, detail=reason)

        raw = await request.body()
        sha_server = hashlib.sha256(raw).hexdigest().lower()
        if not hmac.compare_digest(sha_agent, sha_server):
            raise HTTPException(status_code=400, detail="EVIDENCE_INTEGRITY_MISMATCH")

        vault_name = f"{uuid.uuid4().hex}.dmp"
        dest = (cfg.evidence_dir / vault_name).resolve()
        if not dest.is_relative_to(cfg.evidence_dir.resolve()):
            raise HTTPException(status_code=400, detail="Vault path escape blocked")
        dest.write_bytes(raw)

        art = db.add_artifact(incident_id, agent_id, vault_name, len(raw), sha_agent, sha_server, True)
        db.update_incident(incident_id, t3_dumped_utc=utc_now_iso())
        return {"stored": True, "artifact": art}

    # ---- Layer 4 -> Layer 3: Containment Complete -> Trigger Post-Containment Arabic AI Report ----
    @app.post("/api/v1/incidents/{incident_id}/contained")
    async def mark_contained(incident_id: str, cb: ContainmentCallback, request: Request) -> Dict[str, Any]:
        # Accept either HMAC auth or valid Bearer token (even if already used for upload in same incident)
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            tok = auth[7:].strip()
            with upload_lock:
                rec = upload_tokens.get(tok)
                if not rec or rec["incident_id"] != incident_id or rec["agent_id"] != cb.agent_id:
                    raise HTTPException(status_code=403, detail="Invalid callback token")
        else:
            await require_hmac(request)

        inc = db.get_incident(incident_id)
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found")

        t4 = cb.t4_utc or utc_now_iso()
        mttc_ms = _delta_ms(inc.get("t0_attack_utc") or inc.get("t1_detected_utc"), t4)
        db.update_incident(
            incident_id,
            status="CONTAINED",
            quarantined=1 if cb.quarantined else 0,
            t3_dumped_utc=cb.t3_utc or inc.get("t3_dumped_utc"),
            t4_contained_utc=t4,
            mttc_ms=mttc_ms,
            actions_json=cb.actions_taken or inc.get("actions_taken", []),
        )
        rep = finalize_report_and_notify(incident_id)
        db.update_incident(incident_id, status="REPORT_PENDING" if rep.get("used_fallback") else "COMPLETED")
        return {"incident_id": incident_id, "mttc_ms": mttc_ms, "report": rep}

    # ---- Incident Queries & 1-Click Un-Quarantine Rollback ----
    @app.get("/api/v1/incidents")
    async def list_incidents(limit: int = 50) -> List[Dict[str, Any]]:
        return db.list_incidents(limit=min(limit, 200))

    @app.get("/api/v1/incidents/{incident_id}")
    async def get_incident(incident_id: str) -> Dict[str, Any]:
        inc = db.get_incident(incident_id)
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found")
        return inc

    @app.post("/api/v1/incidents/{incident_id}/unquarantine")
    async def unquarantine(incident_id: str, claims: dict = Depends(require_role(["analyst", "admin"]))) -> Dict[str, Any]:
        inc = db.get_incident(incident_id)
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found")
        ar = soar.trigger_unquarantine(inc["agent_id"], incident_id)
        db.update_incident(incident_id, quarantined=0, status="UNQUARANTINED")
        db.write_audit(str(claims["sub"]), "UNQUARANTINE", inc["agent_id"], f"incident={incident_id}")
        return {"unquarantined": True, "incident_id": incident_id, "active_response": ar}

    # ---- IAM & Scenario 2 (Targeted Phishing -> DNS Sinkhole + Live JWT Revocation) ----
    @app.post("/api/v1/iam/login")
    async def iam_login(req: LoginRequest) -> Dict[str, Any]:
        accounts = {
            "analyst": (cfg.analyst_password, "analyst"),
            "admin": (cfg.analyst_password, "admin"),
            "viewer": ("SaqrViewer!2026", "viewer"),
            "employee": ("Employee!2026", "employee"),
        }
        entry = accounts.get(req.username.strip())
        if not entry or not hmac.compare_digest(entry[0], req.password):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        tok, jti = issue_jwt(cfg.jwt_secret, req.username.strip(), entry[1])
        return {"access_token": tok, "token_type": "bearer", "role": entry[1], "jti": jti}

    @app.get("/api/v1/iam/me")
    async def iam_me(claims: dict = Depends(require_role(["analyst", "admin", "viewer", "employee"]))) -> dict:
        return {"active": True, **claims}

    @app.post("/api/v1/iam/revoke")
    async def iam_revoke(req: RevokeRequest, claims: dict = Depends(require_role(["analyst", "admin"]))) -> dict:
        db.revoke_session(req.jti, req.username, req.reason)
        db.write_audit(str(claims["sub"]), "REVOKE_SESSION", req.jti, req.reason)
        return {"revoked": True, "jti": req.jti}

    @app.post("/api/v1/scenarios/phishing")
    async def scenario_phishing(ev: PhishingAlert, _body: bytes = Depends(require_hmac)) -> Dict[str, Any]:
        t1 = utc_now_iso()
        res = evaluate_phishing(ev, cfg.protected_domains)
        t2 = utc_now_iso()
        actions: List[str] = []
        inc_id: Optional[str] = None

        if res["should_contain"]:
            db.block_domain(ev.domain, None, f"Phishing spoof of {res['matched_brand']} (score={res['score']})")
            actions.append(f"dns_block:{ev.domain.lower()}")
            if ev.session_jti:
                db.revoke_session(ev.session_jti, ev.username, f"Phishing credential compromise ({ev.domain})")
                actions.append(f"session_revoked:{ev.session_jti[:10]}")
            t4 = utc_now_iso()
            inc_id, _ = db.create_or_get_incident(
                {
                    "agent_id": ev.agent_id,
                    "hostname": ev.hostname,
                    "scenario": "phishing",
                    "actor_key": f"phish:{ev.domain.lower()}:{ev.username}",
                    "rule_id": "100205",
                    "command_line": f"url={ev.url} sender={ev.sender_email}",
                    "risk_score": res["score"],
                    "status": "CONTAINED",
                    "mitre_ids": res["mitre_ids"],
                    "signals": res["signals"],
                    "actions_taken": actions,
                    "quarantined": False,
                    "t0_attack_utc": ev.t0_utc,
                    "t1_detected_utc": t1,
                    "t2_decided_utc": t2,
                    "t4_contained_utc": t4,
                    "mttd_ms": _delta_ms(ev.t0_utc, t1),
                    "mttc_ms": _delta_ms(t1, t4),
                }
            )
            db.block_domain(ev.domain, inc_id, f"Phishing spoof of {res['matched_brand']}")
            finalize_report_and_notify(inc_id)
            db.update_incident(inc_id, status="COMPLETED")
        return {"incident_id": inc_id, "evaluation": res, "actions_taken": actions}

    # ---- Scenario 3 (DDoS vs. Flash Crowd + Protected Test Web Server) ----
    @app.post("/api/v1/scenarios/ddos")
    async def scenario_ddos(batch: DDoSBatch, _body: bytes = Depends(require_hmac)) -> Dict[str, Any]:
        t1 = utc_now_iso()
        res = ddos.ingest(batch.events)
        actions: List[str] = []
        inc_id: Optional[str] = None
        if res["verdict"] == "CRITICAL_CONTAIN":
            for ip in res["offending_ips"]:
                db.block_ip(ip, None, f"DDoS flood (score={res['score']})")
                actions.append(f"ip_ban:{ip}")
            t4 = utc_now_iso()
            inc_id, created = db.create_or_get_incident(
                {
                    "agent_id": "gw-01",
                    "hostname": "lab-web-server",
                    "scenario": "ddos",
                    "actor_key": f"ddos:{','.join(res['offending_ips'][:3])}",
                    "rule_id": "100206",
                    "risk_score": res["score"],
                    "status": "CONTAINED",
                    "mitre_ids": res["mitre_ids"],
                    "signals": res["signals"],
                    "actions_taken": actions,
                    "quarantined": False,
                    "t1_detected_utc": t1,
                    "t2_decided_utc": t1,
                    "t4_contained_utc": t4,
                    "mttd_ms": 0.0,
                    "mttc_ms": _delta_ms(t1, t4),
                }
            )
            if created:
                finalize_report_and_notify(inc_id)
                db.update_incident(inc_id, status="COMPLETED")
        return {"incident_id": inc_id, "evaluation": res, "actions_taken": actions}

    @app.get("/api/v1/demo/web-target")
    async def demo_web_target(request: Request) -> JSONResponse:
        ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or (request.client.host if request.client else "127.0.0.1")
        if db.is_ip_blocked(ip):
            return JSONResponse(status_code=403, content={"error": "blocked_by_saqr_ddos_shield", "ip": ip})
        res = ddos.ingest([DDoSRequestItem(src_ip=ip, uri=str(request.url.path), user_agent=request.headers.get("User-Agent", ""))])
        if res["verdict"] == "CRITICAL_CONTAIN":
            for bad_ip in res["offending_ips"]:
                db.block_ip(bad_ip, None, f"Live DDoS flood (score={res['score']})")
            if db.is_ip_blocked(ip):
                return JSONResponse(status_code=403, content={"error": "blocked_by_saqr_ddos_shield", "ip": ip})
        return JSONResponse(status_code=200, content={"status": "healthy", "service": "SAQR Lab Web Target", "client_ip": ip})

    @app.get("/api/v1/controls/blocked-domains")
    async def blocked_domains() -> List[Dict[str, Any]]:
        return db.list_blocked_domains()

    @app.get("/api/v1/controls/blocked-ips")
    async def blocked_ips() -> List[Dict[str, Any]]:
        return db.list_blocked_ips()

    @app.get("/api/v1/outbox")
    async def get_outbox() -> List[Dict[str, Any]]:
        return db.list_outbox()

    @app.get("/api/v1/audit")
    async def get_audit() -> List[Dict[str, Any]]:
        return db.list_audit()

    return app


app = create_app()
