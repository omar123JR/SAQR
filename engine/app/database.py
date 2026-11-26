"""Clean dual-backend database layer (PostgreSQL 16 in Docker, SQLite WAL locally/in tests).

Keeps SQL queries simple, parameterized, and easy for a student team to read and defend.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.models import utc_now_iso

SCHEMA_FILE = Path(__file__).resolve().parent.parent / "db" / "schema.sql"

_ALLOWED_INCIDENT_COLS = frozenset(
    {
        "status",
        "quarantined",
        "t3_dumped_utc",
        "t4_contained_utc",
        "mttd_ms",
        "mttc_ms",
        "affected_files",
        "actions_json",
    }
)


class SAQRDatabase:
    """Thread-safe DB wrapper supporting PostgreSQL 16 (`DATABASE_URL`) or local SQLite WAL."""

    def __init__(self, database_url: str = "", sqlite_path: Path = Path("/tmp/saqr_rework/saqr.db")) -> None:
        self._lock = threading.RLock()
        self.backend = "sqlite"
        self._conn: Any = None

        if database_url.startswith("postgresql://"):
            try:
                import psycopg
                from psycopg.rows import dict_row

                self._conn = psycopg.connect(database_url, autocommit=False, row_factory=dict_row)
                self.backend = "postgres"
            except Exception:
                # Fall back gracefully to SQLite WAL if PostgreSQL isn't reachable locally
                self.backend = "sqlite"

        if self.backend == "sqlite":
            sqlite_path = Path(sqlite_path)
            sqlite_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(sqlite_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            with self._lock:
                self._conn.execute("PRAGMA journal_mode = WAL;")
                self._conn.execute("PRAGMA foreign_keys = ON;")
                self._conn.executescript(SCHEMA_FILE.read_text(encoding="utf-8"))
                self._conn.commit()
        else:
            with self._lock:
                with self._conn.cursor() as cur:
                    cur.execute(SCHEMA_FILE.read_text(encoding="utf-8"))
                self._conn.commit()

    def _ph(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.backend == "postgres" else sql

    def _fetchall(self, sql: str, params: Tuple[Any, ...] = ()) -> List[Dict[str, Any]]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(self._ph(sql), params)
            rows = cur.fetchall()
            return [dict(r) for r in rows]

    def _fetchone(self, sql: str, params: Tuple[Any, ...] = ()) -> Optional[Dict[str, Any]]:
        rows = self._fetchall(sql, params)
        return rows[0] if rows else None

    def _exec(self, sql: str, params: Tuple[Any, ...] = ()) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(self._ph(sql), params)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------
    # Incidents (with Atomic Idempotency Lock)
    # ------------------------------------------------------------------

    def create_or_get_incident(self, data: Dict[str, Any]) -> Tuple[str, bool]:
        incident_id = data.get("incident_id") or f"INC-{uuid.uuid4().hex[:10].upper()}"
        now = utc_now_iso()
        sql = """
            INSERT INTO incidents (
                incident_id, agent_id, hostname, scenario, actor_key, rule_id,
                target_pid, parent_pid, process_image, command_line, risk_score,
                status, mitre_ids_json, signals_json, actions_json,
                affected_files, quarantined, t0_attack_utc, t1_detected_utc,
                t2_decided_utc, t3_dumped_utc, t4_contained_utc, mttd_ms, mttc_ms, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            incident_id,
            data["agent_id"],
            data.get("hostname", "win10-vm"),
            data.get("scenario", "ransomware"),
            data["actor_key"],
            str(data.get("rule_id", "100201")),
            data.get("target_pid"),
            data.get("parent_pid"),
            data.get("process_image"),
            data.get("command_line"),
            int(data.get("risk_score", 85)),
            data.get("status", "CONTAINING"),
            json.dumps(data.get("mitre_ids", []), ensure_ascii=False),
            json.dumps(data.get("signals", []), ensure_ascii=False),
            json.dumps(data.get("actions_taken", []), ensure_ascii=False),
            int(data.get("affected_files", 0)),
            1 if data.get("quarantined") else 0,
            data.get("t0_attack_utc"),
            data["t1_detected_utc"],
            data["t2_decided_utc"],
            data.get("t3_dumped_utc"),
            data.get("t4_contained_utc"),
            data.get("mttd_ms"),
            data.get("mttc_ms"),
            now,
        )
        with self._lock:
            try:
                cur = self._conn.cursor()
                cur.execute(self._ph(sql), params)
                self._conn.commit()
                return incident_id, True
            except Exception:
                self._conn.rollback()
                existing = self._fetchone(
                    """
                    SELECT incident_id FROM incidents
                    WHERE agent_id = ? AND actor_key = ?
                      AND status IN ('DETECTED', 'CONTAINING', 'CONTAINED', 'REPORTING')
                    LIMIT 1
                    """,
                    (data["agent_id"], data["actor_key"]),
                )
                if existing:
                    return str(existing["incident_id"]), False
                raise

    def update_incident(self, incident_id: str, **fields: Any) -> None:
        if not fields:
            return
        cols, vals = [], []
        for k, v in fields.items():
            if k not in _ALLOWED_INCIDENT_COLS:
                raise ValueError(f"Disallowed column update: {k}")
            if k == "actions_json" and not isinstance(v, str):
                v = json.dumps(v, ensure_ascii=False)
            cols.append(f"{k} = ?")
            vals.append(v)
        vals.append(incident_id)
        self._exec(f"UPDATE incidents SET {', '.join(cols)} WHERE incident_id = ?", tuple(vals))

    def _hydrate(self, row: Dict[str, Any]) -> Dict[str, Any]:
        d = dict(row)
        d["mitre_ids"] = json.loads(d.pop("mitre_ids_json") or "[]")
        d["signals"] = json.loads(d.pop("signals_json") or "[]")
        d["actions_taken"] = json.loads(d.pop("actions_json") or "[]")
        d["quarantined"] = bool(d["quarantined"])
        return d

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        row = self._fetchone("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
        if not row:
            return None
        inc = self._hydrate(row)
        inc["artifacts"] = self._fetchall(
            "SELECT * FROM forensic_artifacts WHERE incident_id = ? ORDER BY captured_at ASC",
            (incident_id,),
        )
        for art in inc["artifacts"]:
            art["integrity_ok"] = bool(art["integrity_ok"])
        inc["reports"] = self._fetchall(
            "SELECT * FROM reports WHERE incident_id = ? ORDER BY created_at DESC",
            (incident_id,),
        )
        if inc["artifacts"]:
            inc["evidence_sha256"] = inc["artifacts"][-1]["sha256_server"]
            inc["evidence_integrity_ok"] = inc["artifacts"][-1]["integrity_ok"]
        return inc

    def list_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        rows = self._fetchall("SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,))
        out = []
        for r in rows:
            inc = self._hydrate(r)
            art = self._fetchone(
                "SELECT sha256_server, integrity_ok FROM forensic_artifacts WHERE incident_id = ? ORDER BY captured_at DESC LIMIT 1",
                (inc["incident_id"],),
            )
            if art:
                inc["evidence_sha256"] = art["sha256_server"]
                inc["evidence_integrity_ok"] = bool(art["integrity_ok"])
            out.append(inc)
        return out

    # ------------------------------------------------------------------
    # Forensic Artifacts, Reports, Outbox, Blocks, IAM & Audit
    # ------------------------------------------------------------------

    def add_artifact(
        self,
        incident_id: str,
        agent_id: str,
        vault_filename: str,
        size_bytes: int,
        sha256_agent: str,
        sha256_server: str,
        integrity_ok: bool,
    ) -> Dict[str, Any]:
        aid = f"ART-{uuid.uuid4().hex[:10].upper()}"
        ts = utc_now_iso()
        self._exec(
            """
            INSERT INTO forensic_artifacts
            (artifact_id, incident_id, agent_id, vault_filename, size_bytes, sha256_agent, sha256_server, integrity_ok, captured_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (aid, incident_id, agent_id, vault_filename, size_bytes, sha256_agent.lower(), sha256_server.lower(), 1 if integrity_ok else 0, ts),
        )
        return {
            "artifact_id": aid,
            "incident_id": incident_id,
            "agent_id": agent_id,
            "vault_filename": vault_filename,
            "size_bytes": size_bytes,
            "sha256_agent": sha256_agent.lower(),
            "sha256_server": sha256_server.lower(),
            "integrity_ok": integrity_ok,
            "captured_at": ts,
        }

    def save_report(
        self,
        incident_id: str,
        provider: str,
        model_name: str,
        language: str,
        redacted_input: Dict[str, Any],
        report_markdown: str,
        latency_ms: int,
    ) -> str:
        rid = f"RPT-{uuid.uuid4().hex[:10].upper()}"
        self._exec(
            """
            INSERT INTO reports (report_id, incident_id, provider, model_name, language, redacted_input, report_markdown, latency_ms, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (rid, incident_id, provider, model_name, language, json.dumps(redacted_input, ensure_ascii=False), report_markdown, latency_ms, utc_now_iso()),
        )
        return rid

    def enqueue_outbox(self, incident_id: str, channel: str, payload: Dict[str, Any], error: Optional[str] = None) -> str:
        jid = f"JOB-{uuid.uuid4().hex[:10].upper()}"
        self._exec(
            """
            INSERT INTO delivery_outbox (job_id, incident_id, channel, payload_json, status, attempts, last_error, created_at)
            VALUES (?, ?, ?, ?, 'PENDING', 0, ?, ?)
            """,
            (jid, incident_id, channel, json.dumps(payload, ensure_ascii=False), error, utc_now_iso()),
        )
        return jid

    def list_outbox(self) -> List[Dict[str, Any]]:
        rows = self._fetchall("SELECT * FROM delivery_outbox ORDER BY created_at DESC LIMIT 100")
        for r in rows:
            r["payload"] = json.loads(r.pop("payload_json") or "{}")
        return rows

    def block_domain(self, domain: str, incident_id: Optional[str], reason: str) -> None:
        self._exec(
            "INSERT OR REPLACE INTO blocked_domains (domain, incident_id, reason, blocked_at) VALUES (?, ?, ?, ?)"
            if self.backend == "sqlite"
            else "INSERT INTO blocked_domains (domain, incident_id, reason, blocked_at) VALUES (?, ?, ?, ?) ON CONFLICT (domain) DO UPDATE SET incident_id = EXCLUDED.incident_id, reason = EXCLUDED.reason, blocked_at = EXCLUDED.blocked_at",
            (domain.lower().strip(), incident_id, reason, utc_now_iso()),
        )

    def list_blocked_domains(self) -> List[Dict[str, Any]]:
        return self._fetchall("SELECT * FROM blocked_domains ORDER BY blocked_at DESC")

    def block_ip(self, ip: str, incident_id: Optional[str], reason: str) -> None:
        self._exec(
            "INSERT OR REPLACE INTO blocked_ips (ip, incident_id, reason, blocked_at) VALUES (?, ?, ?, ?)"
            if self.backend == "sqlite"
            else "INSERT INTO blocked_ips (ip, incident_id, reason, blocked_at) VALUES (?, ?, ?, ?) ON CONFLICT (ip) DO UPDATE SET incident_id = EXCLUDED.incident_id, reason = EXCLUDED.reason, blocked_at = EXCLUDED.blocked_at",
            (ip.strip(), incident_id, reason, utc_now_iso()),
        )

    def is_ip_blocked(self, ip: str) -> bool:
        return self._fetchone("SELECT 1 AS ok FROM blocked_ips WHERE ip = ?", (ip.strip(),)) is not None

    def list_blocked_ips(self) -> List[Dict[str, Any]]:
        return self._fetchall("SELECT * FROM blocked_ips ORDER BY blocked_at DESC")

    def revoke_session(self, jti: str, username: Optional[str], reason: str) -> None:
        self._exec(
            "INSERT OR REPLACE INTO revoked_sessions (jti, username, reason, revoked_at) VALUES (?, ?, ?, ?)"
            if self.backend == "sqlite"
            else "INSERT INTO revoked_sessions (jti, username, reason, revoked_at) VALUES (?, ?, ?, ?) ON CONFLICT (jti) DO NOTHING",
            (jti, username, reason, utc_now_iso()),
        )

    def is_session_revoked(self, jti: str) -> bool:
        return self._fetchone("SELECT 1 AS ok FROM revoked_sessions WHERE jti = ?", (jti,)) is not None

    def write_audit(self, actor: str, action: str, target: str, detail: str) -> None:
        row = self._fetchone("SELECT COALESCE(MAX(audit_id), 0) AS m FROM audit_log")
        next_id = int(row["m"]) + 1 if row else 1
        self._exec(
            "INSERT INTO audit_log (audit_id, actor, action, target, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (next_id, actor, action, target, detail, utc_now_iso()),
        )

    def list_audit(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self._fetchall("SELECT * FROM audit_log ORDER BY audit_id DESC LIMIT ?", (limit,))

    def stats(self) -> Dict[str, Any]:
        tot = self._fetchone("SELECT COUNT(*) AS c FROM incidents")["c"]
        quar = self._fetchone("SELECT COUNT(*) AS c FROM incidents WHERE quarantined = 1")["c"]
        arts = self._fetchone("SELECT COUNT(*) AS c FROM forensic_artifacts")["c"]
        doms = self._fetchone("SELECT COUNT(*) AS c FROM blocked_domains")["c"]
        ips = self._fetchone("SELECT COUNT(*) AS c FROM blocked_ips")["c"]
        revs = self._fetchone("SELECT COUNT(*) AS c FROM revoked_sessions")["c"]
        outb = self._fetchone("SELECT COUNT(*) AS c FROM delivery_outbox WHERE status = 'PENDING'")["c"]
        mttd = self._fetchone("SELECT AVG(mttd_ms) AS v FROM incidents WHERE mttd_ms IS NOT NULL")["v"]
        mttc = self._fetchone("SELECT AVG(mttc_ms) AS v FROM incidents WHERE mttc_ms IS NOT NULL")["v"]
        return {
            "total_incidents": tot,
            "quarantined_hosts": quar,
            "forensic_artifacts": arts,
            "blocked_domains": doms,
            "blocked_ips": ips,
            "revoked_sessions": revs,
            "outbox_pending": outb,
            "avg_mttd_ms": round(float(mttd), 2) if mttd is not None else None,
            "avg_mttc_ms": round(float(mttc), 2) if mttc is not None else None,
        }
