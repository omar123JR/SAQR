-- SAQR PostgreSQL 16 Database Schema
-- Matches the 5-layer SAQR graduation proposal with atomic idempotency locking,
-- T0..T4 scientific timestamps, SHA-256 forensic integrity, and offline retry outbox.

CREATE TABLE IF NOT EXISTS incidents (
    incident_id       TEXT PRIMARY KEY,
    agent_id          TEXT NOT NULL,
    hostname          TEXT NOT NULL,
    scenario          TEXT NOT NULL DEFAULT 'ransomware',
    actor_key         TEXT NOT NULL,
    rule_id           TEXT NOT NULL,
    target_pid        INTEGER,
    parent_pid        INTEGER,
    process_image     TEXT,
    command_line      TEXT,
    risk_score        INTEGER NOT NULL,
    status            TEXT NOT NULL,
    mitre_ids_json    TEXT NOT NULL DEFAULT '[]',
    signals_json      TEXT NOT NULL DEFAULT '[]',
    actions_json      TEXT NOT NULL DEFAULT '[]',
    affected_files    INTEGER NOT NULL DEFAULT 0,
    quarantined       INTEGER NOT NULL DEFAULT 0,
    t0_attack_utc     TEXT,
    t1_detected_utc   TEXT NOT NULL,
    t2_decided_utc    TEXT NOT NULL,
    t3_dumped_utc     TEXT,
    t4_contained_utc  TEXT,
    mttd_ms           DOUBLE PRECISION,
    mttc_ms           DOUBLE PRECISION,
    created_at        TEXT NOT NULL
);

-- Atomic Idempotency Lock: prevents 50 rapid Wazuh alerts from triggering 50 ProcDumps / LLM calls
CREATE UNIQUE INDEX IF NOT EXISTS uq_saqr_active_incident
    ON incidents (agent_id, actor_key)
    WHERE status IN ('DETECTED', 'CONTAINING', 'CONTAINED', 'REPORTING');

CREATE TABLE IF NOT EXISTS forensic_artifacts (
    artifact_id       TEXT PRIMARY KEY,
    incident_id       TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    agent_id          TEXT NOT NULL,
    vault_filename    TEXT NOT NULL,
    size_bytes        BIGINT NOT NULL,
    sha256_agent      TEXT NOT NULL,
    sha256_server     TEXT NOT NULL,
    integrity_ok      INTEGER NOT NULL,
    captured_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    report_id         TEXT PRIMARY KEY,
    incident_id       TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    provider          TEXT NOT NULL,
    model_name        TEXT NOT NULL,
    language          TEXT NOT NULL DEFAULT 'ar',
    redacted_input    TEXT NOT NULL,
    report_markdown   TEXT NOT NULL,
    latency_ms        INTEGER NOT NULL,
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS delivery_outbox (
    job_id            TEXT PRIMARY KEY,
    incident_id       TEXT NOT NULL,
    channel           TEXT NOT NULL,
    payload_json      TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'PENDING',
    attempts          INTEGER NOT NULL DEFAULT 0,
    last_error        TEXT,
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blocked_domains (
    domain            TEXT PRIMARY KEY,
    incident_id       TEXT,
    reason            TEXT NOT NULL,
    blocked_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    ip                TEXT PRIMARY KEY,
    incident_id       TEXT,
    reason            TEXT NOT NULL,
    blocked_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS revoked_sessions (
    jti               TEXT PRIMARY KEY,
    username          TEXT,
    reason            TEXT NOT NULL,
    revoked_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    audit_id          INTEGER PRIMARY KEY,
    actor             TEXT NOT NULL,
    action            TEXT NOT NULL,
    target            TEXT NOT NULL,
    detail            TEXT NOT NULL,
    created_at        TEXT NOT NULL
);
