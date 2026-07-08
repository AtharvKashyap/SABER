-- SABER storage migration 001
-- Core mission, evidence, finding, observation, and report artifact storage.
--
-- Security notes:
-- - This migration is static DDL only.
-- - Runtime values must be inserted with parameterized queries.
-- - JSON fields are stored as inert TEXT and are never executed.
-- - Foreign keys preserve referential integrity.

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    mission_name TEXT NOT NULL CHECK (length(trim(mission_name)) > 0),
    status TEXT NOT NULL CHECK (
        status IN (
            'created',
            'running',
            'completed',
            'failed',
            'paused',
            'paused_for_approval',
            'stopped',
            'cancelled',
            'unknown'
        )
        OR length(trim(status)) > 0
    ),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS execution_plans (
    plan_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    mission_name TEXT NOT NULL CHECK (length(trim(mission_name)) > 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS execution_steps (
    step_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    agent_name TEXT NOT NULL CHECK (length(trim(agent_name)) > 0),
    objective TEXT NOT NULL CHECK (length(trim(objective)) > 0),
    phase TEXT NOT NULL CHECK (length(trim(phase)) > 0),
    target_json TEXT,
    status TEXT NOT NULL CHECK (
        status IN (
            'pending',
            'running',
            'completed',
            'failed',
            'skipped',
            'needs_approval',
            'handoff',
            'stopped'
        )
        OR length(trim(status)) > 0
    ),
    depends_on_json TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    result_metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (session_id, step_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS step_records (
    record_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    agent_name TEXT NOT NULL CHECK (length(trim(agent_name)) > 0),
    status TEXT NOT NULL CHECK (length(trim(status)) > 0),
    handoff_agent TEXT,
    requires_approval INTEGER NOT NULL DEFAULT 0 CHECK (requires_approval IN (0, 1)),
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    step_id TEXT,
    tool_name TEXT,
    action TEXT,
    title TEXT NOT NULL CHECK (length(trim(title)) > 0),
    path TEXT NOT NULL CHECK (length(trim(path)) > 0),
    mime_type TEXT,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    step_id TEXT,
    evidence_id TEXT,
    title TEXT NOT NULL CHECK (length(trim(title)) > 0),
    severity TEXT NOT NULL CHECK (
        severity IN ('info', 'low', 'medium', 'high', 'critical', 'unknown')
    ),
    description TEXT NOT NULL CHECK (length(trim(description)) > 0),
    source_tool TEXT,
    status TEXT NOT NULL DEFAULT 'new' CHECK (
        status IN (
            'new',
            'confirmed',
            'false_positive',
            'accepted_risk',
            'remediated',
            'retest_needed',
            'closed'
        )
    ),
    fingerprint TEXT NOT NULL CHECK (length(trim(fingerprint)) > 0),
    evidence_json TEXT NOT NULL DEFAULT '{}',
    references_json TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id) ON DELETE SET NULL,
    UNIQUE (session_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS observations (
    observation_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    step_id TEXT,
    evidence_id TEXT,
    kind TEXT NOT NULL CHECK (length(trim(kind)) > 0),
    summary TEXT NOT NULL CHECK (length(trim(summary)) > 0),
    source_tool TEXT,
    data_json TEXT NOT NULL DEFAULT '{}',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS report_artifacts (
    report_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    report_type TEXT NOT NULL CHECK (
        report_type IN ('json', 'xlsx', 'pdf', 'markdown', 'html', 'other')
        OR length(trim(report_type)) > 0
    ),
    path TEXT NOT NULL CHECK (length(trim(path)) > 0),
    sha256 TEXT CHECK (sha256 IS NULL OR length(sha256) = 64),
    size_bytes INTEGER CHECK (size_bytes IS NULL OR size_bytes >= 0),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_status
    ON sessions(status);

CREATE INDEX IF NOT EXISTS idx_execution_plans_session
    ON execution_plans(session_id);

CREATE INDEX IF NOT EXISTS idx_execution_steps_session_status
    ON execution_steps(session_id, status);

CREATE INDEX IF NOT EXISTS idx_step_records_session_step
    ON step_records(session_id, step_id);

CREATE INDEX IF NOT EXISTS idx_evidence_session
    ON evidence(session_id);

CREATE INDEX IF NOT EXISTS idx_evidence_session_step
    ON evidence(session_id, step_id);

CREATE INDEX IF NOT EXISTS idx_evidence_tool
    ON evidence(tool_name);

CREATE INDEX IF NOT EXISTS idx_findings_session
    ON findings(session_id);

CREATE INDEX IF NOT EXISTS idx_findings_session_severity
    ON findings(session_id, severity);

CREATE INDEX IF NOT EXISTS idx_findings_session_status
    ON findings(session_id, status);

CREATE INDEX IF NOT EXISTS idx_findings_source_tool
    ON findings(source_tool);

CREATE INDEX IF NOT EXISTS idx_observations_session
    ON observations(session_id);

CREATE INDEX IF NOT EXISTS idx_observations_session_kind
    ON observations(session_id, kind);

CREATE INDEX IF NOT EXISTS idx_observations_source_tool
    ON observations(source_tool);

CREATE INDEX IF NOT EXISTS idx_report_artifacts_session
    ON report_artifacts(session_id);
