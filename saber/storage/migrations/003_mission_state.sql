-- saber/storage/migrations/003_mission_state.sql
-- SABER storage migration 003
-- Working-memory state for the agentic mission loop.
--
-- Security notes:
-- - Static DDL only.
-- - state_json is inert JSON TEXT written via parameterized queries.

CREATE TABLE IF NOT EXISTS mission_states (
    session_id TEXT PRIMARY KEY,
    state_json TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);
