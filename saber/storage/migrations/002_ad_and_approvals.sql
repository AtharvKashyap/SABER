-- SABER storage migration 002
-- Approval workflow and AD graph storage.
--
-- Security notes:
-- - This migration is static DDL only.
-- - Runtime values must be inserted with parameterized queries.
-- - Graph properties and requested actions are stored as inert JSON TEXT.
-- - No dynamic SQL, triggers, or executable stored content.

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending', 'approved', 'denied', 'expired', 'cancelled')
    ),
    reason TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    requested_action_json TEXT NOT NULL DEFAULT '{}',
    decision TEXT,
    requested_at TEXT NOT NULL,
    resolved_at TEXT,
    resolved_by TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS graph_nodes (
    node_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    kind TEXT NOT NULL DEFAULT 'unknown' CHECK (length(trim(kind)) > 0),
    labels_json TEXT NOT NULL DEFAULT '[]',
    properties_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    UNIQUE (session_id, name, kind)
);

CREATE TABLE IF NOT EXISTS graph_edges (
    edge_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    source_node_id TEXT NOT NULL,
    target_node_id TEXT NOT NULL,
    relationship TEXT NOT NULL CHECK (length(trim(relationship)) > 0),
    properties_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    FOREIGN KEY (source_node_id) REFERENCES graph_nodes(node_id) ON DELETE CASCADE,
    FOREIGN KEY (target_node_id) REFERENCES graph_nodes(node_id) ON DELETE CASCADE,
    UNIQUE (session_id, source_node_id, target_node_id, relationship)
);

CREATE TABLE IF NOT EXISTS attack_paths (
    path_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    source TEXT NOT NULL CHECK (length(trim(source)) > 0),
    target TEXT NOT NULL CHECK (length(trim(target)) > 0),
    path_length INTEGER NOT NULL CHECK (path_length >= 0),
    edges_json TEXT NOT NULL DEFAULT '[]',
    risk_score REAL CHECK (risk_score IS NULL OR risk_score >= 0),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_approvals_session_status
    ON approvals(session_id, status);

CREATE INDEX IF NOT EXISTS idx_approvals_step
    ON approvals(session_id, step_id);

CREATE INDEX IF NOT EXISTS idx_graph_nodes_session
    ON graph_nodes(session_id);

CREATE INDEX IF NOT EXISTS idx_graph_nodes_session_kind
    ON graph_nodes(session_id, kind);

CREATE INDEX IF NOT EXISTS idx_graph_edges_session
    ON graph_edges(session_id);

CREATE INDEX IF NOT EXISTS idx_graph_edges_relationship
    ON graph_edges(session_id, relationship);

CREATE INDEX IF NOT EXISTS idx_graph_edges_source
    ON graph_edges(source_node_id);

CREATE INDEX IF NOT EXISTS idx_graph_edges_target
    ON graph_edges(target_node_id);

CREATE INDEX IF NOT EXISTS idx_attack_paths_session
    ON attack_paths(session_id);

CREATE INDEX IF NOT EXISTS idx_attack_paths_target
    ON attack_paths(session_id, target);

CREATE INDEX IF NOT EXISTS idx_attack_paths_risk
    ON attack_paths(session_id, risk_score);
