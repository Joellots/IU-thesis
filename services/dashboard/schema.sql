-- schema.sql
-- Auto-executed by PostgreSQL container on first start.
-- Defines all tables for the Aegis pipeline.

-- ── Enriched alerts (one row per flow, primary model only) ────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id               SERIAL PRIMARY KEY,
    flow_id          TEXT        NOT NULL,
    sent_ts          TIMESTAMPTZ,
    inferred_ts      TIMESTAMPTZ,
    translated_ts    TIMESTAMPTZ,

    -- Model output
    model            TEXT        NOT NULL,
    tier             TEXT        NOT NULL,
    pred_label       INTEGER     NOT NULL,   -- 0=benign, 1=malicious
    pred_proba       FLOAT       NOT NULL,
    true_label       INTEGER,                -- -1 if unknown
    explain_time_ms  FLOAT,

    -- XAI output
    top_k_features   TEXT,
    top_k_json       JSONB,

    -- Translation layer output
    mitre_ttps       JSONB,
    mitre_names      JSONB,
    severity         INTEGER,                -- 1/2/3
    severity_label   TEXT,                  -- LOW/MEDIUM/HIGH
    annotation       TEXT,
    n_ttps_matched   INTEGER,

    -- SOAR enrichment (written by translator, consumed by soar_orchestrator;
    -- the translator also adds these idempotently at startup for older DBs)
    observables        JSONB,                -- [{"type": "ip"|"domain"|"url", "value": ..., "role": ...}]
    mapping_confidence DOUBLE PRECISION,
    mapping_version    TEXT,
    mapping_status     TEXT,                 -- mapped / unmapped_heuristic / unmapped
    mapping_reason     TEXT,

    -- Endpoint identity (nullable; stamped by the endpoint NFStream sensor that
    -- captured the flow, NULL for dataset-replay/in-stack flows). Lets the SOAR
    -- orchestrator route a block/isolate to the right Wazuh agent — it populates
    -- the §7.1 handoff `endpoint:{host_id, ip, source}` object.
    agent_id           TEXT,                 -- Wazuh agent id (e.g. "014")
    host_id            TEXT,                 -- Wazuh agent name = endpoint host id
    host_ip            TEXT,                 -- the sensor host's own IP

    -- Analyst decision + feedback (Step 6; written by the dashboard endpoint)
    analyst_decision   TEXT        DEFAULT 'pending',   -- pending / true_positive / false_positive
                                                        -- (legacy confirmed=true_positive, dismissed=false_positive)
    analyst_ts         TIMESTAMPTZ,
    analyst_note       TEXT,
    explanation_useful  BOOLEAN,                        -- was the XAI explanation useful?
    flag_for_retraining BOOLEAN,                        -- include this flow in the next retraining set?

    UNIQUE (flow_id, model)
);

-- ── Raw explanations (all models/tiers, for audit and research) ───────────────
CREATE TABLE IF NOT EXISTS raw_explanations (
    id               SERIAL PRIMARY KEY,
    flow_id          TEXT        NOT NULL,
    model            TEXT        NOT NULL,
    tier             TEXT        NOT NULL,
    pred_label       INTEGER,
    pred_proba       FLOAT,
    explain_time_ms  FLOAT,
    top_k_json       JSONB,
    sent_ts          TIMESTAMPTZ,
    inferred_ts      TIMESTAMPTZ,
    UNIQUE (flow_id, model)
);

-- ── Analyst decisions log ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS analyst_decisions (
    id                  SERIAL      PRIMARY KEY,
    alert_id            INTEGER     REFERENCES alerts(id),
    flow_id             TEXT,
    decision            TEXT        NOT NULL,  -- true_positive / false_positive (legacy: confirmed / dismissed)
    note                TEXT,
    explanation_useful  BOOLEAN,               -- Step 6 feedback
    flag_for_retraining BOOLEAN,               -- Step 6 feedback → retraining dataset
    decided_at          TIMESTAMPTZ DEFAULT NOW()
);

-- ── Indices for dashboard query performance ───────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_alerts_pred_label    ON alerts(pred_label);
CREATE INDEX IF NOT EXISTS idx_alerts_severity      ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_translated_ts ON alerts(translated_ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_decision      ON alerts(analyst_decision);
CREATE INDEX IF NOT EXISTS idx_alerts_agent_id      ON alerts(agent_id);