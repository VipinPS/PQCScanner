-- Migration: agility scoring on repos + migrated_to on findings
-- Run once against your existing database

-- Agility columns on repos
ALTER TABLE repos
  ADD COLUMN IF NOT EXISTS agility_level   INTEGER   DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS agility_label   VARCHAR   DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS agility_score   INTEGER   DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS has_hybrid      BOOLEAN   NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS agility_signals TEXT      DEFAULT NULL;

-- Migration tracking on findings
ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS migrated_to     VARCHAR   DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_repos_agility_level ON repos (agility_level);
CREATE INDEX IF NOT EXISTS idx_findings_migrated_to ON findings (migrated_to);

-- Secret findings table (SSH keys, TLS certs, PKCS12, GPG, SSH config)
CREATE TABLE IF NOT EXISTS secret_findings (
    id               VARCHAR PRIMARY KEY,
    scan_run_id      VARCHAR REFERENCES scan_runs(id) ON DELETE CASCADE,
    repo_id          VARCHAR REFERENCES repos(id)     ON DELETE CASCADE,
    file_path        VARCHAR NOT NULL,
    finding_type     VARCHAR NOT NULL,
    algorithm        VARCHAR NOT NULL,
    key_size         INTEGER,
    curve            VARCHAR,
    quantum_status   VARCHAR,
    risk_level       VARCHAR,
    nist_replacement VARCHAR,
    subject          VARCHAR,
    issuer           VARCHAR,
    not_before       VARCHAR,
    not_after        VARCHAR,
    expiry_status    VARCHAR,
    serial           VARCHAR,
    config_key       VARCHAR,
    config_value     TEXT,
    context          TEXT,
    error            TEXT,
    created_at       TIMESTAMP DEFAULT NOW(),
    migration_status VARCHAR NOT NULL DEFAULT 'open',
    resolved_at      TIMESTAMP,
    resolved_by      VARCHAR,
    archived         BOOLEAN  NOT NULL DEFAULT FALSE,
    archived_at      TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_secret_findings_repo_id      ON secret_findings (repo_id);
CREATE INDEX IF NOT EXISTS idx_secret_findings_finding_type ON secret_findings (finding_type);
CREATE INDEX IF NOT EXISTS idx_secret_findings_risk_level   ON secret_findings (risk_level);
CREATE INDEX IF NOT EXISTS idx_secret_findings_archived     ON secret_findings (archived);

-- CBOM: code vs secret usage breakdown
ALTER TABLE cbom_entries
  ADD COLUMN IF NOT EXISTS code_usages   INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS secret_usages INTEGER NOT NULL DEFAULT 0;
