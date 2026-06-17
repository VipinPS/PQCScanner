-- Stage 12: runtime / eBPF agent — host registry + aggregated runtime findings

CREATE TABLE IF NOT EXISTS runtime_hosts (
    id            VARCHAR PRIMARY KEY,
    hostname      VARCHAR NOT NULL,
    label         VARCHAR,
    token         VARCHAR NOT NULL UNIQUE,
    repo_id       VARCHAR REFERENCES repos(id),
    agent_version VARCHAR,
    kernel_info   VARCHAR,
    created_at    TIMESTAMP DEFAULT NOW(),
    last_seen_at  TIMESTAMP
);

CREATE TABLE IF NOT EXISTS runtime_findings (
    id               VARCHAR PRIMARY KEY,
    host_id          VARCHAR NOT NULL REFERENCES runtime_hosts(id),
    algorithm        VARCHAR NOT NULL,
    algo_type        VARCHAR,
    symbol           VARCHAR NOT NULL,
    library          VARCHAR,
    process_name     VARCHAR,
    pid              INTEGER,
    occurrences      INTEGER DEFAULT 0,
    risk_level       VARCHAR,
    quantum_status   VARCHAR,
    quantum_safe     BOOLEAN DEFAULT FALSE,
    nist_replacement VARCHAR,
    first_seen_at    TIMESTAMP,
    last_seen_at     TIMESTAMP,
    migration_status VARCHAR DEFAULT 'open',
    archived         BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_runtime_findings_host_id   ON runtime_findings(host_id);
CREATE INDEX IF NOT EXISTS idx_runtime_findings_algorithm ON runtime_findings(algorithm);
CREATE UNIQUE INDEX IF NOT EXISTS idx_runtime_findings_dedup
    ON runtime_findings(host_id, algorithm, symbol, process_name, pid);
