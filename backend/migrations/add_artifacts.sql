-- Phase 4: Artifact Scanning
-- Tracks uploaded artifact files (.whl, .jar, .war, ELF/PE, container tarballs)

CREATE TABLE IF NOT EXISTS artifacts (
    id                VARCHAR PRIMARY KEY,
    repo_id           VARCHAR NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    name              VARCHAR NOT NULL,
    original_filename VARCHAR NOT NULL,
    artifact_type     VARCHAR NOT NULL,   -- python_wheel|python_sdist|java_jar|java_war|container_image|native_elf|native_pe|unknown
    size_bytes        BIGINT,
    file_path         VARCHAR,            -- absolute path on disk
    scan_status       VARCHAR NOT NULL DEFAULT 'pending',  -- pending|scanning|complete|failed
    scan_error        TEXT,
    finding_count     INTEGER DEFAULT 0,
    uploaded_at       TIMESTAMP DEFAULT NOW(),
    scanned_at        TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_artifacts_repo_id ON artifacts(repo_id);

-- Tag scan runs so we can tell code scans from artifact scans
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS scan_type VARCHAR DEFAULT 'code';

-- Link findings back to the artifact that produced them (nullable)
ALTER TABLE findings ADD COLUMN IF NOT EXISTS artifact_id VARCHAR REFERENCES artifacts(id) ON DELETE SET NULL;
