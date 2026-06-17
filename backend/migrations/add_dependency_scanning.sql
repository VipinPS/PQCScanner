-- Phase 1.1: Dependency scanning support
-- Adds source_type, dependency_name, dependency_version to findings table

ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS source_type        VARCHAR NOT NULL DEFAULT 'source_code',
  ADD COLUMN IF NOT EXISTS dependency_name    VARCHAR,
  ADD COLUMN IF NOT EXISTS dependency_version VARCHAR;

-- Index for filtering by source type in the Explorer
CREATE INDEX IF NOT EXISTS idx_findings_source_type ON findings(source_type);
