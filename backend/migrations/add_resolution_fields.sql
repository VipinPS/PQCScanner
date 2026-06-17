-- Migration: add resolution tracking + soft delete to findings table
-- Run once against your existing database

ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS migration_status  VARCHAR   NOT NULL DEFAULT 'open',
  ADD COLUMN IF NOT EXISTS resolved_at       TIMESTAMP          DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS resolved_by       VARCHAR            DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS resolution_note   TEXT               DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS archived          BOOLEAN   NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS archived_at       TIMESTAMP          DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS archived_by       VARCHAR            DEFAULT NULL;

-- Index for common query patterns
CREATE INDEX IF NOT EXISTS idx_findings_migration_status ON findings (migration_status);
CREATE INDEX IF NOT EXISTS idx_findings_archived         ON findings (archived);
CREATE INDEX IF NOT EXISTS idx_findings_repo_status      ON findings (repo_id, migration_status, archived);

-- Backfill: all existing findings are open and not archived
UPDATE findings SET migration_status = 'open', archived = FALSE
  WHERE migration_status IS NULL OR migration_status = '';
