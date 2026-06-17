-- Add artifact_id to scan_runs (missed in add_artifacts.sql)
-- Links an artifact-triggered scan run back to the artifact that caused it
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS artifact_id VARCHAR REFERENCES artifacts(id) ON DELETE SET NULL;
