-- Phase: Projects
CREATE TABLE IF NOT EXISTS projects (
    id          VARCHAR PRIMARY KEY,
    name        VARCHAR NOT NULL UNIQUE,
    description TEXT,
    created_at  TIMESTAMP DEFAULT NOW()
);

ALTER TABLE repos
    ADD COLUMN IF NOT EXISTS project_id VARCHAR REFERENCES projects(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_repos_project_id ON repos(project_id);
