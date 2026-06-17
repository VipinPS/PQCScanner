-- Phase 1.4 + 3.2: Context window expansion and AI validation columns

-- 1.4 — Store the 1-indexed start line of the captured context window
--        so the inline code viewer can display correct line numbers
ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS context_start_line INTEGER DEFAULT 1;

-- 3.2 — AI validation results from Ollama / IBM Granite
--   ai_label: pending | true_positive | false_positive | uncertain | error
ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS ai_validated    BOOLEAN   NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS ai_confidence   FLOAT,
  ADD COLUMN IF NOT EXISTS ai_label        VARCHAR,
  ADD COLUMN IF NOT EXISTS ai_explanation  TEXT,
  ADD COLUMN IF NOT EXISTS ai_validated_at TIMESTAMP;

-- Index for fast filtering of unvalidated findings (used by batch validate endpoint)
CREATE INDEX IF NOT EXISTS idx_findings_ai_validated ON findings(ai_validated);
CREATE INDEX IF NOT EXISTS idx_findings_ai_label     ON findings(ai_label);
