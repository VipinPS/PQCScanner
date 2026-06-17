-- Phase 6: CBOM enrichment — artifact and call-graph data
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS artifact_usages   INTEGER DEFAULT 0;   -- findings from artifact scans
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS min_call_depth    INTEGER;              -- shallowest call depth seen (null = not analysed)
ALTER TABLE cbom_entries ADD COLUMN IF NOT EXISTS unreachable_count INTEGER DEFAULT 0;   -- findings unreachable from entry points
