-- Phase 5: Call Graph Analysis
-- Adds reachability metadata to source-code findings

ALTER TABLE findings ADD COLUMN IF NOT EXISTS reachable   BOOLEAN;         -- null=not analyzed, true=reachable, false=unreachable
ALTER TABLE findings ADD COLUMN IF NOT EXISTS call_depth  INTEGER;         -- hops from entry point (null if unreachable/not analyzed)
ALTER TABLE findings ADD COLUMN IF NOT EXISTS call_chain  TEXT;            -- JSON array of function names, e.g. ["main","auth","verify"]
