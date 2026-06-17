-- Path-based false-positive heuristic: flag findings whose file path matches
-- common test/fixture/example/vendor patterns (mirrors the scanner's
-- TEST_PATH_PATTERN / VENDOR_PATH_PATTERN used for agility scoring).

ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS in_test_path BOOLEAN DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_findings_in_test_path ON findings (in_test_path);
