-- Remove duplicate findings, keeping only the most recent per (repo_id, file_path, algorithm)
-- Duplicates accumulate when the same finding is inserted on every scan

WITH ranked AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY repo_id, file_path, algorithm
               ORDER BY created_at DESC
           ) AS rn
    FROM findings
    WHERE archived = FALSE
),
to_delete AS (
    SELECT id FROM ranked WHERE rn > 1
)
DELETE FROM findings
WHERE id IN (SELECT id FROM to_delete);

-- Confirm
SELECT COUNT(*) AS remaining_findings FROM findings;
