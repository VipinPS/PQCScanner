-- CVE overlay: persist structured CVE/CVSS data alongside dependency findings

ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS ecosystem VARCHAR;

CREATE TABLE IF NOT EXISTS finding_cves (
    id            VARCHAR PRIMARY KEY,
    finding_id    VARCHAR NOT NULL REFERENCES findings(id),
    cve_id        VARCHAR NOT NULL,
    summary       TEXT,
    cvss_score    FLOAT,
    cvss_severity VARCHAR,
    source        VARCHAR DEFAULT 'osv',
    fetched_at    TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_finding_cves_finding_id ON finding_cves(finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_cves_cve_id     ON finding_cves(cve_id);
