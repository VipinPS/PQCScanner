import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, Text, Float
from sqlalchemy.orm import relationship
from app.db.database import Base

def gen_uuid():
    return str(uuid.uuid4())

class Artifact(Base):
    __tablename__ = "artifacts"
    id                = Column(String,   primary_key=True, default=gen_uuid)
    repo_id           = Column(String,   ForeignKey("repos.id"), nullable=False)
    name              = Column(String,   nullable=False)
    original_filename = Column(String,   nullable=False)
    artifact_type     = Column(String,   nullable=False)   # python_wheel|python_sdist|java_jar|java_war|container_image|native_elf|native_pe|unknown
    size_bytes        = Column(Integer,  nullable=True)
    file_path         = Column(String,   nullable=True)    # on-disk path
    scan_status       = Column(String,   default="pending")
    scan_error        = Column(Text,     nullable=True)
    finding_count     = Column(Integer,  default=0)
    uploaded_at       = Column(DateTime, default=datetime.utcnow)
    scanned_at        = Column(DateTime, nullable=True)
    repo              = relationship("Repo",    back_populates="artifacts")

class Project(Base):
    __tablename__ = "projects"
    id          = Column(String,   primary_key=True, default=gen_uuid)
    name        = Column(String,   nullable=False, unique=True)
    description = Column(Text,     nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow)
    repos       = relationship("Repo", back_populates="project", cascade="all, delete")

class Repo(Base):
    __tablename__ = "repos"
    id             = Column(String, primary_key=True, default=gen_uuid)
    name           = Column(String, nullable=False)
    url            = Column(String, nullable=False, unique=True)
    provider       = Column(String, default="github")
    language       = Column(String)
    branch         = Column(String, default="main")
    risk_level     = Column(String, default="UNKNOWN")
    last_scanned_at= Column(DateTime, nullable=True)
    created_at     = Column(DateTime, default=datetime.utcnow)
    project_id     = Column(String, ForeignKey("projects.id"), nullable=True)
    project        = relationship("Project", back_populates="repos")

    # ── Agility scoring ──────────────────────────────────────────────────────
    agility_level  = Column(Integer,  nullable=True)   # 1–5
    agility_label  = Column(String,   nullable=True)   # Hardcoded … Fully Agile
    agility_score  = Column(Integer,  nullable=True)   # raw score
    has_hybrid     = Column(Boolean,  default=False)   # hybrid PQC detected
    agility_signals= Column(Text,     nullable=True)   # JSON list of signals
    scan_runs          = relationship("ScanRun",          back_populates="repo", cascade="all, delete")
    findings           = relationship("Finding",          back_populates="repo", cascade="all, delete")
    secret_findings    = relationship("SecretFinding",    back_populates="repo", cascade="all, delete")
    artifacts          = relationship("Artifact",         back_populates="repo", cascade="all, delete")
    network_findings   = relationship("NetworkFinding",   back_populates="repo", cascade="all, delete")
    cicd_config        = relationship("CICDConfig",       back_populates="repo", uselist=False, cascade="all, delete")
    webhook_deliveries = relationship("WebhookDelivery",  back_populates="repo", cascade="all, delete")

class ScanRun(Base):
    __tablename__ = "scan_runs"
    id              = Column(String, primary_key=True, default=gen_uuid)
    repo_id         = Column(String, ForeignKey("repos.id"), nullable=False)
    status          = Column(String, default="pending")
    started_at      = Column(DateTime, default=datetime.utcnow)
    completed_at    = Column(DateTime, nullable=True)
    total_files     = Column(Integer, default=0)
    scanned_files   = Column(Integer, default=0)
    total_findings  = Column(Integer, default=0)
    error_message   = Column(Text, nullable=True)
    scan_type       = Column(String, default="code")  # "code" | "artifact"
    artifact_id     = Column(String, ForeignKey("artifacts.id"), nullable=True)
    repo            = relationship("Repo", back_populates="scan_runs")
    findings        = relationship("Finding", back_populates="scan_run", cascade="all, delete")
    secret_findings = relationship("SecretFinding", back_populates="scan_run", cascade="all, delete")

class Finding(Base):
    __tablename__ = "findings"
    id               = Column(String, primary_key=True, default=gen_uuid)
    scan_run_id      = Column(String, ForeignKey("scan_runs.id"), nullable=False)
    repo_id          = Column(String, ForeignKey("repos.id"),     nullable=False)
    file_path        = Column(String, nullable=False)
    line_number      = Column(Integer, nullable=False)
    algorithm        = Column(String, nullable=False)
    algo_type        = Column(String)
    context          = Column(Text)
    risk_level       = Column(String)
    quantum_status   = Column(String)
    quantum_safe     = Column(Boolean, default=False)
    nist_replacement = Column(String, nullable=True)
    created_at       = Column(DateTime, default=datetime.utcnow)

    # ── Migration tracking ───────────────────────────────────────────────────
    # What algorithm was this migrated TO (e.g. "ML-KEM-768")
    migrated_to      = Column(String,   nullable=True)

    # ── Resolution tracking ──────────────────────────────────────────────────
    # Statuses: open | auto_resolved | manually_resolved | re_opened
    migration_status = Column(String,   default="open",       nullable=False)
    resolved_at      = Column(DateTime, nullable=True)
    resolved_by      = Column(String,   nullable=True)   # "scanner" | username
    resolution_note  = Column(Text,     nullable=True)

    # ── Context window ───────────────────────────────────────────────────────
    # 1-indexed line number of the first line in context (for the code viewer)
    context_start_line = Column(Integer, nullable=True, default=1)

    # ── Dependency / artifact scanning ───────────────────────────────────────────
    # source_type: "source_code" (default) | "dependency" | "artifact"
    source_type       = Column(String,  default="source_code", nullable=False)
    dependency_name   = Column(String,  nullable=True)   # e.g. "pyjwt"
    dependency_version= Column(String,  nullable=True)   # e.g. "1.7.0"
    ecosystem         = Column(String,  nullable=True)   # e.g. "pypi" | "npm" | "go" | "crates.io" | "maven" | "rubygems"
    artifact_id       = Column(String,  ForeignKey("artifacts.id"), nullable=True)

    # ── AI validation (Granite / Ollama) ─────────────────────────────────────
    # Statuses: null (not run) | pending | true_positive | false_positive | uncertain
    ai_validated    = Column(Boolean,  default=False,    nullable=False)
    ai_confidence   = Column(Float,    nullable=True)    # 0.0 – 1.0
    ai_label        = Column(String,   nullable=True)    # true_positive | false_positive | uncertain
    ai_explanation  = Column(Text,     nullable=True)    # model explanation
    ai_validated_at = Column(DateTime, nullable=True)

    # ── Soft delete ──────────────────────────────────────────────────────────
    # archived = True means hidden from normal views but kept for audit trail
    archived         = Column(Boolean,  default=False,        nullable=False)
    archived_at      = Column(DateTime, nullable=True)
    archived_by      = Column(String,   nullable=True)

    # ── Call graph analysis (Phase 5) ────────────────────────────────────────────
    # null = not yet analyzed
    reachable    = Column(Boolean,  nullable=True)   # True = reachable from entry point
    call_depth   = Column(Integer,  nullable=True)   # hops from entry point
    call_chain   = Column(Text,     nullable=True)   # JSON array: ["main","auth","verify"]

    # ── Path-based FP heuristic ──────────────────────────────────────────────
    # True = file path matches test/fixture/example/vendor patterns
    in_test_path = Column(Boolean,  default=False,   nullable=True)

    repo             = relationship("Repo",    back_populates="findings")
    scan_run         = relationship("ScanRun", back_populates="findings")
    cves             = relationship("FindingCVE", back_populates="finding", cascade="all, delete-orphan")

class FindingCVE(Base):
    """CVE overlay — known vulnerabilities associated with a dependency finding."""
    __tablename__ = "finding_cves"
    id            = Column(String,   primary_key=True, default=gen_uuid)
    finding_id    = Column(String,   ForeignKey("findings.id"), nullable=False)
    cve_id        = Column(String,   nullable=False)   # e.g. "CVE-2022-29217"
    summary       = Column(Text,     nullable=True)
    cvss_score    = Column(Float,    nullable=True)    # 0.0 – 10.0
    cvss_severity = Column(String,   nullable=True)     # CRITICAL | HIGH | MEDIUM | LOW
    source        = Column(String,   default="osv")    # "osv" | "curated"
    fetched_at    = Column(DateTime, default=datetime.utcnow)

    finding       = relationship("Finding", back_populates="cves")

class SecretFinding(Base):
    """SSH keys, TLS certs, PKCS12, GPG keys, SSH config findings."""
    __tablename__ = "secret_findings"
    id               = Column(String,  primary_key=True, default=gen_uuid)
    scan_run_id      = Column(String,  ForeignKey("scan_runs.id"), nullable=False)
    repo_id          = Column(String,  ForeignKey("repos.id"),     nullable=False)
    file_path        = Column(String,  nullable=False)
    finding_type     = Column(String,  nullable=False)  # SSH_PRIVATE_KEY | TLS_CERT | …
    algorithm        = Column(String,  nullable=False)
    key_size         = Column(Integer, nullable=True)
    curve            = Column(String,  nullable=True)
    quantum_status   = Column(String,  nullable=True)
    risk_level       = Column(String,  nullable=True)
    nist_replacement = Column(String,  nullable=True)
    # Certificate fields
    subject          = Column(String,  nullable=True)
    issuer           = Column(String,  nullable=True)
    not_before       = Column(String,  nullable=True)
    not_after        = Column(String,  nullable=True)
    expiry_status    = Column(String,  nullable=True)
    serial           = Column(String,  nullable=True)
    # SSH config fields
    config_key       = Column(String,  nullable=True)
    config_value     = Column(Text,    nullable=True)
    # Common
    context          = Column(Text,    nullable=True)
    error            = Column(Text,    nullable=True)
    created_at       = Column(DateTime, default=datetime.utcnow)
    # Resolution (same lifecycle as Finding)
    migration_status = Column(String,  default="open", nullable=False)
    resolved_at      = Column(DateTime, nullable=True)
    resolved_by      = Column(String,  nullable=True)
    archived         = Column(Boolean, default=False,  nullable=False)
    archived_at      = Column(DateTime, nullable=True)

    repo             = relationship("Repo",    foreign_keys=[repo_id],     back_populates="secret_findings")
    scan_run         = relationship("ScanRun", foreign_keys=[scan_run_id], back_populates="secret_findings")

class CBOMEntry(Base):
    __tablename__ = "cbom_entries"
    id               = Column(String, primary_key=True, default=gen_uuid)
    algorithm        = Column(String, unique=True, nullable=False)
    algo_type        = Column(String)
    quantum_status   = Column(String)
    nist_replacement = Column(String, nullable=True)
    priority         = Column(Integer, default=3)
    total_usages     = Column(Integer, default=0)
    code_usages      = Column(Integer, default=0)   # from source code findings
    secret_usages    = Column(Integer, default=0)   # from SSH keys / TLS certs / etc.
    artifact_usages  = Column(Integer, default=0)   # from artifact scans
    unreachable_count= Column(Integer, default=0)   # call-graph: unreachable findings
    min_call_depth   = Column(Integer, nullable=True)  # shallowest call depth seen
    affected_repos   = Column(Integer, default=0)
    risk_score       = Column(Float,   default=0.0)
    updated_at       = Column(DateTime, default=datetime.utcnow)


class CICDConfig(Base):
    """Per-repo CI/CD gate configuration and webhook secret."""
    __tablename__ = "cicd_configs"
    id                  = Column(String,  primary_key=True, default=gen_uuid)
    repo_id             = Column(String,  ForeignKey("repos.id"), nullable=False, unique=True)
    # Gate thresholds — quantum_status triggers
    fail_on_broken      = Column(Boolean, default=True)
    fail_on_vulnerable  = Column(Boolean, default=True)
    fail_on_weak        = Column(Boolean, default=False)
    # Gate thresholds — risk_level triggers
    fail_on_critical    = Column(Boolean, default=True)
    fail_on_high        = Column(Boolean, default=True)
    # Webhook
    webhook_secret      = Column(String,  nullable=True)   # HMAC secret shared with GitHub/GitLab
    created_at          = Column(DateTime, default=datetime.utcnow)
    updated_at          = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    repo                = relationship("Repo", back_populates="cicd_config")


class WebhookDelivery(Base):
    """Log of inbound webhook events."""
    __tablename__ = "webhook_deliveries"
    id                = Column(String,  primary_key=True, default=gen_uuid)
    repo_id           = Column(String,  ForeignKey("repos.id"), nullable=False)
    received_at       = Column(DateTime, default=datetime.utcnow)
    provider          = Column(String,  nullable=True)   # github | gitlab | bitbucket
    event_type        = Column(String,  nullable=True)   # push | pull_request
    branch            = Column(String,  nullable=True)
    commit_sha        = Column(String,  nullable=True)
    triggered_scan_id = Column(String,  nullable=True)   # ScanRun.id if scan was triggered
    status            = Column(String,  default="received")  # received|scan_queued|ignored|error
    error             = Column(Text,    nullable=True)
    repo              = relationship("Repo", back_populates="webhook_deliveries")


class RuntimeHost(Base):
    """A host running the Stage 12 eBPF runtime agent (agent/)."""
    __tablename__ = "runtime_hosts"

    id            = Column(String,   primary_key=True, default=gen_uuid)
    hostname      = Column(String,   nullable=False)
    label         = Column(String,   nullable=True)
    token         = Column(String,   nullable=False, unique=True)
    repo_id       = Column(String,   ForeignKey("repos.id"), nullable=True)
    agent_version = Column(String,   nullable=True)
    kernel_info   = Column(String,   nullable=True)
    created_at    = Column(DateTime, default=datetime.utcnow)
    last_seen_at  = Column(DateTime, nullable=True)

    repo          = relationship("Repo")
    findings      = relationship("RuntimeFinding", back_populates="host", cascade="all, delete-orphan")


class RuntimeFinding(Base):
    """
    Aggregated runtime crypto-call observation reported by the Stage 12
    agent — one row per (host, algorithm, symbol, process, pid), with an
    occurrence counter incremented on each ingest.
    """
    __tablename__ = "runtime_findings"

    id               = Column(String,   primary_key=True, default=gen_uuid)
    host_id          = Column(String,   ForeignKey("runtime_hosts.id"), nullable=False)

    algorithm        = Column(String,   nullable=False)   # ALGORITHM_REGISTRY key, e.g. "MD5"
    algo_type        = Column(String,   nullable=True)
    symbol           = Column(String,   nullable=False)   # e.g. "MD5_Init"
    library          = Column(String,   nullable=True)    # "libcrypto" | "libssl" | "liboqs"
    process_name     = Column(String,   nullable=True)    # comm, e.g. "python3"
    pid              = Column(Integer,  nullable=True)
    occurrences      = Column(Integer,  default=0)

    risk_level       = Column(String,   nullable=True)
    quantum_status   = Column(String,   nullable=True)
    quantum_safe     = Column(Boolean,  default=False)
    nist_replacement = Column(String,   nullable=True)

    first_seen_at    = Column(DateTime, nullable=True)
    last_seen_at     = Column(DateTime, nullable=True)

    # Lifecycle (same convention as Finding / NetworkFinding)
    migration_status = Column(String,   default="open")
    archived         = Column(Boolean,  default=False)

    host             = relationship("RuntimeHost", back_populates="findings")


class NetworkFinding(Base):
    """TLS/network endpoint scan results."""
    __tablename__ = "network_findings"

    id               = Column(String,   primary_key=True, default=gen_uuid)
    repo_id          = Column(String,   ForeignKey("repos.id"), nullable=True)
    endpoint         = Column(String,   nullable=False)          # host:port
    scanned_at       = Column(DateTime, default=datetime.utcnow)

    # TLS handshake info
    tls_version      = Column(String,   nullable=True)           # TLSv1.3 / TLSv1.2 / …
    cipher_name      = Column(String,   nullable=True)
    cipher_bits      = Column(Integer,  nullable=True)

    # Certificate fields
    cert_subject     = Column(String,   nullable=True)
    cert_issuer      = Column(String,   nullable=True)
    cert_not_before  = Column(DateTime, nullable=True)
    cert_not_after   = Column(DateTime, nullable=True)
    cert_serial      = Column(String,   nullable=True)

    # Public-key info (extracted from cert)
    key_type         = Column(String,   nullable=True)   # RSA | EC | Ed25519 | DSA
    key_size         = Column(Integer,  nullable=True)   # bits
    key_curve        = Column(String,   nullable=True)   # secp256r1, prime256v1, …
    sig_algorithm    = Column(String,   nullable=True)   # sha256WithRSAEncryption

    # Quantum risk
    algorithm        = Column(String,   nullable=True)   # display name, e.g. RSA-2048
    quantum_status   = Column(String,   nullable=True)   # BROKEN / VULNERABLE / WEAK / SAFE
    risk_level       = Column(String,   nullable=True)
    nist_replacement = Column(String,   nullable=True)
    issues           = Column(Text,     nullable=True)   # JSON list of issue strings

    # Scan status
    scan_status      = Column(String,   default="complete")      # complete | failed
    error_message    = Column(String,   nullable=True)

    # Lifecycle
    migration_status = Column(String,   default="open")
    archived         = Column(Boolean,  default=False)

    repo             = relationship("Repo", back_populates="network_findings")
