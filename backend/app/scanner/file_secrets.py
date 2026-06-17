"""
File Secrets Scanner — SSH keys, TLS certificates, PKCS#12, JKS, GPG, OpenSSH config.
Uses Python cryptography + paramiko. No external binaries required.
"""
import os, re, logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── Quantum risk assessment helpers ──────────────────────────────────────────

def _rsa_risk(bits: int):
    if bits <= 1024: return ("BROKEN",     "CRITICAL", "ML-KEM-768 / ML-DSA-65 (FIPS 203/204)")
    if bits <= 2048: return ("VULNERABLE", "CRITICAL", "ML-KEM-768 / ML-DSA-65 (FIPS 203/204)")
    if bits <= 3072: return ("VULNERABLE", "HIGH",     "ML-KEM-1024 / ML-DSA-87 (FIPS 203/204)")
    return             ("VULNERABLE", "HIGH",     "ML-KEM-1024 / ML-DSA-87 (FIPS 203/204)")

def _ec_risk(curve: str):
    curve = (curve or "").lower()
    if any(x in curve for x in ["p-256","prime256","secp256r1","p256"]):
        return ("VULNERABLE", "HIGH", "ML-DSA-65 (FIPS 204)")
    if any(x in curve for x in ["p-384","secp384r1"]):
        return ("VULNERABLE", "HIGH", "ML-DSA-65 (FIPS 204)")
    if any(x in curve for x in ["p-521","secp521r1"]):
        return ("VULNERABLE", "HIGH", "ML-DSA-87 (FIPS 204)")
    if any(x in curve for x in ["25519","ed25519"]):
        return ("VULNERABLE", "MEDIUM", "ML-DSA-65 (FIPS 204) — Ed25519 is safe classically but quantum-vulnerable")
    return ("VULNERABLE", "HIGH", "ML-DSA-65 (FIPS 204)")

def _dsa_risk(bits: int):
    return ("BROKEN", "CRITICAL", "ML-DSA-65 (FIPS 204)")

def _hash_risk(algo: str):
    algo = (algo or "").lower().replace("-","").replace("_","")
    if "md5"   in algo: return ("BROKEN",     "CRITICAL")
    if "sha1"  in algo: return ("WEAK",       "HIGH")
    if "sha224"in algo: return ("MONITOR",    "MEDIUM")
    return                     ("SAFE",       "LOW")

def _cert_expiry_risk(not_after: datetime) -> str:
    """Extra urgency if cert expires soon."""
    now = datetime.now(timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    days = (not_after - now).days
    if days < 0:    return "EXPIRED"
    if days < 30:   return "EXPIRES_SOON"
    if days < 90:   return "EXPIRES_90D"
    return               "VALID"

# ── Finding dataclass ─────────────────────────────────────────────────────────

@dataclass
class SecretFinding:
    file_path:        str
    finding_type:     str       # SSH_PRIVATE_KEY | SSH_PUBLIC_KEY | TLS_CERT | PKCS12 | JKS | GPG | SSH_CONFIG
    algorithm:        str       # RSA-2048, ECDSA-P256, Ed25519, …
    key_size:         Optional[int]   = None
    curve:            Optional[str]   = None
    quantum_status:   str             = "VULNERABLE"
    risk_level:       str             = "HIGH"
    nist_replacement: Optional[str]   = None
    # Certificate-specific
    subject:          Optional[str]   = None
    issuer:           Optional[str]   = None
    not_before:       Optional[str]   = None
    not_after:        Optional[str]   = None
    expiry_status:    Optional[str]   = None
    serial:           Optional[str]   = None
    # SSH config-specific
    config_key:       Optional[str]   = None
    config_value:     Optional[str]   = None
    # Context snippet
    context:          Optional[str]   = None
    error:            Optional[str]   = None

# ── File patterns ─────────────────────────────────────────────────────────────

SSH_PRIVATE_EXTS  = {".pem", ".key", ".rsa", ".dsa", ".ecdsa", ".ed25519"}
SSH_PUBLIC_EXTS   = {".pub"}
CERT_EXTS         = {".crt", ".cer", ".cert"}
PKCS12_EXTS       = {".p12", ".pfx"}
JKS_EXTS          = {".jks", ".keystore"}
GPG_EXTS          = {".gpg", ".asc", ".pgp"}
ALL_SECRET_EXTS   = (SSH_PRIVATE_EXTS | SSH_PUBLIC_EXTS | CERT_EXTS |
                     PKCS12_EXTS | JKS_EXTS | GPG_EXTS)

# Names that hint at SSH/TLS even without extension
HINT_NAMES = re.compile(
    r"(id_rsa|id_dsa|id_ecdsa|id_ed25519|id_xmss|authorized_keys|known_hosts"
    r"|ssh_host_rsa_key|ssh_host_ecdsa_key|ssh_host_ed25519_key"
    r"|ssh_config|sshd_config"
    r"|server\.crt|ca\.crt|ca-bundle|rootca|client\.crt"
    r"|deploy_key|github_rsa|gitlab_rsa)",
    re.IGNORECASE
)

# SSH config directives we care about
SSH_CONFIG_PATTERNS = [
    (re.compile(r"^\s*HostKeyAlgorithms\s+(.+)$",       re.I|re.M), "HostKeyAlgorithms"),
    (re.compile(r"^\s*Ciphers\s+(.+)$",                 re.I|re.M), "Ciphers"),
    (re.compile(r"^\s*MACs\s+(.+)$",                    re.I|re.M), "MACs"),
    (re.compile(r"^\s*KexAlgorithms\s+(.+)$",           re.I|re.M), "KexAlgorithms"),
    (re.compile(r"^\s*PubkeyAuthentication\s+(.+)$",    re.I|re.M), "PubkeyAuthentication"),
    (re.compile(r"^\s*PasswordAuthentication\s+(.+)$",  re.I|re.M), "PasswordAuthentication"),
]

SKIP_DIRS = {".git","node_modules","__pycache__",".venv","venv","dist","build",
             ".next","vendor","target"}

# ── Scanner class ─────────────────────────────────────────────────────────────

class FileSecretsScanner:
    def __init__(self):
        self._has_crypto    = self._try_import_crypto()
        self._has_paramiko  = self._try_import_paramiko()

    def _try_import_crypto(self):
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
            from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate
            return True
        except ImportError:
            logger.warning("cryptography library not installed — cert/key parsing limited")
            return False

    def _try_import_paramiko(self):
        try:
            import paramiko
            return True
        except ImportError:
            logger.warning("paramiko not installed — SSH key parsing limited")
            return False

    def scan_directory(self, root_path: str) -> list:
        findings = []
        for dirpath, dirnames, filenames in os.walk(root_path):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fname in filenames:
                fpath    = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(fpath, root_path)
                ext      = Path(fname).suffix.lower()
                name     = fname.lower()

                try:
                    if ext in SSH_PRIVATE_EXTS or HINT_NAMES.search(fname):
                        findings.extend(self._scan_file_dispatch(fpath, rel_path, ext, name))
                    elif ext in CERT_EXTS:
                        findings.extend(self._scan_cert_pem(fpath, rel_path))
                    elif ext in PKCS12_EXTS:
                        findings.extend(self._scan_pkcs12(fpath, rel_path))
                    elif ext in SSH_PUBLIC_EXTS:
                        findings.extend(self._scan_ssh_public(fpath, rel_path))
                    elif ext in GPG_EXTS:
                        findings.extend(self._scan_gpg(fpath, rel_path))
                except Exception as e:
                    logger.debug(f"FileSecretsScanner error on {rel_path}: {e}")

        return findings

    def _scan_file_dispatch(self, fpath, rel_path, ext, name):
        """Route file to the right scanner based on content sniffing."""
        try:
            with open(fpath, "rb") as f:
                header = f.read(512)
        except Exception:
            return []

        text = header.decode("utf-8", errors="ignore")

        if "ssh_config" in name or "sshd_config" in name:
            return self._scan_ssh_config(fpath, rel_path)
        if "authorized_keys" in name:
            return self._scan_authorized_keys(fpath, rel_path)
        if "known_hosts" in name:
            return []  # known_hosts: low value, skip

        if "BEGIN" in text and "PRIVATE KEY" in text:
            return self._scan_private_key_pem(fpath, rel_path)
        if "BEGIN" in text and "PUBLIC KEY" in text:
            return self._scan_ssh_public(fpath, rel_path)
        if "BEGIN" in text and "CERTIFICATE" in text:
            return self._scan_cert_pem(fpath, rel_path)
        if "BEGIN" in text and "PGP" in text:
            return self._scan_gpg(fpath, rel_path)

        # Binary — try PKCS12
        if ext in PKCS12_EXTS or header[:2] == b'\x30\x82':
            return self._scan_pkcs12(fpath, rel_path)

        return []

    # ── Private key (PEM) ─────────────────────────────────────────────────────
    def _scan_private_key_pem(self, fpath, rel_path):
        findings = []
        try:
            with open(fpath, "rb") as f:
                data = f.read()
        except Exception as e:
            return [SecretFinding(rel_path, "SSH_PRIVATE_KEY", "UNKNOWN",
                                  error=str(e), context="Could not read file")]

        text = data.decode("utf-8", errors="ignore")

        if self._has_crypto:
            findings.extend(self._parse_pem_key_crypto(data, rel_path))
        else:
            # Fallback: regex-based type detection
            findings.extend(self._parse_pem_key_regex(text, rel_path))

        return findings

    def _parse_pem_key_crypto(self, data: bytes, rel_path: str):
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
        try:
            key = load_pem_private_key(data, password=None)
        except TypeError:
            return [SecretFinding(rel_path, "SSH_PRIVATE_KEY", "ENCRYPTED-KEY",
                                  quantum_status="UNKNOWN", risk_level="MEDIUM",
                                  nist_replacement="Verify algorithm after decryption",
                                  context="Key is passphrase-protected — algorithm not inspectable without password")]
        except Exception as e:
            return [SecretFinding(rel_path, "SSH_PRIVATE_KEY", "UNKNOWN",
                                  error=str(e))]

        if isinstance(key, rsa.RSAPrivateKey):
            bits = key.key_size
            qs, risk, repl = _rsa_risk(bits)
            algo = f"RSA-{bits}"
            return [SecretFinding(rel_path, "SSH_PRIVATE_KEY", algo,
                                  key_size=bits, quantum_status=qs, risk_level=risk,
                                  nist_replacement=repl,
                                  context=f"RSA private key, {bits}-bit")]
        if isinstance(key, ec.EllipticCurvePrivateKey):
            curve = key.curve.name
            qs, risk, repl = _ec_risk(curve)
            algo = f"ECDSA-{curve}"
            return [SecretFinding(rel_path, "SSH_PRIVATE_KEY", algo,
                                  curve=curve, quantum_status=qs, risk_level=risk,
                                  nist_replacement=repl,
                                  context=f"EC private key, curve {curve}")]
        if isinstance(key, dsa.DSAPrivateKey):
            bits = key.key_size
            qs, risk, repl = _dsa_risk(bits)
            return [SecretFinding(rel_path, "SSH_PRIVATE_KEY", f"DSA-{bits}",
                                  key_size=bits, quantum_status=qs, risk_level=risk,
                                  nist_replacement=repl,
                                  context=f"DSA private key, {bits}-bit — DSA is broken, replace immediately")]
        if isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
            algo = "Ed25519" if isinstance(key, ed25519.Ed25519PrivateKey) else "Ed448"
            return [SecretFinding(rel_path, "SSH_PRIVATE_KEY", algo,
                                  quantum_status="VULNERABLE", risk_level="MEDIUM",
                                  nist_replacement="ML-DSA-65 (FIPS 204)",
                                  context=f"{algo} key — safe classically, quantum-vulnerable via Shor")]
        return [SecretFinding(rel_path, "SSH_PRIVATE_KEY", "UNKNOWN-KEY-TYPE",
                              quantum_status="MONITOR", risk_level="LOW")]

    def _parse_pem_key_regex(self, text: str, rel_path: str):
        """Fallback when cryptography lib not available."""
        if "RSA PRIVATE KEY" in text:
            return [SecretFinding(rel_path, "SSH_PRIVATE_KEY", "RSA",
                                  quantum_status="VULNERABLE", risk_level="CRITICAL",
                                  nist_replacement="ML-DSA-65 (FIPS 204)",
                                  context="RSA private key detected (install cryptography lib for key size)")]
        if "EC PRIVATE KEY" in text:
            return [SecretFinding(rel_path, "SSH_PRIVATE_KEY", "ECDSA",
                                  quantum_status="VULNERABLE", risk_level="HIGH",
                                  nist_replacement="ML-DSA-65 (FIPS 204)",
                                  context="EC private key detected")]
        if "DSA PRIVATE KEY" in text:
            return [SecretFinding(rel_path, "SSH_PRIVATE_KEY", "DSA",
                                  quantum_status="BROKEN", risk_level="CRITICAL",
                                  nist_replacement="ML-DSA-65 (FIPS 204)",
                                  context="DSA private key — broken, replace immediately")]
        if "OPENSSH PRIVATE KEY" in text:
            return [SecretFinding(rel_path, "SSH_PRIVATE_KEY", "OpenSSH-KEY",
                                  quantum_status="VULNERABLE", risk_level="HIGH",
                                  nist_replacement="ML-DSA-65 (FIPS 204)",
                                  context="OpenSSH private key (install paramiko for algorithm details)")]
        return []

    # ── SSH public key ────────────────────────────────────────────────────────
    def _scan_ssh_public(self, fpath, rel_path):
        findings = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return []

        for i, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            f = self._parse_pubkey_line(line, rel_path, i+1)
            if f:
                findings.append(f)
        return findings

    def _scan_authorized_keys(self, fpath, rel_path):
        findings = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return []
        for i, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            f = self._parse_pubkey_line(line, rel_path, i+1)
            if f:
                f.finding_type = "AUTHORIZED_KEY"
                findings.append(f)
        return findings

    def _parse_pubkey_line(self, line: str, rel_path: str, line_num: int):
        parts = line.split()
        if not parts:
            return None
        key_type = parts[0].lower()
        comment  = parts[2] if len(parts) > 2 else ""

        if "rsa" in key_type:
            # Try to get key size via paramiko
            bits = self._ssh_pubkey_bits(line)
            algo = f"RSA-{bits}" if bits else "RSA"
            qs, risk, repl = _rsa_risk(bits or 2048)
            return SecretFinding(rel_path, "SSH_PUBLIC_KEY", algo,
                                 key_size=bits, quantum_status=qs, risk_level=risk,
                                 nist_replacement=repl,
                                 context=f"SSH RSA public key{f' — {comment}' if comment else ''}")
        if "ecdsa" in key_type:
            curve = "P-256"
            if "384" in key_type: curve = "P-384"
            if "521" in key_type: curve = "P-521"
            qs, risk, repl = _ec_risk(curve)
            return SecretFinding(rel_path, "SSH_PUBLIC_KEY", f"ECDSA-{curve}",
                                 curve=curve, quantum_status=qs, risk_level=risk,
                                 nist_replacement=repl,
                                 context=f"SSH ECDSA public key{f' — {comment}' if comment else ''}")
        if "ed25519" in key_type:
            return SecretFinding(rel_path, "SSH_PUBLIC_KEY", "Ed25519",
                                 quantum_status="VULNERABLE", risk_level="MEDIUM",
                                 nist_replacement="ML-DSA-65 (FIPS 204)",
                                 context=f"SSH Ed25519 public key{f' — {comment}' if comment else ''} — safe classically, quantum-vulnerable")
        if "dss" in key_type or "dsa" in key_type:
            return SecretFinding(rel_path, "SSH_PUBLIC_KEY", "DSA",
                                 quantum_status="BROKEN", risk_level="CRITICAL",
                                 nist_replacement="ML-DSA-65 (FIPS 204)",
                                 context=f"SSH DSA public key — broken algorithm, replace immediately")
        return None

    def _ssh_pubkey_bits(self, pubkey_line: str) -> Optional[int]:
        if not self._has_paramiko:
            return None
        try:
            import paramiko, base64, io
            parts = pubkey_line.split()
            if len(parts) < 2:
                return None
            key_data = base64.b64decode(parts[1])
            key = paramiko.RSAKey(data=key_data)
            return key.get_bits()
        except Exception:
            return None

    # ── TLS Certificate (PEM) ─────────────────────────────────────────────────
    def _scan_cert_pem(self, fpath, rel_path):
        findings = []
        try:
            with open(fpath, "rb") as f:
                data = f.read()
        except Exception:
            return []

        if not self._has_crypto:
            # Regex fallback
            text = data.decode("utf-8", errors="ignore")
            if "CERTIFICATE" in text:
                return [SecretFinding(rel_path, "TLS_CERT", "UNKNOWN",
                                      context="Certificate file detected (install cryptography lib for details)")]
            return []

        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519

        # Handle multi-cert PEM (cert chains)
        pem_blocks = re.findall(
            b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            data, re.DOTALL
        )
        if not pem_blocks:
            return []

        for i, block in enumerate(pem_blocks):
            try:
                cert  = x509.load_pem_x509_certificate(block)
                pub   = cert.public_key()
                label = "Leaf cert" if i == 0 else f"Chain cert #{i}"

                # Algorithm from public key
                if isinstance(pub, rsa.RSAPublicKey):
                    bits = pub.key_size
                    qs, risk, repl = _rsa_risk(bits)
                    algo = f"RSA-{bits}"
                elif isinstance(pub, ec.EllipticCurvePublicKey):
                    curve = pub.curve.name
                    qs, risk, repl = _ec_risk(curve)
                    algo = f"ECDSA-{curve}"
                elif isinstance(pub, dsa.DSAPublicKey):
                    qs, risk, repl = _dsa_risk(pub.key_size)
                    algo = f"DSA-{pub.key_size}"
                elif isinstance(pub, ed25519.Ed25519PublicKey):
                    algo, qs, risk = "Ed25519", "VULNERABLE", "MEDIUM"
                    repl = "ML-DSA-65 (FIPS 204)"
                else:
                    algo, qs, risk, repl = "UNKNOWN", "MONITOR", "LOW", None

                # Signature hash
                try:
                    sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
                    hqs, hrisk = _hash_risk(sig_hash)
                    # Escalate if hash is weak
                    if hrisk == "CRITICAL" and risk not in ("CRITICAL",):
                        risk = "CRITICAL"
                        qs   = "BROKEN"
                except Exception:
                    sig_hash = "unknown"

                # Expiry
                try:
                    not_after    = cert.not_valid_after_utc
                    not_before   = cert.not_valid_before_utc
                    expiry_status = _cert_expiry_risk(not_after)
                    if expiry_status in ("EXPIRED", "EXPIRES_SOON") and risk != "CRITICAL":
                        risk = "CRITICAL"
                    not_after_str  = not_after.strftime("%Y-%m-%d")
                    not_before_str = not_before.strftime("%Y-%m-%d")
                except Exception:
                    not_after_str = not_before_str = expiry_status = None

                # Subject / Issuer
                def _dn(name):
                    try: return name.rfc4514_string()
                    except: return str(name)

                subject = _dn(cert.subject)
                issuer  = _dn(cert.issuer)
                serial  = str(cert.serial_number)

                findings.append(SecretFinding(
                    file_path        = rel_path,
                    finding_type     = "TLS_CERT",
                    algorithm        = algo,
                    quantum_status   = qs,
                    risk_level       = risk,
                    nist_replacement = repl,
                    subject          = subject[:120] if subject else None,
                    issuer           = issuer[:120]  if issuer  else None,
                    not_before       = not_before_str,
                    not_after        = not_after_str,
                    expiry_status    = expiry_status,
                    serial           = serial[:32],
                    context          = f"{label} | {algo} | sig: {sig_hash} | expires: {not_after_str}",
                ))
            except Exception as e:
                logger.debug(f"Cert parse error in {rel_path}: {e}")

        return findings

    # ── PKCS#12 ───────────────────────────────────────────────────────────────
    def _scan_pkcs12(self, fpath, rel_path):
        if not self._has_crypto:
            return [SecretFinding(rel_path, "PKCS12",
                                  "UNKNOWN", context="PKCS12 file found (install cryptography lib for details)")]
        try:
            from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12
            with open(fpath, "rb") as f:
                data = f.read()
            try:
                p12 = load_pkcs12(data, password=None)
            except Exception:
                return [SecretFinding(rel_path, "PKCS12", "ENCRYPTED-P12",
                                      quantum_status="UNKNOWN", risk_level="MEDIUM",
                                      context="PKCS12 bundle is password-protected — inspect manually")]
            findings = []
            if p12.cert:
                findings.extend(self._parse_x509(p12.cert.certificate, rel_path, "PKCS12"))
            for ac in (p12.additional_certs or []):
                findings.extend(self._parse_x509(ac.certificate, rel_path, "PKCS12-CHAIN"))
            return findings
        except Exception as e:
            return [SecretFinding(rel_path, "PKCS12", "UNKNOWN", error=str(e))]

    def _parse_x509(self, cert, rel_path, ftype):
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            bits = pub.key_size
            qs, risk, repl = _rsa_risk(bits)
            algo = f"RSA-{bits}"
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            curve = pub.curve.name
            qs, risk, repl = _ec_risk(curve)
            algo = f"ECDSA-{curve}"
        elif isinstance(pub, ed25519.Ed25519PublicKey):
            algo, qs, risk, repl = "Ed25519", "VULNERABLE", "MEDIUM", "ML-DSA-65 (FIPS 204)"
        else:
            algo, qs, risk, repl = "UNKNOWN", "MONITOR", "LOW", None
        try:
            not_after     = cert.not_valid_after_utc
            expiry_status = _cert_expiry_risk(not_after)
            not_after_str = not_after.strftime("%Y-%m-%d")
        except Exception:
            not_after_str = expiry_status = None
        return [SecretFinding(rel_path, ftype, algo,
                              quantum_status=qs, risk_level=risk, nist_replacement=repl,
                              subject=cert.subject.rfc4514_string()[:120],
                              not_after=not_after_str, expiry_status=expiry_status,
                              context=f"{algo} | expires: {not_after_str}")]

    # ── GPG / PGP ─────────────────────────────────────────────────────────────
    def _scan_gpg(self, fpath, rel_path):
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read(2048)
        except Exception:
            return []
        if "PGP" not in text and "GPG" not in text:
            return []
        # GPG keys in the wild are usually RSA-2048/4096 or ECDSA
        algo = "RSA-2048"  # conservative assumption
        if "nistp256" in text.lower() or "ecdsa" in text.lower():
            algo = "ECDSA-P256"
        return [SecretFinding(rel_path, "GPG_KEY", algo,
                              quantum_status="VULNERABLE", risk_level="HIGH",
                              nist_replacement="ML-DSA-65 (FIPS 204)",
                              context="GPG/PGP key file — verify algorithm with gpg --list-keys")]

    # ── SSH config ────────────────────────────────────────────────────────────
    def _scan_ssh_config(self, fpath, rel_path):
        findings = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception:
            return []

        for pattern, key in SSH_CONFIG_PATTERNS:
            for match in pattern.finditer(text):
                value    = match.group(1).strip()
                line_num = text[:match.start()].count("\n") + 1
                risk     = "LOW"
                qs       = "SAFE"
                repl     = None

                # Flag weak algorithms in config values
                val_lower = value.lower()
                if any(x in val_lower for x in ["rsa","dss","dsa","diffie-hellman",
                                                 "ecdh","ecdsa","nistp256","nistp384","nistp521"]):
                    risk = "HIGH"; qs = "VULNERABLE"
                    repl = "Use ML-KEM / ML-DSA (FIPS 203/204) hybrid; interim: curve25519-sha256"
                if any(x in val_lower for x in ["arcfour","rc4","des","blowfish","cast128"]):
                    risk = "CRITICAL"; qs = "BROKEN"
                    repl = "Use aes256-gcm@openssh.com or chacha20-poly1305@openssh.com"
                if "md5" in val_lower or "sha1" in val_lower:
                    risk = "HIGH"; qs = "WEAK"
                    repl = "Use hmac-sha2-256 or hmac-sha2-512"
                if any(x in val_lower for x in ["aes128","aes-128","3des","aes192"]):
                    if risk == "LOW":  # don't downgrade CRITICAL/BROKEN findings
                        risk = "MEDIUM"; qs = "MONITOR"
                        repl = "Prefer aes256-gcm@openssh.com or chacha20-poly1305@openssh.com"

                findings.append(SecretFinding(
                    file_path      = rel_path,
                    finding_type   = "SSH_CONFIG",
                    algorithm      = key,
                    quantum_status = qs,
                    risk_level     = risk,
                    nist_replacement = repl,
                    config_key     = key,
                    config_value   = value[:200],
                    context        = f"Line {line_num}: {key} = {value[:80]}",
                ))
        return findings
