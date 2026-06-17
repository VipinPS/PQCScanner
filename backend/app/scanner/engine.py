"""
PQC Scanner Engine — Multi-language crypto discovery + Agility scoring + Hybrid detection
"""
import re, os, tempfile, subprocess, shutil
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# ── Algorithm registry ────────────────────────────────────────────────────────
ALGORITHM_REGISTRY = {
    "MD5": {
        "type": "Hash", "quantum_status": "BROKEN", "risk": "CRITICAL",
        "nist_replacement": "SHA-3-256",
        "patterns": [
            r"\bMD5\b",
            r"hashlib\.md5",
            r"MessageDigest\.getInstance\(['\"]MD5['\"]",
            r"DigestUtils\.md5",
            r"crypto\.createHash\(['\"]md5['\"]",
            r"MD5Digest",
            # C/C++ OpenSSL
            r"\bMD5\s*\(",
            r"\bMD5_(?:Init|Update|Final)\s*\(",
            r"\bMD5_CTX\b",
            r"\bEVP_md5\s*\(",
            r"\bMD5_DIGEST_LENGTH\b",
            # C# System.Security.Cryptography
            r"MD5\.Create\(\)",
            r"new MD5CryptoServiceProvider\(\)",
            r"MD5Cng\b",
            # Dart package:crypto
            r"\bmd5\.convert\b",
            r"Hmac\(md5\b",
        ],
    },
    "SHA-1": {
        "type": "Hash", "quantum_status": "WEAK", "risk": "HIGH",
        "nist_replacement": "SHA-3-256",
        "patterns": [
            r"\bSHA[-_]?1\b",
            r"hashlib\.sha1",
            r"MessageDigest\.getInstance\(['\"]SHA-1['\"]",
            r"crypto\.createHash\(['\"]sha1['\"]",
            r"DigestUtils\.sha1",
            # C/C++ OpenSSL
            r"\bSHA1\s*\(",
            r"\bSHA1_(?:Init|Update|Final)\s*\(",
            r"\bSHA1_CTX\b",
            r"\bEVP_sha1\s*\(",
            r"\bSHA_DIGEST_LENGTH\b",
            # C# System.Security.Cryptography
            r"SHA1\.Create\(\)",
            r"new SHA1CryptoServiceProvider\(\)",
            r"SHA1Managed\b",
            r"SHA1Cng\b",
            # Dart package:crypto
            r"\bsha1\.convert\b",
            r"Hmac\(sha1\b",
        ],
    },
    "DES": {
        "type": "Symmetric", "quantum_status": "BROKEN", "risk": "CRITICAL",
        "nist_replacement": "AES-256-GCM",
        "patterns": [
            r"\bDESede\b", r"\b3DES\b", r"\bTripleDES\b",
            r"Cipher\.getInstance\(['\"]DES", r"\bDESKeySpec\b",
            # C# System.Security.Cryptography
            r"DES\.Create\(\)", r"TripleDES\.Create\(\)",
            r"new DESCryptoServiceProvider\(\)",
            r"new TripleDESCryptoServiceProvider\(\)",
            # C/C++ OpenSSL
            r"\bDES_set_key\b", r"\bDES_(?:ecb|cbc|ede3)_encrypt\b",
            r"\bDES_cblock\b", r"\bDES_key_schedule\b",
            r"\bEVP_des_", r"\bEVP_des_ede3?_",
            # mbedTLS / wolfSSL
            r"\bmbedtls_des3?_", r"\bwc_Des3?_",
        ],
    },
    "RSA-1024": {
        "type": "Asymmetric", "quantum_status": "BROKEN", "risk": "CRITICAL",
        "nist_replacement": "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
        "patterns": [
            r"RSA\.generate\(1024", r"KeyPairGenerator.*1024",
            r"generateKeyPair.*1024",
            # C# RSACryptoServiceProvider with key size
            r"new RSACryptoServiceProvider\(1024\)",
            r"RSA\.Create\(1024\)",
            # Bouncy Castle Java
            r"RsaKeyGenerationParameters.*1024",
            # C/C++ OpenSSL / mbedTLS / wolfSSL
            r"RSA_generate_key(?:_ex)?\([^;]*?\b1024\b",
            r"EVP_PKEY_CTX_set_rsa_keygen_bits\([^,]*,\s*1024\s*\)",
            r"mbedtls_rsa_gen_key\([^;]*?\b1024\b",
            r"wc_MakeRsaKey\([^,]*,\s*1024",
        ],
    },
    "RSA-2048": {
        "type": "Asymmetric", "quantum_status": "VULNERABLE", "risk": "CRITICAL",
        "nist_replacement": "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
        "patterns": [
            r"RSA\.generate\(2048", r"KeyPairGenerator.*2048",
            r"RSAKeySize\.RSA_2048", r"KeySize\(2048\)",
            r"default_bits\s*=\s*2048",
            # C#
            r"new RSACryptoServiceProvider\(2048\)",
            r"RSA\.Create\(2048\)",
            # Bouncy Castle Java
            r"RsaKeyGenerationParameters.*2048",
            # C/C++ OpenSSL / mbedTLS / wolfSSL
            r"RSA_generate_key(?:_ex)?\([^;]*?\b2048\b",
            r"EVP_PKEY_CTX_set_rsa_keygen_bits\([^,]*,\s*2048\s*\)",
            r"mbedtls_rsa_gen_key\([^;]*?\b2048\b",
            r"wc_MakeRsaKey\([^,]*,\s*2048",
        ],
    },
    "RSA-4096": {
        "type": "Asymmetric", "quantum_status": "VULNERABLE", "risk": "HIGH",
        "nist_replacement": "ML-KEM-1024 (FIPS 203) / ML-DSA-87 (FIPS 204)",
        "patterns": [
            r"RSA\.generate\(4096", r"KeyPairGenerator.*4096",
            r"new RSACryptoServiceProvider\(4096\)",
            r"RSA\.Create\(4096\)",
            r"RsaKeyGenerationParameters.*4096",
            # C/C++ OpenSSL / mbedTLS / wolfSSL
            r"RSA_generate_key(?:_ex)?\([^;]*?\b4096\b",
            r"EVP_PKEY_CTX_set_rsa_keygen_bits\([^,]*,\s*4096\s*\)",
            r"mbedtls_rsa_gen_key\([^;]*?\b4096\b",
            r"wc_MakeRsaKey\([^,]*,\s*4096",
        ],
    },
    "ECDSA": {
        "type": "Signature", "quantum_status": "VULNERABLE", "risk": "HIGH",
        "nist_replacement": "ML-DSA-65 (FIPS 204)",
        "patterns": [
            r"\bECDSA\b", r"ec\.generate_private_key",
            r"\bES256\b", r"\bES384\b", r"\bES512\b",
            # C# System.Security.Cryptography
            r"ECDsa\.Create\(\)", r"new ECDsaCng\(",
            r"ECDsaOpenSsl\b",
            # Bouncy Castle Java
            r"ECKeyPairGenerator\b",
            r"X9ECParameters\b",
            # C/C++ OpenSSL / mbedTLS / wolfSSL
            r"\bECDSA_(?:sign|verify|do_sign|do_verify|SIG_new)\b",
            r"\bEC_KEY_(?:new|generate_key)\b",
            r"\bEVP_PKEY_EC\b",
            r"\bmbedtls_ecdsa_",
            r"\bwc_ecc_(?:sign_hash|verify_hash|make_key)\b",
        ],
    },
    "ECDH": {
        "type": "KEM", "quantum_status": "VULNERABLE", "risk": "HIGH",
        "nist_replacement": "ML-KEM-768 (FIPS 203)",
        "patterns": [
            r"\bECDH\b", r"\bECDHE\b", r"ECDHE-RSA-",
            r"KeyAgreement.*ECDH", r"ecdh\.computeSecret",
            # C# System.Security.Cryptography
            r"ECDiffieHellman\.Create\(\)", r"new ECDiffieHellmanCng\(",
            # Bouncy Castle Java
            r"ECDHBasicAgreement\b", r"ECDHCBasicAgreement\b",
            # C/C++ OpenSSL / mbedTLS / wolfSSL
            r"\bECDH_compute_key\b",
            r"\bmbedtls_ecdh_",
            r"\bwc_ecc_shared_secret\b",
        ],
    },
    "X25519": {
        "type": "KEM", "quantum_status": "VULNERABLE", "risk": "MEDIUM",
        "nist_replacement": "ML-KEM-768 hybrid (FIPS 203)",
        "patterns": [
            r"\bX25519\b", r"X25519PrivateKey",
            # Dart package:cryptography
            r"X25519\(\)",
            # C/C++ OpenSSL / mbedTLS / wolfSSL
            r"\bEVP_PKEY_X25519\b", r"\bNID_X25519\b",
            r"\bMBEDTLS_ECP_DP_CURVE25519\b",
            r"\bwc_curve25519_",
        ],
    },
    "AES-128": {
        "type": "Symmetric", "quantum_status": "MONITOR", "risk": "MEDIUM",
        "nist_replacement": "AES-256-GCM",
        "patterns": [
            r"AES.{0,5}128", r"KeyGenerator.*128.*AES",
            # C# — Aes.Create() defaults to 128-bit; flag explicit 128
            r"\.KeySize\s*=\s*128",
            # Dart package:cryptography — AesCbc/AesCtr default to 128-bit
            r"\bAesCbc\(\)", r"\bAesCtr\(\)",
            # C/C++ OpenSSL / mbedTLS / wolfSSL
            r"\bEVP_aes_128_\w+\b",
            r"AES_set_encrypt_key\([^,]*,\s*128",
            r"mbedtls_aes_setkey_enc\([^,]*,[^,]*,\s*128",
            r"wc_AesSetKey\([^,]*,\s*16\b",
        ],
    },
    "TLS-1.0": {
        "type": "Protocol", "quantum_status": "BROKEN", "risk": "CRITICAL",
        "nist_replacement": "TLS 1.3 + ML-KEM hybrid",
        "patterns": [r"TLSv1\b(?!\.)", r"TLSv1\.0",
                     r"ssl\.PROTOCOL_TLSv1\b", r"TLS_1_0",
                     # C/C++ OpenSSL
                     r"\bTLS1_VERSION\b", r"\bTLSv1_(?:client_|server_)?method\b"],
    },
    "TLS-1.1": {
        "type": "Protocol", "quantum_status": "WEAK", "risk": "HIGH",
        "nist_replacement": "TLS 1.3 + ML-KEM hybrid",
        "patterns": [r"TLSv1\.1", r"ssl\.PROTOCOL_TLSv1_1", r"TLS_1_1",
                     # C/C++ OpenSSL
                     r"\bTLS1_1_VERSION\b", r"\bTLSv1_1_(?:client_|server_)?method\b"],
    },
    "TLS-1.2": {
        "type": "Protocol", "quantum_status": "MONITOR", "risk": "MEDIUM",
        "nist_replacement": "TLS 1.3 + ML-KEM hybrid",
        "patterns": [r"TLSv1\.2", r"ssl\.PROTOCOL_TLSv1_2", r"TLS_1_2",
                     r"sslVersion\s*=\s*TLSv1\.2",
                     # C/C++ OpenSSL
                     r"\bTLS1_2_VERSION\b", r"\bTLSv1_2_(?:client_|server_)?method\b"],
    },
    "RC4": {
        "type": "Symmetric", "quantum_status": "BROKEN", "risk": "CRITICAL",
        "nist_replacement": "AES-256-GCM or ChaCha20-Poly1305",
        "patterns": [
            r"\bRC4\b", r"\bARCFOUR\b",
            r"Cipher\.getInstance\(['\"]RC4",
            # C# System.Security.Cryptography
            r"RC2\.Create\(\)", r"new RC2CryptoServiceProvider\(\)",
            # C/C++ OpenSSL / mbedTLS / wolfSSL
            r"\bRC4_set_key\b", r"\bEVP_rc4\b",
            r"\bmbedtls_arc4_", r"\bwc_Arc4",
        ],
    },
    "PBKDF2": {
        "type": "KDF", "quantum_status": "MONITOR", "risk": "MEDIUM",
        "nist_replacement": "Argon2id",
        "patterns": [
            r"\bPBKDF2\b", r"pbkdf2_hmac", r"PBKDF2WithHmac",
            # C# System.Security.Cryptography
            r"new Rfc2898DeriveBytes\b",
            r"Rfc2898DeriveBytes\.Pbkdf2\b",
            # C/C++ OpenSSL / mbedTLS / wolfSSL
            r"\bPKCS5_PBKDF2_HMAC\b",
            r"\bmbedtls_pkcs5_pbkdf2_hmac\b",
            r"\bwc_PBKDF2\b",
        ],
    },
    "JWT-RS256": {
        "type": "Signature", "quantum_status": "VULNERABLE", "risk": "HIGH",
        "nist_replacement": "JWT with ML-DSA-65 (FIPS 204)",
        "patterns": [
            r"['\"]RS256['\"]", r"['\"]RS384['\"]", r"['\"]RS512['\"]",
            # Nimbus JOSE + JWT (Java)
            r"JWSAlgorithm\.RS256\b", r"JWSAlgorithm\.RS384\b", r"JWSAlgorithm\.RS512\b",
            # JJWT
            r"SignatureAlgorithm\.RS256\b",
        ],
    },
    "HARDCODED-KEY": {
        "type": "KeyMgmt", "quantum_status": "WEAK", "risk": "CRITICAL",
        "nist_replacement": "Use HSM or key management service (e.g. AWS KMS, HashiCorp Vault)",
        "patterns": [r"-----BEGIN RSA PRIVATE KEY-----",
                     r"-----BEGIN EC PRIVATE KEY-----",
                     r"-----BEGIN PRIVATE KEY-----",
                     # ZeroMQ CURVE hardcoded keys
                     r"(?:PRODUCTION|TEST|PUBLIC|PRIVATE)_(?:PUBLIC|PRIVATE)?_?(?:CURVE|ZMQ)_KEY\s*=\s*['\"]",
                     r"curve_(?:public|private|server|client)_key\s*=\s*['\"]",
        ],
    },
    "BLOWFISH": {
        "type": "Symmetric", "quantum_status": "BROKEN", "risk": "CRITICAL",
        "nist_replacement": "AES-256-GCM",
        "patterns": [
            r"\bBlowfish\b",
            r"\bbf-(?:cbc|ecb|cfb|ofb)\b",
            r"Cipher\.getInstance\(['\"]Blowfish",
            r"\bEVP_bf_",
        ],
    },
    "RSA-KEYGEN-CLI": {
        "type": "Asymmetric", "quantum_status": "VULNERABLE", "risk": "CRITICAL",
        "nist_replacement": "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
        "patterns": [
            # ssh-keygen with RSA/DSA type (shell scripts and Python strings)
            r"ssh-keygen\s+[^'\"\n]*-t\s+rsa",
            r"ssh-keygen\s+[^'\"\n]*-t\s+dsa",
            # variable-wrapped keygen: $SSHKEYGEN -b 2048 -t rsa -f ...
            r"\$\w+\s+[^'\"\n]*-t\s+(?:rsa|dsa)",
            # flags in any order: -b <size> ... -t rsa  or  -t rsa ... -b <size>
            r"-b\s+(?:512|1024|2048|3072|4096)\s+[^'\"\n]*-t\s+rsa",
            r"-t\s+rsa\s+[^'\"\n]*-b\s+(?:512|1024|2048|3072|4096)",
            # openssl RSA key generation
            r"openssl\s+genrsa\b",
            r"openssl\s+genpkey\s+[^'\"\n]*-algorithm\s+rsa",
            # openssl self-signed cert (shell heredoc / scripts)
            r"openssl\s+req\s+[^'\"\n]*-x509",
            # openssl DH parameter generation (classical DH, quantum-vulnerable)
            r"openssl\s+dhparam\b",
        ],
    },
    "CRYPTSETUP-WEAK-KDF": {
        "type": "KDF", "quantum_status": "MONITOR", "risk": "HIGH",
        "nist_replacement": "Use --pbkdf=argon2id with cryptsetup",
        "patterns": [
            r"--pbkdf[=\s]+pbkdf2",
            r"cryptsetup\b[^'\"\n]*--pbkdf",
        ],
    },
    "AES-XTS": {
        "type": "Symmetric", "quantum_status": "MONITOR", "risk": "MEDIUM",
        "nist_replacement": "AES-256-GCM (authenticated encryption preferred over XTS for non-disk use)",
        "patterns": [
            r"\baes-xts-plain\b",
            r"\baes-\d+-xts\b",
            r"--cipher\s+aes-xts",
        ],
    },
    "SSH-WEAK-KEX": {
        "type": "Protocol", "quantum_status": "VULNERABLE", "risk": "HIGH",
        "nist_replacement": "Use sntrup761x25519-sha512@openssh.com or mlkem768x25519-sha256 in KexAlgorithms",
        "patterns": [
            # KexAlgorithms line containing classic ECDH or DH groups (sshd_config / ssh_config)
            r"(?m)^KexAlgorithms\s+[^\n]*(?:ecdh-sha2-nistp|diffie-hellman-group)",
        ],
    },

    # ── PQC-safe algorithms (SAFE status — already migrated code) ────────────
    "ML-KEM-512": {
        "type": "KEM", "quantum_status": "SAFE", "risk": "LOW",
        "nist_replacement": "Already NIST FIPS 203 compliant (128-bit quantum security)",
        "patterns": [
            r"\bML[-_]?KEM[-_]?512\b", r"\bMLKEM512\b",
            r"kyber512\b",                           # pre-FIPS naming
            r"Kyber512",
            r"MLKEMParameters\.ML_KEM_512",          # Bouncy Castle
        ],
    },
    "ML-KEM-768": {
        "type": "KEM", "quantum_status": "SAFE", "risk": "LOW",
        "nist_replacement": "Already NIST FIPS 203 compliant (192-bit quantum security)",
        "patterns": [
            r"\bML[-_]?KEM[-_]?768\b", r"\bMLKEM768\b",
            r"kyber768\b",
            r"Kyber768",
            r"MLKEMParameters\.ML_KEM_768",
            r"sntrup761",                            # OpenSSH hybrid uses this
        ],
    },
    "ML-KEM-1024": {
        "type": "KEM", "quantum_status": "SAFE", "risk": "LOW",
        "nist_replacement": "Already NIST FIPS 203 compliant (256-bit quantum security)",
        "patterns": [
            r"\bML[-_]?KEM[-_]?1024\b", r"\bMLKEM1024\b",
            r"kyber1024\b",
            r"Kyber1024",
            r"MLKEMParameters\.ML_KEM_1024",
        ],
    },
    "ML-DSA-44": {
        "type": "Signature", "quantum_status": "SAFE", "risk": "LOW",
        "nist_replacement": "Already NIST FIPS 204 compliant (128-bit quantum security)",
        "patterns": [
            r"\bML[-_]?DSA[-_]?44\b", r"\bMLDSA44\b",
            r"dilithium2\b", r"Dilithium2",
            r"MLDSAParameters\.ML_DSA_44",
        ],
    },
    "ML-DSA-65": {
        "type": "Signature", "quantum_status": "SAFE", "risk": "LOW",
        "nist_replacement": "Already NIST FIPS 204 compliant (192-bit quantum security)",
        "patterns": [
            r"\bML[-_]?DSA[-_]?65\b", r"\bMLDSA65\b",
            r"dilithium3\b", r"Dilithium3",
            r"MLDSAParameters\.ML_DSA_65",
            r"mldsa65",
        ],
    },
    "ML-DSA-87": {
        "type": "Signature", "quantum_status": "SAFE", "risk": "LOW",
        "nist_replacement": "Already NIST FIPS 204 compliant (256-bit quantum security)",
        "patterns": [
            r"\bML[-_]?DSA[-_]?87\b", r"\bMLDSA87\b",
            r"dilithium5\b", r"Dilithium5",
            r"MLDSAParameters\.ML_DSA_87",
            r"mldsa87",
        ],
    },
    "SLH-DSA": {
        "type": "Signature", "quantum_status": "SAFE", "risk": "LOW",
        "nist_replacement": "Already NIST FIPS 205 compliant (hash-based, stateless)",
        "patterns": [
            r"\bSLH[-_]?DSA\b",
            r"\bSPHINCS\+\b", r"\bsphincsplus\b", r"\bsphincs_plus\b",
            r"SLHDSAParameters\.",                  # Bouncy Castle
            r"slh_dsa", r"slhdsa",
        ],
    },
}

# ── Non-cryptographic algorithm exclusions ────────────────────────────────────
# Lines matching any of these patterns are skipped during agility scoring
# to avoid false positives from scheduling, routing, sorting, etc.
NON_CRYPTO_ALGORITHMS = re.compile(
    r"LoadSchedulingAlgorithm|RoutingAlgorithm|SortingAlgorithm|"
    r"CompressionAlgorithm|CachingAlgorithm|LoadBalanc|Scheduling",
    re.IGNORECASE,
)

# ── Agility signal patterns ───────────────────────────────────────────────────
# Each entry: (regex, level_bump, description)
# Positive signals push the maturity level UP, negative push it DOWN
AGILITY_SIGNALS = [
    # L5 — per-request negotiation
    (r"alg_negotiat|AlgorithmNegotiat|negotiateAlgorithm",          +4, "Algorithm negotiation detected (L5)"),
    # L4 — hybrid classical+PQC running simultaneously
    (r"HybridKEM|hybrid_kem|X25519MLKEM|X25519Kyber|hybrid.*pqc|pqc.*hybrid", +3, "Hybrid KEM detected (L4)"),
    (r"ML[-_]?KEM|MLKEM|kyber|dilithium|ML[-_]?DSA|MLDSA|CRYSTALS", +3, "PQC algorithm in use (L4+)"),
    (r"mlkem|ml_kem|fips[-_]?203|fips[-_]?204",                     +3, "NIST FIPS 203/204 in use"),
    # L3 — registry / hot-swap pattern
    (r"CryptoRegistry|CryptoProvider|AlgorithmRegistry|AlgorithmProvider", +2, "Crypto registry pattern (L3)"),
    (r"registerAlgorithm|register_algorithm|registry\.get\(",        +2, "Algorithm registry usage (L3)"),
    # L2 — config-driven
    (r"algorithm.*config|config.*algorithm|crypto.*config|CRYPTO_ALGO", +1, "Config-driven algorithm (L2)"),
    (r"alg_fallback|algorithm_fallback|fallback.*alg",               +1, "Fallback algorithm defined (L2)"),
    # Negative signals — hardcoded = drags toward L1
    (r"-----BEGIN RSA PRIVATE KEY-----|-----BEGIN EC PRIVATE KEY-----", -3, "Hardcoded private key (L1 signal)"),
    (r"RSA\.generate\(1024|RSA\.generate\(512",                      -2, "Weak hardcoded RSA size (L1 signal)"),
]

# ── Hybrid detection patterns ─────────────────────────────────────────────────
HYBRID_PATTERNS = [
    (r"X25519.*ML[-_]?KEM|ML[-_]?KEM.*X25519",     "X25519+ML-KEM hybrid KEM"),
    (r"HybridKEM|hybrid_kem",                        "Hybrid KEM implementation"),
    (r"X25519Kyber|Kyber.*X25519",                   "X25519+Kyber hybrid (pre-FIPS)"),
    (r"classical.*pqc|pqc.*classical",               "Classical+PQC hybrid pattern"),
    (r"CRYSTALS.*Dilithium|Dilithium.*CRYSTALS",     "CRYSTALS-Dilithium (pre-FIPS ML-DSA)"),
    (r"kyber512|kyber768|kyber1024",                 "Kyber KEM (pre-FIPS ML-KEM)"),
    (r"dilithium2|dilithium3|dilithium5",            "Dilithium signature (pre-FIPS ML-DSA)"),
    (r"SPHINCS\+|sphincsplus|slh.dsa",               "SLH-DSA / SPHINCS+ signature"),
    (r"alg_fallback.*RS256|RS256.*alg_fallback",     "JWT PQC+RSA fallback"),
    (r"TLS_KYBER|kyber.*tls|tls.*kyber",             "TLS Kyber hybrid"),
]

LANGUAGE_EXTENSIONS = {
    "python":     [".py"],
    "java":       [".java"],
    "go":         [".go"],
    "typescript": [".ts", ".tsx"],
    "javascript": [".js", ".jsx", ".mjs"],
    "kotlin":     [".kt", ".kts"],
    "rust":       [".rs"],
    "cpp":        [".cpp", ".cc", ".cxx", ".c++", ".h", ".hpp", ".hxx", ".h++", ".c"],
    "csharp":     [".cs"],
    "dart":       [".dart"],
    "ruby":       [".rb"],
    "swift":      [".swift"],
    "yaml":       [".yml", ".yaml"],
    "config":     [".conf", ".cfg", ".ini", ".toml", ".env"],
    "shell":      [".sh", ".bash", ".zsh", ".ksh"],
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", "vendor", "target",
}

# Paths matching these patterns are test/fixture/example/vendor code — crypto
# usage there carries little production risk and is a common source of false
# positives (shared by the scanner's path-based FP heuristic and agility scoring).
TEST_PATH_PATTERN = re.compile(
    r"(^|/)test[s_]?/|/spec/|_test\.|_spec\.|test_|spec_"
    r"|\.test\.|\.spec\.|/mock/|/mocks/|/fixture/|/fixtures/"
    r"|/examples?/|/sample/|/demo/|/docs?/",
    re.IGNORECASE
)
VENDOR_PATH_PATTERN = re.compile(
    r"(^|/)(vendor|third.?party|extern|generated|auto.?gen"
    r"|\.cache|node_modules|__pycache__|dist|build)/",
    re.IGNORECASE
)

# ── Data classes ──────────────────────────────────────────────────────────────
CONTEXT_LINES = 10   # lines captured before AND after the finding line

@dataclass
class ScanFinding:
    file_path:          str
    line_number:        int
    algorithm:          str
    algo_type:          str
    context:            str
    risk_level:         str
    quantum_status:     str
    quantum_safe:       bool
    nist_replacement:   Optional[str] = None
    context_start_line: int = 1       # 1-indexed line number of first context line
    in_test_path:       bool = False  # file path matches test/fixture/example/vendor patterns

@dataclass
class HybridSignal:
    file_path:   str
    line_number: int
    pattern:     str
    description: str
    context:     str

@dataclass
class AgilityResult:
    level:           int          # 1–5
    label:           str          # Hardcoded / Configurable / Hot-Swap / Hybrid / Fully Agile
    score:           int          # raw score before clamping
    signals:         list         # list of (description, file, line) tuples found
    hybrid_signals:  list         # list of HybridSignal
    has_hybrid:      bool

@dataclass
class ScanResult:
    repo_path:      str
    total_files:    int   = 0
    scanned_files:  int   = 0
    findings:       list  = field(default_factory=list)
    errors:         list  = field(default_factory=list)
    language_stats: dict  = field(default_factory=dict)
    agility:        Optional[AgilityResult] = None

# ── Scanner ───────────────────────────────────────────────────────────────────
class CryptoScanner:
    def __init__(self, progress_callback=None):
        self.progress_callback = progress_callback
        self._compiled = {
            algo: [re.compile(p, re.IGNORECASE | re.MULTILINE)
                   for p in info["patterns"]]
            for algo, info in ALGORITHM_REGISTRY.items()
        }
        self._agility_compiled = [
            (re.compile(pat, re.IGNORECASE | re.MULTILINE), bump, desc)
            for pat, bump, desc in AGILITY_SIGNALS
        ]
        self._hybrid_compiled = [
            (re.compile(pat, re.IGNORECASE | re.MULTILINE), desc)
            for pat, desc in HYBRID_PATTERNS
        ]

    def scan_directory(self, root_path: str) -> ScanResult:
        result = ScanResult(repo_path=root_path)
        all_files = self._collect_files(root_path)
        result.total_files = len(all_files)

        for i, fpath in enumerate(all_files):
            try:
                findings = self._scan_file(fpath, root_path)
                result.findings.extend(findings)
                result.scanned_files += 1
                ext = Path(fpath).suffix.lower()
                result.language_stats[ext] = result.language_stats.get(ext, 0) + 1
                if self.progress_callback:
                    self.progress_callback(i + 1, result.total_files)
            except Exception as e:
                result.errors.append(f"{fpath}: {e}")

        # Agility scoring pass — runs over entire codebase, aware of findings
        result.agility = self._score_agility(root_path, all_files, result.findings)
        return result

    # SSH server/client config files have no extension — match by name
    SSH_CONFIG_NAMES = {"sshd_config", "ssh_config"}

    def _collect_files(self, root: str) -> list:
        files = []
        all_exts = {ext for exts in LANGUAGE_EXTENSIONS.values() for ext in exts}
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fname in filenames:
                if (Path(fname).suffix.lower() in all_exts
                        or fname in self.SSH_CONFIG_NAMES):
                    files.append(os.path.join(dirpath, fname))
        return files

    def _scan_file(self, filepath: str, root: str) -> list:
        findings = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines   = content.splitlines()
        except Exception:
            return findings

        rel_path = os.path.relpath(filepath, root)
        seen     = set()
        in_test_path = bool(TEST_PATH_PATTERN.search(rel_path) or VENDOR_PATH_PATTERN.search(rel_path))

        for algo, compiled_patterns in self._compiled.items():
            info = ALGORITHM_REGISTRY[algo]
            for pattern in compiled_patterns:
                for match in pattern.finditer(content):
                    line_num = content[:match.start()].count("\n") + 1
                    # Deduplicate by (file, algo, line) so two patterns matching
                    # the same line don't produce duplicate findings, but
                    # different lines of the same algorithm are all reported.
                    key = (rel_path, algo, line_num)
                    if key in seen:
                        continue
                    seen.add(key)
                    start   = max(0, line_num - CONTEXT_LINES)
                    end     = min(len(lines), line_num + CONTEXT_LINES + 1)
                    context = "\n".join(lines[start:end])
                    findings.append(ScanFinding(
                        file_path          = rel_path,
                        line_number        = line_num,
                        algorithm          = algo,
                        algo_type          = info["type"],
                        context            = context,   # no truncation — full ±10 lines
                        risk_level         = info["risk"],
                        quantum_status     = info["quantum_status"],
                        quantum_safe       = info["quantum_status"] in ("SAFE", "MONITOR"),
                        nist_replacement   = info.get("nist_replacement"),
                        context_start_line = start + 1,  # 1-indexed
                        in_test_path       = in_test_path,
                    ))
        return findings

    def _score_agility(self, root: str, all_files: list, code_findings: list) -> AgilityResult:
        """
        Score repo agility L1–L5 with four correctness rules:

        Rule 1 — Test/vendor/doc files carry zero agility weight.
                 A registry pattern in test_crypto.py is not proof of agility.

        Rule 2 — Negative signals anchor the minimum level.
                 Hardcoded private keys → score floored to ≤ 0 (L1).
                 Weak RSA sizes → score capped at +2 max (L2).

        Rule 3 — Critical finding count caps the maximum level.
                 ≥ 10 CRITICAL findings → max L2  (configurable at best)
                 1–9  CRITICAL findings → max L3  (hot-swap possible but not there yet)
                 0    CRITICAL findings → max L5  (no cap applied)

        Rule 4 — Hybrid PQC signals only count in non-test production files.
        """
        # ── Classify files ────────────────────────────────────────────────────
        prod_files = []
        for fpath in all_files:
            rel = os.path.relpath(fpath, root)
            if TEST_PATH_PATTERN.search(rel) or VENDOR_PATH_PATTERN.search(rel):
                continue
            prod_files.append(fpath)

        # ── Count CRITICAL findings in production files only ──────────────────
        critical_count = sum(
            1 for f in code_findings
            if f.risk_level == "CRITICAL"
            and not TEST_PATH_PATTERN.search(f.file_path)
            and not VENDOR_PATH_PATTERN.search(f.file_path)
        )

        # ── Scan production files for agility signals ─────────────────────────
        score          = 0
        signals_found  = []
        hybrid_signals = []
        has_hardcoded_key = False
        has_weak_rsa      = False

        for fpath in prod_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
                    lines   = content.splitlines()
            except Exception:
                continue

            rel_path = os.path.relpath(fpath, root)

            for compiled, bump, desc in self._agility_compiled:
                for match in compiled.finditer(content):
                    line_num = content[:match.start()].count("\n") + 1
                    line_text = lines[line_num - 1] if line_num <= len(lines) else ""
                    if NON_CRYPTO_ALGORITHMS.search(line_text):
                        continue  # skip non-cryptographic algorithm references

                    # Track negative anchors separately
                    if bump < 0:
                        if "private key" in desc.lower():
                            has_hardcoded_key = True
                        if "weak" in desc.lower() and "rsa" in desc.lower():
                            has_weak_rsa = True

                    score += bump
                    start  = max(0, line_num - 2)
                    end    = min(len(lines), line_num + 2)
                    signals_found.append({
                        "description": desc,
                        "file":        rel_path,
                        "line":        line_num,
                        "bump":        bump,
                        "context":     "\n".join(lines[start:end])[:300],
                        "source":      "production",
                    })
                    break  # one signal per pattern per file

            for compiled, desc in self._hybrid_compiled:
                for match in compiled.finditer(content):
                    line_num = content[:match.start()].count("\n") + 1
                    start    = max(0, line_num - 2)
                    end      = min(len(lines), line_num + 2)
                    hybrid_signals.append(HybridSignal(
                        file_path   = rel_path,
                        line_number = line_num,
                        pattern     = compiled.pattern,
                        description = desc,
                        context     = "\n".join(lines[start:end])[:300],
                    ))
                    break

        has_hybrid = len(hybrid_signals) > 0

        # ── Rule 2 — Negative anchors floor/cap the raw score ────────────────
        if has_hardcoded_key:
            # Hardcoded private key → score can never be positive
            score = min(score, 0)
        elif has_weak_rsa:
            # Weak RSA size → score capped at L2 range max
            score = min(score, 2)

        # ── Rule 3 — Hybrid bump only applies to production code ────────────
        if has_hybrid and score < 3:
            score = 3

        # ── Rule 3 — Critical finding count caps maximum level ───────────────
        if critical_count >= 10:
            max_level = 2   # Too many unfixed criticals → at best Configurable
        elif critical_count >= 1:
            max_level = 3   # Has criticals → at best Hot-Swap
        else:
            max_level = 5   # No criticals → no cap

        # ── Score → level mapping ─────────────────────────────────────────────
        if   score <= 0: raw_level = 1
        elif score <= 2: raw_level = 2
        elif score <= 4: raw_level = 3
        elif score <= 7: raw_level = 4
        else:            raw_level = 5

        level = min(raw_level, max_level)

        labels = {1:"Hardcoded", 2:"Configurable", 3:"Hot-Swap", 4:"Hybrid", 5:"Fully Agile"}

        # Append a cap notice to signals if the cap was applied
        if level < raw_level:
            signals_found.append({
                "description": (
                    f"⚠ Agility capped at L{level} ({labels[level]}) — "
                    f"{critical_count} CRITICAL finding{'s' if critical_count != 1 else ''} "
                    f"in production code must be resolved first"
                    if critical_count >= 1 else
                    f"⚠ Agility capped at L{level} — hardcoded key detected"
                ),
                "file":    "— scoring engine —",
                "line":    0,
                "bump":    0,
                "context": "",
                "source":  "cap",
            })

        return AgilityResult(
            level          = level,
            label          = labels[level],
            score          = score,
            signals        = signals_found,
            hybrid_signals = hybrid_signals,
            has_hybrid     = has_hybrid,
        )


# ── Agility to dict (for DB storage) ─────────────────────────────────────────
def agility_to_dict(agility: AgilityResult) -> dict:
    return {
        "agility_level":    agility.level,
        "agility_label":    agility.label,
        "agility_score":    agility.score,
        "agility_signals":  agility.signals,
        "has_hybrid":       agility.has_hybrid,
        "hybrid_signals":   [
            {"file": h.file_path, "line": h.line_number,
             "description": h.description, "context": h.context}
            for h in agility.hybrid_signals
        ],
    }


# ── CBOM builder ──────────────────────────────────────────────────────────────
def build_cbom_from_findings(findings: list) -> list:
    cbom = {}
    for f in findings:
        if f.algorithm not in cbom:
            cbom[f.algorithm] = {
                "algorithm":        f.algorithm,
                "algo_type":        f.algo_type,
                "quantum_status":   f.quantum_status,
                "nist_replacement": f.nist_replacement,
                "priority":         {"BROKEN":1,"VULNERABLE":1,"WEAK":2,"MONITOR":3,"SAFE":5}.get(f.quantum_status, 3),
                "total_usages":     0,
                "affected_repos":   set(),
                "risk_score":       {"BROKEN":10.0,"VULNERABLE":8.5,"WEAK":6.0,"MONITOR":4.0,"SAFE":1.0}.get(f.quantum_status, 5.0),
            }
        cbom[f.algorithm]["total_usages"]   += 1
        cbom[f.algorithm]["affected_repos"].add(f.file_path.split("/")[0])
    result = []
    for entry in cbom.values():
        entry["affected_repos"] = len(entry["affected_repos"])
        result.append(entry)
    return sorted(result, key=lambda x: x["priority"])


# ── Git clone helpers ─────────────────────────────────────────────────────────
def clone_repo(url: str, token: str = "", branch: str = "main") -> str:
    tmp = tempfile.mkdtemp(prefix="pqc_scan_")
    if token:
        if "bitbucket" in url:
            # Bitbucket app password: user:app_password bare in URL
            auth_url = url.replace("https://", f"https://{token}@")
        elif "gitlab" in url:
            # GitLab personal access token uses oauth2 as username
            auth_url = url.replace("https://", f"https://oauth2:{token}@")
        else:
            # GitHub.com and GitHub Enterprise (github.ibm.com, etc.)
            auth_url = url.replace("https://", f"https://x-access-token:{token}@")
    else:
        auth_url = url

    def _clone(b):
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", b,
             "--no-recurse-submodules",
             auth_url, tmp],
            check=True, capture_output=True, timeout=180,
        )

    # Try requested branch first, fall back to common alternatives
    for candidate in [branch, "main", "master", "develop"]:
        try:
            _clone(candidate)
            logger.info(f"Cloned {url} branch={candidate}")
            return tmp
        except subprocess.CalledProcessError:
            # Clean tmp for retry
            shutil.rmtree(tmp, ignore_errors=True)
            os.makedirs(tmp, exist_ok=True)
            continue

    # Last resort: clone default branch (no --branch flag)
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1",
             "--no-recurse-submodules",
             auth_url, tmp],
            check=True, capture_output=True, timeout=180,
        )
        logger.info(f"Cloned {url} default branch")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to clone {url}: {e.stderr.decode()[:300]}")

    return tmp


def clone_repo_ssh(url: str, ssh_key_path: str, branch: str = "main") -> str:
    tmp = tempfile.mkdtemp(prefix="pqc_scan_")
    env = {**os.environ,
           "GIT_SSH_COMMAND": f"ssh -i {ssh_key_path} -o StrictHostKeyChecking=no"}
    subprocess.run(
        ["git", "clone", "--depth", "1", "--branch", branch, url, tmp],
        check=True, capture_output=True, timeout=120, env=env,
    )
    return tmp
