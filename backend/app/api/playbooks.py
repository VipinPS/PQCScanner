"""
Remediation playbooks — actionable before/after code diffs per algorithm per language.
"""
from fastapi import APIRouter, HTTPException

router = APIRouter()

PLAYBOOKS = {
    "RSA-2048": {
        "algorithm":    "RSA-2048",
        "severity":     "CRITICAL",
        "quantum_risk": "Broken by Shor's algorithm on a quantum computer with ~4000 logical qubits.",
        "nist_replacement": "ML-KEM-768 (FIPS 203) for key exchange, ML-DSA-65 (FIPS 204) for signatures",
        "migration_effort": "medium",
        "steps": [
            "Identify all RSA key generation and usage points (use Scan Explorer)",
            "Choose replacement: ML-KEM-768 for key encapsulation, ML-DSA-65 for signing",
            "Add PQC library dependency for your language",
            "Implement in hybrid mode first (classical + PQC simultaneously)",
            "Test across all environments",
            "Once validated, disable classical fallback",
        ],
        "languages": {
            "python": {
                "library": "pqcrypto or liboqs-python",
                "install": "pip install liboqs-python",
                "before": """\
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# BEFORE: RSA-2048 key generation — vulnerable to quantum attack
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

# Encryption
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)""",
                "after": """\
import oqs  # liboqs-python

# AFTER: ML-KEM-768 (NIST FIPS 203) — quantum-safe key encapsulation
with oqs.KeyEncapsulation("ML-KEM-768") as kem:
    public_key  = kem.generate_keypair()
    ciphertext, shared_secret = kem.encap_secret(public_key)

# Hybrid mode (recommended during transition):
# Run X25519 + ML-KEM-768 in parallel, HKDF-combine shared secrets
import hkdf, hashlib
combined_secret = hkdf.hkdf_extract(
    salt=None,
    input_key_material=classical_secret + pqc_secret,
    hash=hashlib.sha256,
)""",
            },
            "java": {
                "library": "Bouncy Castle PQC",
                "install": "implementation 'org.bouncycastle:bcprov-jdk18on:1.78'",
                "before": """\
// BEFORE: RSA-2048 — vulnerable to quantum attack
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
kpg.initialize(2048);
KeyPair keyPair = kpg.generateKeyPair();

Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
byte[] ciphertext = cipher.doFinal(message);""",
                "after": """\
// AFTER: ML-KEM-768 (NIST FIPS 203) via Bouncy Castle
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec; // BC name for ML-KEM

Security.addProvider(new BouncyCastleProvider());
KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BC");
kpg.initialize(KyberParameterSpec.kyber768); // = ML-KEM-768

KeyPair keyPair = kpg.generateKeyPair();

// Encapsulate
KeyGenerator kg = KeyGenerator.getInstance("Kyber", "BC");
kg.init(new KEMGenerateSpec(keyPair.getPublic(), "AES"));
SecretKeyWithEncapsulation secEnc = (SecretKeyWithEncapsulation) kg.generateKey();
byte[] ciphertext   = secEnc.getEncapsulation();
SecretKey sharedKey = secEnc;""",
            },
            "go": {
                "library": "cloudflare/circl or filippo.io/mlkem768",
                "install": "go get filippo.io/mlkem768",
                "before": """\
// BEFORE: RSA-2048 — vulnerable to quantum attack
import "crypto/rsa"

privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
if err != nil { panic(err) }

ciphertext, err := rsa.EncryptOAEP(
    sha256.New(), rand.Reader, &privateKey.PublicKey, message, nil,
)""",
                "after": """\
// AFTER: ML-KEM-768 (NIST FIPS 203)
import "filippo.io/mlkem768"

// Key generation
dk, err := mlkem768.GenerateKey()
if err != nil { panic(err) }

ek := dk.EncapsulationKey()

// Encapsulate (sender)
sharedKey, ciphertext, err := ek.Encapsulate()

// Decapsulate (receiver)
sharedKey, err := dk.Decapsulate(ciphertext)""",
            },
            "typescript": {
                "library": "liboqs-node or @noble/post-quantum",
                "install": "npm install @noble/post-quantum",
                "before": """\
// BEFORE: RSA-2048 via node:crypto — vulnerable to quantum attack
import { generateKeyPairSync, publicEncrypt } from 'node:crypto'

const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })

const ciphertext = publicEncrypt(
  { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
  Buffer.from(message)
)""",
                "after": """\
// AFTER: ML-KEM-768 (NIST FIPS 203) via @noble/post-quantum
import { ml_kem768 } from '@noble/post-quantum/ml-kem'

// Key generation
const { publicKey, secretKey } = ml_kem768.keygen()

// Encapsulate (sender) — returns ciphertext + 32-byte shared secret
const { cipherText, sharedSecret: senderSecret } = ml_kem768.encapsulate(publicKey)

// Decapsulate (receiver)
const receiverSecret = ml_kem768.decapsulate(cipherText, secretKey)""",
            },
        },
    },

    "ECDSA": {
        "algorithm":    "ECDSA",
        "severity":     "HIGH",
        "quantum_risk": "Broken by Shor's algorithm. All ECDSA-signed data is at risk once quantum computers scale.",
        "nist_replacement": "ML-DSA-65 (FIPS 204) — lattice-based digital signature",
        "migration_effort": "medium",
        "steps": [
            "Audit all signing and verification points",
            "Replace with ML-DSA-65 for new signatures",
            "For JWT: use ML-DSA-65 as 'alg', keep RS256 as fallback during transition",
            "Re-sign any long-lived certificates or tokens",
        ],
        "languages": {
            "python": {
                "library": "liboqs-python",
                "install": "pip install liboqs-python",
                "before": """\
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

# BEFORE: ECDSA P-256 — vulnerable to quantum attack
private_key = ec.generate_private_key(ec.SECP256R1())
signature   = private_key.sign(message, ec.ECDSA(hashes.SHA256()))""",
                "after": """\
import oqs

# AFTER: ML-DSA-65 (NIST FIPS 204)
with oqs.Signature("ML-DSA-65") as signer:
    public_key = signer.generate_keypair()
    signature  = signer.sign(message)

with oqs.Signature("ML-DSA-65") as verifier:
    valid = verifier.verify(message, signature, public_key)""",
            },
            "go": {
                "library": "cloudflare/circl",
                "install": "go get github.com/cloudflare/circl/sign/dilithium",
                "before": """\
// BEFORE: ECDSA P-256
import "crypto/ecdsa"

key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
sig, _ := ecdsa.SignASN1(rand.Reader, key, hash)
valid  := ecdsa.VerifyASN1(&key.PublicKey, hash, sig)""",
                "after": """\
// AFTER: ML-DSA-65 (NIST FIPS 204) via circl
import "github.com/cloudflare/circl/sign/mldsa/mldsa65"

// Key generation
pub, priv, _ := mldsa65.GenerateKey(rand.Reader)

// Sign
sig := make([]byte, mldsa65.SignatureSize)
mldsa65.Sign(priv, sig, message, nil)

// Verify
valid := mldsa65.Verify(pub, message, nil, sig)""",
            },
        },
    },

    "SHA-1": {
        "algorithm":    "SHA-1",
        "severity":     "HIGH",
        "quantum_risk": "Classically broken (collision attacks). SHA-1 is also weakened further by Grover's algorithm.",
        "nist_replacement": "SHA-3-256 (FIPS 202) or SHA-256",
        "migration_effort": "low",
        "steps": [
            "Find all SHA-1 usage with Scan Explorer",
            "Replace with SHA-3-256 (preferred) or SHA-256 as minimum",
            "Note: SHA-256 is acceptable short-term but SHA-3-256 is quantum-hardened",
        ],
        "languages": {
            "python": {
                "library": "hashlib (stdlib)",
                "install": "# No install needed — stdlib",
                "before": "import hashlib\ndigest = hashlib.sha1(data).hexdigest()",
                "after":  "import hashlib\ndigest = hashlib.sha3_256(data).hexdigest()  # SHA-3-256 (FIPS 202)",
            },
            "java": {
                "library": "java.security (stdlib)",
                "install": "# No install needed",
                "before": 'MessageDigest md = MessageDigest.getInstance("SHA-1");\nbyte[] hash = md.digest(data);',
                "after":  'MessageDigest md = MessageDigest.getInstance("SHA3-256");\nbyte[] hash = md.digest(data);',
            },
            "go": {
                "library": "crypto/sha3 (stdlib)",
                "install": "# No install needed",
                "before": 'import "crypto/sha1"\nhash := sha1.Sum(data)',
                "after":  'import "golang.org/x/crypto/sha3"\nhash := sha3.Sum256(data)  // SHA-3-256',
            },
            "typescript": {
                "library": "@noble/hashes",
                "install": "npm install @noble/hashes",
                "before": "import { createHash } from 'node:crypto'\nconst hash = createHash('sha1').update(data).digest('hex')",
                "after":  "import { sha3_256 } from '@noble/hashes/sha3'\nconst hash = sha3_256(data)  // SHA-3-256 (FIPS 202)",
            },
        },
    },

    "MD5": {
        "algorithm":    "MD5",
        "severity":     "CRITICAL",
        "quantum_risk": "Classically broken (collision attacks in seconds). Should have been replaced years ago.",
        "nist_replacement": "SHA-3-256 (FIPS 202)",
        "migration_effort": "low",
        "steps": [
            "Replace all MD5 with SHA-3-256 immediately",
            "If used for non-security checksums only, SHA-256 is acceptable",
            "Never use MD5 for passwords, signatures, or integrity checks",
        ],
        "languages": {
            "python": {
                "library": "hashlib (stdlib)",
                "install": "# No install needed",
                "before": "import hashlib\nhash = hashlib.md5(data).hexdigest()",
                "after":  "import hashlib\nhash = hashlib.sha3_256(data).hexdigest()",
            },
            "typescript": {
                "library": "@noble/hashes",
                "install": "npm install @noble/hashes",
                "before": "import { createHash } from 'node:crypto'\nconst hash = createHash('md5').update(data).digest('hex')",
                "after":  "import { sha3_256 } from '@noble/hashes/sha3'\nconst hash = sha3_256(data)",
            },
        },
    },

    "JWT-RS256": {
        "algorithm":    "JWT-RS256",
        "severity":     "HIGH",
        "quantum_risk": "RS256 uses RSA-2048 internally — vulnerable to Shor's algorithm.",
        "nist_replacement": "ML-DSA-65 (FIPS 204) as JWT signing algorithm",
        "migration_effort": "medium",
        "steps": [
            "Add alg_fallback field to JWT header for backwards compat",
            "Issue new tokens with ML-DSA-65",
            "Keep RS256 verification support for existing tokens until they expire",
            "Set token TTL to ≤24h to accelerate rotation",
        ],
        "languages": {
            "python": {
                "library": "pyjwt + liboqs-python",
                "install": "pip install PyJWT liboqs-python",
                "before": """\
import jwt
# BEFORE: RS256 — RSA-2048 based, quantum vulnerable
token = jwt.encode({"sub": user_id}, rsa_private_key, algorithm="RS256")
data  = jwt.decode(token, rsa_public_key, algorithms=["RS256"])""",
                "after": """\
# AFTER: ML-DSA-65 with RS256 fallback during transition
# Header: {"alg": "ML-DSA-65", "alg_fallback": "RS256"}

import oqs, json, base64

def sign_token(payload: dict, ml_dsa_private_key: bytes) -> str:
    header  = {"alg": "ML-DSA-65", "alg_fallback": "RS256", "typ": "JWT"}
    b64h    = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=")
    b64p    = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
    signing_input = b64h + b"." + b64p
    with oqs.Signature("ML-DSA-65") as signer:
        sig = signer.sign(signing_input)
    b64s = base64.urlsafe_b64encode(sig).rstrip(b"=")
    return (signing_input + b"." + b64s).decode()""",
            },
        },
    },

    "TLS-1.0": {
        "algorithm":    "TLS-1.0",
        "severity":     "CRITICAL",
        "quantum_risk": "Classically broken. Enable TLS 1.3 with X25519+ML-KEM hybrid immediately.",
        "nist_replacement": "TLS 1.3 with X25519+ML-KEM-768 hybrid key exchange",
        "migration_effort": "low",
        "steps": [
            "Disable TLS 1.0 and 1.1 at load balancer / server config level",
            "Enable TLS 1.3 as minimum version",
            "Configure X25519+ML-KEM-768 as preferred cipher suite",
            "Test client compatibility",
        ],
        "languages": {
            "python": {
                "library": "ssl (stdlib)",
                "install": "# No install needed",
                "before": """\
import ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # BROKEN""",
                "after": """\
import ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
# For hybrid PQC: configure at OpenSSL/nginx level with OQS-OpenSSL""",
            },
        },
    },

    "HARDCODED-KEY": {
        "algorithm":    "HARDCODED-KEY",
        "severity":     "CRITICAL",
        "quantum_risk": "Hardcoded keys are already a critical classical risk. Move to KMS immediately.",
        "nist_replacement": "AWS KMS, HashiCorp Vault, or Azure Key Vault with quantum-safe key types",
        "migration_effort": "high",
        "steps": [
            "Rotate all exposed keys immediately",
            "Move keys to a secrets manager (Vault, AWS KMS, etc.)",
            "Use environment variables or secret injection at runtime",
            "Enable key rotation policies with quantum-safe key types",
        ],
        "languages": {
            "python": {
                "library": "boto3 (AWS KMS) or hvac (HashiCorp Vault)",
                "install": "pip install boto3",
                "before": """\
# BEFORE: Hardcoded private key — never do this
PRIVATE_KEY = \"\"\"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA...
-----END RSA PRIVATE KEY-----\"\"\"
""",
                "after": """\
# AFTER: Fetch from AWS KMS at runtime
import boto3

kms = boto3.client('kms', region_name='us-east-1')

def sign_with_kms(message: bytes, key_id: str) -> bytes:
    response = kms.sign(
        KeyId    = key_id,  # KMS key ARN
        Message  = message,
        SigningAlgorithm = 'RSASSA_PSS_SHA_256',  # or ML-DSA once supported
    )
    return response['Signature']""",
            },
        },
    },
    "DES": {
        "algorithm":    "DES",
        "severity":     "CRITICAL",
        "quantum_risk": "DES and 3DES are classically broken. Brute-forceable in hours. Also weakened by Grover's algorithm.",
        "nist_replacement": "AES-256-GCM (FIPS 197)",
        "migration_effort": "low",
        "steps": [
            "Replace all DES/3DES with AES-256-GCM",
            "Use authenticated encryption — GCM mode provides both confidentiality and integrity",
            "Re-encrypt any data at rest that was encrypted with DES/3DES",
            "Rotate all DES keys immediately",
        ],
        "languages": {
            "python": {
                "library": "cryptography (stdlib-like)",
                "install": "pip install cryptography",
                "before": """\
from Crypto.Cipher import DES3
# BEFORE: 3DES — classically and quantum broken
key    = b'MySuperS3cretKey'[:24]
cipher = DES3.new(key, DES3.MODE_CBC)
ct     = cipher.encrypt(b'Hello World!!!!!')""",
                "after": """\
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
# AFTER: AES-256-GCM (FIPS 197) — authenticated encryption
key    = os.urandom(32)          # 256-bit key
nonce  = os.urandom(12)          # 96-bit nonce
aesgcm = AESGCM(key)
ct     = aesgcm.encrypt(nonce, b'Hello World!!!!', None)
pt     = aesgcm.decrypt(nonce, ct, None)""",
            },
            "java": {
                "library": "javax.crypto (stdlib)",
                "install": "# No install needed",
                "before": """\
// BEFORE: DESede (3DES) — broken
Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
SecretKey key = new SecretKeySpec(keyBytes, "DESede");
cipher.init(Cipher.ENCRYPT_MODE, key);""",
                "after": """\
// AFTER: AES-256-GCM — authenticated encryption
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
SecretKey key = new SecretKeySpec(keyBytes256, "AES"); // 32-byte key
GCMParameterSpec spec = new GCMParameterSpec(128, iv);
cipher.init(Cipher.ENCRYPT_MODE, key, spec);""",
            },
            "go": {
                "library": "crypto/aes + crypto/cipher (stdlib)",
                "install": "# No install needed",
                "before": """\
// BEFORE: DES — broken
import "crypto/des"
block, _ := des.NewTripleDESCipher(key)""",
                "after": """\
// AFTER: AES-256-GCM
import "crypto/aes"
import "crypto/cipher"
block, _  := aes.NewCipher(key32)        // 32-byte key = AES-256
gcm, _    := cipher.NewGCM(block)
nonce     := make([]byte, gcm.NonceSize())
ct        := gcm.Seal(nonce, nonce, plaintext, nil)""",
            },
        },
    },

    "RSA-1024": {
        "algorithm":    "RSA-1024",
        "severity":     "CRITICAL",
        "quantum_risk": "Already classically breakable with modern hardware. Immediately broken by Shor's algorithm on quantum computers.",
        "nist_replacement": "ML-KEM-768 (FIPS 203) for key exchange, ML-DSA-65 (FIPS 204) for signatures",
        "migration_effort": "medium",
        "steps": [
            "Treat this as an emergency — RSA-1024 is already classically weak",
            "Replace immediately with ML-KEM-768 (key exchange) or ML-DSA-65 (signatures)",
            "Do not use RSA-2048 as an intermediate step — go directly to PQC",
            "Revoke and reissue any certificates using RSA-1024 keys",
        ],
        "languages": {
            "python": {
                "library": "liboqs-python",
                "install": "pip install liboqs-python",
                "before": """\
from cryptography.hazmat.primitives.asymmetric import rsa
# BEFORE: RSA-1024 — classically AND quantum broken
key = rsa.generate_private_key(public_exponent=65537, key_size=1024)""",
                "after": """\
import oqs
# AFTER: ML-KEM-768 (NIST FIPS 203)
with oqs.KeyEncapsulation("ML-KEM-768") as kem:
    public_key = kem.generate_keypair()
    ciphertext, shared_secret = kem.encap_secret(public_key)""",
            },
            "java": {
                "library": "Bouncy Castle PQC",
                "install": "implementation 'org.bouncycastle:bcprov-jdk18on:1.78'",
                "before": """\
// BEFORE: RSA-1024 — immediately broken
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
kpg.initialize(1024);
KeyPair kp = kpg.generateKeyPair();""",
                "after": """\
// AFTER: ML-KEM-768 via Bouncy Castle
Security.addProvider(new BouncyCastleProvider());
KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BC");
kpg.initialize(KyberParameterSpec.kyber768);
KeyPair kp = kpg.generateKeyPair();""",
            },
        },
    },

    "RSA-4096": {
        "algorithm":    "RSA-4096",
        "severity":     "HIGH",
        "quantum_risk": "RSA-4096 requires ~8000 logical qubits to break with Shor's algorithm. Larger than RSA-2048 but still in scope for future quantum computers.",
        "nist_replacement": "ML-KEM-1024 (FIPS 203) for key exchange, ML-DSA-87 (FIPS 204) for signatures",
        "migration_effort": "medium",
        "steps": [
            "Migrate to ML-KEM-1024 or ML-DSA-87 (the higher security tier matching RSA-4096's intent)",
            "Use hybrid mode during transition: RSA-4096 + ML-KEM-1024 in parallel",
            "RSA-4096 buys more time than RSA-2048 but migration should still be planned for 2025–2027",
        ],
        "languages": {
            "python": {
                "library": "liboqs-python",
                "install": "pip install liboqs-python",
                "before": """\
from cryptography.hazmat.primitives.asymmetric import rsa
# BEFORE: RSA-4096 — high security intent, still quantum vulnerable
key = rsa.generate_private_key(public_exponent=65537, key_size=4096)""",
                "after": """\
import oqs
# AFTER: ML-KEM-1024 (NIST FIPS 203 — highest tier)
with oqs.KeyEncapsulation("ML-KEM-1024") as kem:
    public_key = kem.generate_keypair()
    ciphertext, shared_secret = kem.encap_secret(public_key)""",
            },
            "go": {
                "library": "filippo.io/mlkem768 (use 1024 variant)",
                "install": "go get filippo.io/mlkem768",
                "before": """\
// BEFORE: RSA-4096
import "crypto/rsa"
key, _ := rsa.GenerateKey(rand.Reader, 4096)""",
                "after": """\
// AFTER: ML-KEM-1024 (FIPS 203 highest tier)
// Use cloudflare/circl for ML-KEM-1024
import "github.com/cloudflare/circl/kem/mlkem/mlkem1024"
pk, sk, _ := mlkem1024.GenerateKeyPair(rand.Reader)
ct, ss, _ := pk.Encapsulate()""",
            },
        },
    },

    "ECDH": {
        "algorithm":    "ECDH",
        "severity":     "HIGH",
        "quantum_risk": "ECDH key exchange is broken by Shor's algorithm. Any session keys negotiated with ECDH can be decrypted retroactively once quantum computers scale.",
        "nist_replacement": "ML-KEM-768 (FIPS 203)",
        "migration_effort": "medium",
        "steps": [
            "Replace ECDH key exchange with ML-KEM-768",
            "For TLS: upgrade to TLS 1.3 with X25519+ML-KEM-768 hybrid",
            "For application-level KEM: use liboqs ML-KEM-768 directly",
            "Prioritise forward secrecy — use ephemeral ML-KEM keys per session",
        ],
        "languages": {
            "python": {
                "library": "liboqs-python",
                "install": "pip install liboqs-python",
                "before": """\
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import ECDH

# BEFORE: ECDH P-256 key exchange — quantum vulnerable
private_key = ec.generate_private_key(ec.SECP256R1())
peer_key    = ec.generate_private_key(ec.SECP256R1()).public_key()
shared_key  = private_key.exchange(ECDH(), peer_key)""",
                "after": """\
import oqs
# AFTER: ML-KEM-768 (NIST FIPS 203)
with oqs.KeyEncapsulation("ML-KEM-768") as server:
    server_pk = server.generate_keypair()

with oqs.KeyEncapsulation("ML-KEM-768") as client:
    ciphertext, client_shared = client.encap_secret(server_pk)

server_shared = server.decap_secret(ciphertext)
# server_shared == client_shared — session key established""",
            },
            "go": {
                "library": "filippo.io/mlkem768",
                "install": "go get filippo.io/mlkem768",
                "before": """\
// BEFORE: ECDH P-256
import "crypto/ecdh"
key, _    := ecdh.P256().GenerateKey(rand.Reader)
peer, _   := ecdh.P256().GenerateKey(rand.Reader)
shared, _ := key.ECDH(peer.PublicKey())""",
                "after": """\
// AFTER: ML-KEM-768 (FIPS 203)
import "filippo.io/mlkem768"
dk, _  := mlkem768.GenerateKey()
ek     := dk.EncapsulationKey()
// Sender:
sharedSend, ct, _ := ek.Encapsulate()
// Receiver:
sharedRecv, _     := dk.Decapsulate(ct)""",
            },
            "typescript": {
                "library": "@noble/post-quantum",
                "install": "npm install @noble/post-quantum",
                "before": """\
// BEFORE: ECDH via Web Crypto
const kp = await crypto.subtle.generateKey(
  { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']
)
const shared = await crypto.subtle.deriveKey(
  { name: 'ECDH', public: peerPublicKey }, kp.privateKey, ...
)""",
                "after": """\
// AFTER: ML-KEM-768 (FIPS 203)
import { ml_kem768 } from '@noble/post-quantum/ml-kem'
const { publicKey, secretKey } = ml_kem768.keygen()
// Sender encapsulates:
const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey)
// Receiver decapsulates:
const receiverSecret = ml_kem768.decapsulate(cipherText, secretKey)""",
            },
        },
    },

    "X25519": {
        "algorithm":    "X25519",
        "severity":     "MEDIUM",
        "quantum_risk": "X25519 provides excellent classical security but is broken by Shor's algorithm. Recommended approach is hybrid X25519+ML-KEM-768 during transition.",
        "nist_replacement": "X25519 + ML-KEM-768 hybrid (FIPS 203) — run both in parallel",
        "migration_effort": "low",
        "steps": [
            "X25519 alone is quantum-vulnerable — add ML-KEM-768 alongside it",
            "Use hybrid mode: derive shared secret from HKDF(X25519_secret || ML-KEM_secret)",
            "This is the approach used in TLS 1.3 hybrid key exchange (RFC draft)",
            "Full cutover to ML-KEM-768 only once clients widely support it",
        ],
        "languages": {
            "python": {
                "library": "cryptography + liboqs-python",
                "install": "pip install cryptography liboqs-python",
                "before": """\
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
# BEFORE: X25519 only — quantum vulnerable
private_key = X25519PrivateKey.generate()
shared_key  = private_key.exchange(peer_public_key)""",
                "after": """\
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import oqs

# AFTER: Hybrid X25519 + ML-KEM-768
# Classical part
x_priv   = X25519PrivateKey.generate()
x_shared = x_priv.exchange(peer_x25519_pub)

# PQC part
with oqs.KeyEncapsulation("ML-KEM-768") as kem:
    ct, pqc_shared = kem.encap_secret(peer_mlkem_pub)

# Combine with HKDF — attacker must break BOTH
combined = HKDF(
    algorithm=hashes.SHA256(), length=32, salt=None, info=b"hybrid-kem"
).derive(x_shared + pqc_shared)""",
            },
            "go": {
                "library": "crypto/ecdh + filippo.io/mlkem768",
                "install": "go get filippo.io/mlkem768",
                "before": """\
// BEFORE: X25519 only
import "crypto/ecdh"
key, _    := ecdh.X25519().GenerateKey(rand.Reader)
shared, _ := key.ECDH(peerPub)""",
                "after": """\
// AFTER: Hybrid X25519 + ML-KEM-768
import "crypto/ecdh"
import "filippo.io/mlkem768"
import "golang.org/x/crypto/hkdf"

xKey, _      := ecdh.X25519().GenerateKey(rand.Reader)
xShared, _   := xKey.ECDH(peerX25519Pub)

mlkemDK, _   := mlkem768.GenerateKey()
mlkemShared, ct, _ := mlkemDK.EncapsulationKey().Encapsulate()

// HKDF-combine both secrets
combined := hkdf.Extract(sha256.New,
    append(xShared, mlkemShared...), nil)""",
            },
        },
    },

    "AES-128": {
        "algorithm":    "AES-128",
        "severity":     "MEDIUM",
        "quantum_risk": "Grover's algorithm halves the effective key length — AES-128 becomes effectively 64-bit security against a quantum attacker. AES-256 is the quantum-safe minimum.",
        "nist_replacement": "AES-256-GCM (FIPS 197)",
        "migration_effort": "low",
        "steps": [
            "Upgrade all AES-128 to AES-256 — same API, just use a 32-byte key instead of 16-byte",
            "Always use GCM mode for authenticated encryption",
            "Re-encrypt any data at rest using AES-128",
            "Update key generation to produce 256-bit keys",
        ],
        "languages": {
            "python": {
                "library": "cryptography",
                "install": "pip install cryptography",
                "before": """\
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
# BEFORE: AES-128 (16-byte key) — Grover halves to 64-bit security
key = os.urandom(16)   # 128 bits
ct  = AESGCM(key).encrypt(nonce, plaintext, None)""",
                "after": """\
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
# AFTER: AES-256-GCM (32-byte key) — 128-bit quantum security via Grover
key = os.urandom(32)   # 256 bits — quantum safe minimum
ct  = AESGCM(key).encrypt(nonce, plaintext, None)""",
            },
            "java": {
                "library": "javax.crypto (stdlib)",
                "install": "# No install needed",
                "before": """\
// BEFORE: AES-128
KeyGenerator kg = KeyGenerator.getInstance("AES");
kg.init(128);
SecretKey key = kg.generateKey();""",
                "after": """\
// AFTER: AES-256-GCM
KeyGenerator kg = KeyGenerator.getInstance("AES");
kg.init(256);  // Only change needed
SecretKey key = kg.generateKey();
// Use with GCM mode:
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");""",
            },
            "go": {
                "library": "crypto/aes (stdlib)",
                "install": "# No install needed",
                "before": """\
// BEFORE: AES-128
key := make([]byte, 16)  // 128-bit
io.ReadFull(rand.Reader, key)
block, _ := aes.NewCipher(key)""",
                "after": """\
// AFTER: AES-256
key := make([]byte, 32)  // 256-bit — only change needed
io.ReadFull(rand.Reader, key)
block, _ := aes.NewCipher(key)
gcm, _   := cipher.NewGCM(block)""",
            },
            "typescript": {
                "library": "Web Crypto API (stdlib)",
                "install": "# No install needed",
                "before": """\
// BEFORE: AES-128-GCM
const key = await crypto.subtle.generateKey(
  { name: 'AES-GCM', length: 128 }, true, ['encrypt', 'decrypt']
)""",
                "after": """\
// AFTER: AES-256-GCM
const key = await crypto.subtle.generateKey(
  { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
)
// Identical API — just length: 256""",
            },
        },
    },

    "TLS-1.1": {
        "algorithm":    "TLS-1.1",
        "severity":     "HIGH",
        "quantum_risk": "TLS 1.1 uses vulnerable cipher suites and lacks forward secrecy. Also weakened by quantum attacks on its key exchange.",
        "nist_replacement": "TLS 1.3 with X25519+ML-KEM-768 hybrid key exchange",
        "migration_effort": "low",
        "steps": [
            "Disable TLS 1.0 and 1.1 at your load balancer or server config",
            "Set TLS 1.2 as absolute minimum, TLS 1.3 as preferred",
            "Configure X25519+ML-KEM-768 as preferred key exchange in TLS 1.3",
            "Test all clients — most modern browsers support TLS 1.3",
        ],
        "languages": {
            "python": {
                "library": "ssl (stdlib)",
                "install": "# No install needed",
                "before": """\
import ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.maximum_version = ssl.TLSVersion.TLSv1_1  # BROKEN""",
                "after": """\
import ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3  # TLS 1.3 only
# For PQC hybrid: configure at nginx/OpenSSL level with OQS provider
# NGINX: ssl_protocols TLSv1.3;
# NGINX: ssl_ecdh_curve X25519MLKEM768:X25519;""",
            },
            "go": {
                "library": "crypto/tls (stdlib)",
                "install": "# No install needed",
                "before": """\
// BEFORE: TLS 1.1 allowed
cfg := &tls.Config{
    MaxVersion: tls.VersionTLS11,
}""",
                "after": """\
// AFTER: TLS 1.3 only
cfg := &tls.Config{
    MinVersion: tls.VersionTLS13,
    // For PQC hybrid curves, use Go 1.23+ with GODEBUG=tlskyber=1
    // or use cloudflare/go fork with X25519+ML-KEM support
}""",
            },
        },
    },

    "RC4": {
        "algorithm":    "RC4",
        "severity":     "CRITICAL",
        "quantum_risk": "RC4 is completely broken classically (BEAST, RC4 NOMORE attacks). Should have been replaced years ago. Also trivially broken by quantum.",
        "nist_replacement": "AES-256-GCM (FIPS 197) or ChaCha20-Poly1305",
        "migration_effort": "low",
        "steps": [
            "Replace RC4 immediately — it is completely broken classically",
            "Use AES-256-GCM for symmetric encryption",
            "Use ChaCha20-Poly1305 as an alternative (excellent for mobile/embedded)",
            "Never use RC4 in any new code under any circumstances",
        ],
        "languages": {
            "python": {
                "library": "cryptography",
                "install": "pip install cryptography",
                "before": """\
from Crypto.Cipher import ARC4
# BEFORE: RC4 — completely broken
cipher = ARC4.new(key)
ct     = cipher.encrypt(plaintext)""",
                "after": """\
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
import os
# AFTER option 1: AES-256-GCM
key   = os.urandom(32)
nonce = os.urandom(12)
ct    = AESGCM(key).encrypt(nonce, plaintext, None)

# AFTER option 2: ChaCha20-Poly1305 (great for embedded/mobile)
key   = os.urandom(32)
nonce = os.urandom(12)
ct    = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)""",
            },
            "java": {
                "library": "javax.crypto (stdlib)",
                "install": "# No install needed",
                "before": """\
// BEFORE: RC4 / ARCFOUR — completely broken
Cipher cipher = Cipher.getInstance("ARCFOUR");
cipher.init(Cipher.ENCRYPT_MODE, secretKey);""",
                "after": """\
// AFTER: AES-256-GCM
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
SecretKey key = new SecretKeySpec(keyBytes32, "AES");
GCMParameterSpec spec = new GCMParameterSpec(128, iv12bytes);
cipher.init(Cipher.ENCRYPT_MODE, key, spec);""",
            },
            "go": {
                "library": "crypto/cipher (stdlib)",
                "install": "# No install needed",
                "before": """\
// BEFORE: RC4
import "crypto/rc4"
cipher, _ := rc4.NewCipher(key)
cipher.XORKeyStream(dst, src)""",
                "after": """\
// AFTER: ChaCha20-Poly1305 (or AES-256-GCM)
import "golang.org/x/crypto/chacha20poly1305"
aead, _  := chacha20poly1305.New(key32)
nonce    := make([]byte, aead.NonceSize())
ct       := aead.Seal(nonce, nonce, plaintext, nil)""",
            },
        },
    },

    "PBKDF2": {
        "algorithm":    "PBKDF2",
        "severity":     "MEDIUM",
        "quantum_risk": "PBKDF2 is weakened by Grover's algorithm and is GPU-parallelisable. Argon2id is memory-hard, making both classical and quantum brute-force attacks significantly harder.",
        "nist_replacement": "Argon2id (winner of Password Hashing Competition)",
        "migration_effort": "low",
        "steps": [
            "Replace PBKDF2 with Argon2id for all new password hashing",
            "Recommended params: memory=64MB, iterations=3, parallelism=4",
            "For existing hashes: re-hash on next user login (check PBKDF2, re-store as Argon2id)",
            "Never migrate by re-hashing the old hash — wait for plaintext password on login",
        ],
        "languages": {
            "python": {
                "library": "argon2-cffi",
                "install": "pip install argon2-cffi",
                "before": """\
import hashlib
# BEFORE: PBKDF2 — GPU-parallelisable, weakened by Grover
dk = hashlib.pbkdf2_hmac('sha256', password, salt, iterations=260000)""",
                "after": """\
from argon2 import PasswordHasher
# AFTER: Argon2id — memory-hard, quantum-resistant password hashing
ph   = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
hash = ph.hash(password)        # store this
ph.verify(hash, password)       # verify on login""",
            },
            "java": {
                "library": "de.mkammerer:argon2-jvm",
                "install": "implementation 'de.mkammerer:argon2-jvm:2.11'",
                "before": """\
// BEFORE: PBKDF2
SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
KeySpec spec = new PBEKeySpec(password, salt, 260000, 256);
byte[] hash  = skf.generateSecret(spec).getEncoded();""",
                "after": """\
// AFTER: Argon2id
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
Argon2 argon2 = Argon2Factory.createAdvanced(Argon2Factory.Argon2Types.ARGON2id);
String hash   = argon2.hash(3, 65536, 4, password);  // iter, mem(KB), threads
boolean valid = argon2.verify(hash, password);""",
            },
            "go": {
                "library": "golang.org/x/crypto/argon2",
                "install": "go get golang.org/x/crypto",
                "before": """\
// BEFORE: PBKDF2
import "golang.org/x/crypto/pbkdf2"
dk := pbkdf2.Key(password, salt, 260000, 32, sha256.New)""",
                "after": """\
// AFTER: Argon2id
import "golang.org/x/crypto/argon2"
hash := argon2.IDKey(
    password,
    salt,
    3,      // iterations
    64*1024, // 64 MB memory
    4,      // parallelism
    32,     // key length
)""",
            },
            "typescript": {
                "library": "argon2 (node) or @noble/hashes",
                "install": "npm install argon2",
                "before": """\
import { pbkdf2 } from 'node:crypto'
// BEFORE: PBKDF2
pbkdf2(password, salt, 260000, 32, 'sha256', (err, dk) => { ... })""",
                "after": """\
import argon2 from 'argon2'
// AFTER: Argon2id
const hash  = await argon2.hash(password, {
  type: argon2.argon2id,
  memoryCost: 65536,   // 64 MB
  timeCost:   3,
  parallelism: 4,
})
const valid = await argon2.verify(hash, password)""",
            },
        },
    },

    "BLOWFISH": {
        "algorithm":    "Blowfish",
        "severity":     "CRITICAL",
        "quantum_risk": "Blowfish uses a 64-bit block size, making it vulnerable to birthday attacks (SWEET32). It is also weakened by Grover's algorithm. Immediately replace with AES-256-GCM.",
        "nist_replacement": "AES-256-GCM",
        "migration_effort": "low",
        "steps": [
            "Replace Blowfish with AES-256-GCM (authenticated encryption)",
            "Generate a 256-bit (32-byte) random key; do NOT reuse Blowfish keys",
            "Generate a fresh 96-bit (12-byte) random IV/nonce per encryption operation",
            "Store the nonce alongside the ciphertext (it is not secret)",
            "Verify decryption succeeds before removing old Blowfish code",
        ],
        "languages": {
            "python": {
                "library": "cryptography",
                "install": "pip install cryptography",
                "before": """\
from Crypto.Cipher import Blowfish
# BEFORE: Blowfish — 64-bit block, vulnerable to SWEET32
cipher = Blowfish.new(key, Blowfish.MODE_CBC)
ct = cipher.encrypt(pad(data, Blowfish.block_size))""",
                "after": """\
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
# AFTER: AES-256-GCM — authenticated, quantum-resilient
key   = os.urandom(32)           # 256-bit key
nonce = os.urandom(12)           # 96-bit nonce (unique per message)
ct    = AESGCM(key).encrypt(nonce, data, None)
pt    = AESGCM(key).decrypt(nonce, ct,   None)""",
            },
            "java": {
                "library": "javax.crypto (built-in)",
                "install": "# No extra dependency — use JDK built-in",
                "before": """\
// BEFORE: Blowfish
Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, blowfishKey);
byte[] ct = cipher.doFinal(data);""",
                "after": """\
// AFTER: AES-256-GCM
import javax.crypto.*;
import javax.crypto.spec.*;
byte[] nonce = new byte[12];
new java.security.SecureRandom().nextBytes(nonce);
SecretKey aesKey = KeyGenerator.getInstance("AES").generateKey();  // 256-bit
Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
gcm.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, nonce));
byte[] ct = gcm.doFinal(data);""",
            },
            "go": {
                "library": "crypto/aes + crypto/cipher (stdlib)",
                "install": "# Standard library only",
                "before": """\
// BEFORE: Blowfish
import "golang.org/x/crypto/blowfish"
block, _ := blowfish.NewCipher(key)
// ... CBC encrypt""",
                "after": """\
// AFTER: AES-256-GCM
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
)
block, _ := aes.NewCipher(key32)          // 32-byte key = AES-256
gcm, _   := cipher.NewGCM(block)
nonce    := make([]byte, gcm.NonceSize())
rand.Read(nonce)
ct       := gcm.Seal(nonce, nonce, plaintext, nil)
pt, _    := gcm.Open(nil, ct[:gcm.NonceSize()], ct[gcm.NonceSize():], nil)""",
            },
        },
    },

    "RSA-KEYGEN-CLI": {
        "algorithm":    "RSA-KEYGEN-CLI",
        "severity":     "CRITICAL",
        "quantum_risk": "RSA keys generated via ssh-keygen or openssl genrsa are broken by Shor's algorithm on a CRQC. Shell scripts embedding these commands perpetuate quantum-vulnerable key material throughout your infrastructure.",
        "nist_replacement": "ML-KEM-768 (key exchange) / ML-DSA-65 (signatures) via oqs-provider or liboqs",
        "migration_effort": "medium",
        "steps": [
            "Audit all shell scripts, Dockerfiles, CI pipelines, and Makefiles for ssh-keygen -t rsa / openssl genrsa",
            "Replace RSA key generation with ML-DSA-65 (signing) or ML-KEM-768 (key exchange) using OQS tools",
            "For SSH host/user keys: switch to Ed25519 now (classical-safe), plan migration to OQS SSH when OpenSSH adds ML-DSA support",
            "For TLS/x.509: use oqs-provider with openssl genpkey -algorithm mldsa65 or a hybrid mldsa65_ec_p256",
            "Revoke and rotate any RSA keys already distributed",
            "Update key-generation scripts in CI/CD and infrastructure-as-code repos",
        ],
        "languages": {
            "shell": {
                "library": "OQS-OpenSSL provider (liboqs)",
                "install": "# Install liboqs + oqs-provider: https://github.com/open-quantum-safe/oqs-provider",
                "before": """\
# BEFORE: RSA key generation — quantum-vulnerable
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa
openssl genrsa -out server.key 4096
openssl genpkey -algorithm rsa -out server.key -pkeyopt rsa_keygen_bits:4096""",
                "after": """\
# AFTER (near-term): Ed25519 for SSH (classical-safe)
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519

# AFTER (PQC-safe): ML-DSA-65 signing key via OQS-OpenSSL
openssl genpkey -provider oqsprovider -algorithm mldsa65 -out signing.key
openssl req   -provider oqsprovider -new -key signing.key -out signing.csr

# AFTER: Hybrid ML-DSA65 + P-256 (transition-safe)
openssl genpkey -provider oqsprovider -algorithm mldsa65_ec_p256 -out hybrid.key""",
            },
            "python": {
                "library": "oqs-python (liboqs Python bindings)",
                "install": "pip install oqs",
                "before": """\
import subprocess
# BEFORE: shell-out to openssl genrsa — RSA key, quantum-vulnerable
subprocess.run(['openssl', 'genrsa', '-out', 'key.pem', '4096'], check=True)""",
                "after": """\
import oqs
# AFTER: ML-DSA-65 signing key pair (FIPS 204 draft)
with oqs.Signature("ML-DSA-65") as sig:
    public_key  = sig.generate_keypair()
    private_key = sig.export_secret_key()
    # Persist public_key and private_key securely""",
            },
            "go": {
                "library": "open-quantum-safe/liboqs-go",
                "install": "go get github.com/open-quantum-safe/liboqs-go/oqs",
                "before": """\
// BEFORE: RSA key generation
import "crypto/rsa"
priv, _ := rsa.GenerateKey(rand.Reader, 4096)""",
                "after": """\
// AFTER: ML-DSA-65 via liboqs-go
import "github.com/open-quantum-safe/liboqs-go/oqs"
signer := oqs.Signature{}
signer.Init("ML-DSA-65", nil)
pubKey, _ := signer.GenerateKeyPair()
_ = pubKey   // distribute public key""",
            },
        },
    },

    "AES-XTS": {
        "algorithm":    "AES-XTS",
        "severity":     "MEDIUM",
        "quantum_risk": "AES-XTS with a 256-bit key (two 128-bit subkeys) provides only 128-bit quantum security due to Grover's algorithm. Prefer AES-XTS-512 (two 256-bit subkeys) for full 256-bit quantum security in disk encryption contexts.",
        "nist_replacement": "AES-XTS-512 (512-bit total key = two 256-bit subkeys) for disk encryption",
        "migration_effort": "medium",
        "steps": [
            "Identify all AES-XTS usage — typically dm-crypt/LUKS, FileVault, BitLocker, or VeraCrypt",
            "Upgrade to AES-XTS with 512-bit key (aes-xts-plain64 with 512-bit key = two 256-bit AES keys)",
            "For LUKS2: re-encrypt the volume with --cipher aes-xts-plain64 --key-size 512",
            "For application-level XTS: switch to AES-256-GCM if authentication is also needed",
            "Note: XTS mode does NOT provide authentication — add an HMAC or use AES-GCM for authenticated use cases",
        ],
        "languages": {
            "shell": {
                "library": "cryptsetup (LUKS2)",
                "install": "# cryptsetup >= 2.0 supports LUKS2 with Argon2id",
                "before": """\
# BEFORE: AES-XTS with 256-bit key (128-bit quantum security)
cryptsetup luksFormat --type luks2 \\
  --cipher aes-xts-plain64 \\
  --key-size 256 \\
  /dev/sdX""",
                "after": """\
# AFTER: AES-XTS with 512-bit key (256-bit quantum security)
cryptsetup luksFormat --type luks2 \\
  --cipher aes-xts-plain64 \\
  --key-size 512 \\
  --pbkdf argon2id \\
  --pbkdf-memory 65536 \\
  /dev/sdX""",
            },
            "python": {
                "library": "cryptography",
                "install": "pip install cryptography",
                "before": """\
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# BEFORE: AES-XTS-256 (two 128-bit keys — 128-bit quantum security)
key   = os.urandom(32)   # 256-bit total
tweak = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))""",
                "after": """\
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
# AFTER: AES-XTS-512 (two 256-bit keys — 256-bit quantum security)
key   = os.urandom(64)   # 512-bit total (two 256-bit AES keys)
tweak = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
# OR switch to AES-256-GCM if authentication is needed""",
            },
        },
    },

    "TLS-1.2": {
        "algorithm":    "TLS-1.2",
        "severity":     "MEDIUM",
        "quantum_risk": "TLS 1.2 does not natively support post-quantum key exchange. While not classically broken, it cannot negotiate ML-KEM hybrid key exchange, leaving TLS sessions vulnerable to harvest-now-decrypt-later attacks. Upgrade to TLS 1.3.",
        "nist_replacement": "TLS 1.3 + X25519+ML-KEM-768 hybrid key exchange",
        "migration_effort": "low",
        "steps": [
            "Upgrade all TLS endpoints to TLS 1.3 and disable TLS 1.2",
            "Configure X25519+ML-KEM-768 hybrid key exchange (available in BoringSSL, OQS-OpenSSL, Cloudflare)",
            "Verify client compatibility — modern browsers and runtimes support TLS 1.3",
            "Set minimum TLS version to 1.3 in server configuration",
            "Test with: openssl s_client -connect host:443 -tls1_3",
        ],
        "languages": {
            "python": {
                "library": "ssl (stdlib) / cryptography",
                "install": "pip install cryptography",
                "before": """\
import ssl
# BEFORE: TLS 1.2 — no PQC key exchange support
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_2""",
                "after": """\
import ssl
# AFTER: TLS 1.3 only
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
# Load OQS-OpenSSL provider for ML-KEM hybrid groups (if available)
# ctx.set_ciphers('TLS_AES_256_GCM_SHA384')""",
            },
            "go": {
                "library": "crypto/tls (stdlib)",
                "install": "# Standard library only",
                "before": """\
// BEFORE: TLS 1.2 permitted
import "crypto/tls"
cfg := &tls.Config{
    MinVersion: tls.VersionTLS12,
}""",
                "after": """\
// AFTER: TLS 1.3 only
import "crypto/tls"
cfg := &tls.Config{
    MinVersion: tls.VersionTLS13,
    // CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
    // ^ Enable hybrid PQC when Go adds ML-KEM support
}""",
            },
            "typescript": {
                "library": "Node.js tls module",
                "install": "# Built-in — Node.js 12+ supports TLS 1.3",
                "before": """\
import tls from 'tls'
// BEFORE: TLS 1.2 allowed
const server = tls.createServer({ minVersion: 'TLSv1.2' }, handler)""",
                "after": """\
import tls from 'tls'
// AFTER: TLS 1.3 only
const server = tls.createServer({ minVersion: 'TLSv1.3' }, handler)""",
            },
        },
    },

    "CRYPTSETUP-WEAK-KDF": {
        "algorithm":    "CRYPTSETUP-WEAK-KDF",
        "severity":     "HIGH",
        "quantum_risk": "Using PBKDF2 as the KDF for LUKS disk encryption is weakened by Grover's algorithm and is highly GPU-parallelisable. Argon2id is memory-hard, making both classical and quantum brute-force significantly harder.",
        "nist_replacement": "Argon2id (via LUKS2 --pbkdf argon2id)",
        "migration_effort": "medium",
        "steps": [
            "Identify LUKS volumes using PBKDF2: cryptsetup luksDump /dev/sdX | grep PBKDF",
            "Back up the LUKS header: cryptsetup luksHeaderBackup /dev/sdX --header-backup-file header.img",
            "Convert existing keyslots to Argon2id: cryptsetup luksConvertKey --pbkdf argon2id /dev/sdX",
            "For new volumes: always specify --pbkdf argon2id --pbkdf-memory 65536 (64MB)",
            "Recommended Argon2id params: --pbkdf-memory 65536, --pbkdf-time 2000, --pbkdf-parallel 4",
        ],
        "languages": {
            "shell": {
                "library": "cryptsetup >= 2.0 (LUKS2)",
                "install": "apt install cryptsetup  # or yum/dnf",
                "before": """\
# BEFORE: LUKS2 with PBKDF2 — GPU-crackable, weakened by Grover
cryptsetup luksFormat --type luks2 \\
  --pbkdf pbkdf2 \\
  /dev/sdX

# Check existing volume KDF:
cryptsetup luksDump /dev/sdX | grep -i pbkdf""",
                "after": """\
# AFTER: LUKS2 with Argon2id — memory-hard, quantum-resilient
cryptsetup luksFormat --type luks2 \\
  --cipher aes-xts-plain64 \\
  --key-size 512 \\
  --pbkdf argon2id \\
  --pbkdf-memory 65536 \\
  --pbkdf-time 2000 \\
  /dev/sdX

# Migrate existing keyslot to Argon2id (no data loss):
cryptsetup luksConvertKey --pbkdf argon2id --pbkdf-memory 65536 /dev/sdX""",
            },
        },
    },

    "SSH-WEAK-KEX": {
        "algorithm":    "SSH-WEAK-KEX",
        "severity":     "HIGH",
        "quantum_risk": "SSH key exchange using ECDH over NIST curves or classical Diffie-Hellman groups is broken by Shor's algorithm. Session keys negotiated today can be decrypted retroactively by a CRQC (harvest-now-decrypt-later).",
        "nist_replacement": "sntrup761x25519-sha512@openssh.com or mlkem768x25519-sha256 (hybrid PQC KEX)",
        "migration_effort": "low",
        "steps": [
            "Upgrade to OpenSSH >= 9.0 which includes sntrup761x25519-sha512 hybrid KEX",
            "Set KexAlgorithms in sshd_config to prefer hybrid PQC algorithms",
            "For client config: add KexAlgorithms preference in ~/.ssh/config",
            "Remove classical-only ECDH NIST curve and DH group entries from KexAlgorithms",
            "Test with: ssh -vv host 2>&1 | grep 'kex: algorithm'",
            "Monitor IETF draft for mlkem768x25519-sha256 once standardised in OpenSSH",
        ],
        "languages": {
            "shell": {
                "library": "OpenSSH >= 9.0",
                "install": "apt upgrade openssh-server  # ensure >= 9.0",
                "before": """\
# BEFORE: /etc/ssh/sshd_config — classical ECDH KEX only
KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,\\
              diffie-hellman-group14-sha256""",
                "after": """\
# AFTER: /etc/ssh/sshd_config — hybrid PQC KEX first
KexAlgorithms sntrup761x25519-sha512@openssh.com,\\
              curve25519-sha256,curve25519-sha256@libssh.org

# Restart SSH after change:
systemctl restart sshd

# Verify active KEX:
ssh -vv localhost 2>&1 | grep 'kex: algorithm'""",
            },
            "python": {
                "library": "asyncssh >= 2.14",
                "install": "pip install asyncssh",
                "before": """\
import asyncssh
# BEFORE: default KEX includes classical ECDH NIST curves
conn = await asyncssh.connect(host, username=user)""",
                "after": """\
import asyncssh
# AFTER: restrict to hybrid PQC + Curve25519 KEX
conn = await asyncssh.connect(
    host,
    username=user,
    kex_algs=['sntrup761x25519-sha512@openssh.com', 'curve25519-sha256'],
)""",
            },
        },
    },
}

@router.get("/")
def list_playbooks():
    """List all available playbooks with summary info."""
    return [
        {
            "algorithm":        v["algorithm"],
            "severity":         v["severity"],
            "nist_replacement": v["nist_replacement"],
            "migration_effort": v["migration_effort"],
            "languages":        list(v["languages"].keys()),
        }
        for v in PLAYBOOKS.values()
    ]

@router.get("/{algorithm}")
def get_playbook(algorithm: str):
    """Get full playbook for a specific algorithm."""
    key = algorithm.upper().replace("%20", "-").replace(" ", "-")
    pb  = PLAYBOOKS.get(key) or PLAYBOOKS.get(algorithm)
    if not pb:
        available = list(PLAYBOOKS.keys())
        raise HTTPException(404, f"No playbook for '{algorithm}'. Available: {available}")
    return pb

@router.get("/{algorithm}/{language}")
def get_playbook_for_language(algorithm: str, language: str):
    """Get playbook for a specific algorithm + language combination."""
    key = algorithm.upper().replace("%20", "-").replace(" ", "-")
    pb  = PLAYBOOKS.get(key) or PLAYBOOKS.get(algorithm)
    if not pb:
        raise HTTPException(404, f"No playbook for '{algorithm}'")
    lang_data = pb["languages"].get(language.lower())
    if not lang_data:
        available = list(pb["languages"].keys())
        raise HTTPException(404, f"No {language} playbook for {algorithm}. Available: {available}")
    return {
        "algorithm":        pb["algorithm"],
        "language":         language,
        "nist_replacement": pb["nist_replacement"],
        "steps":            pb["steps"],
        "quantum_risk":     pb["quantum_risk"],
        **lang_data,
    }
