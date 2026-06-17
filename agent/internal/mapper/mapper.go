// Package mapper defines the curated set of crypto-library symbols the agent
// attaches uprobes to, and maps each one to an algorithm name from the
// backend's ALGORITHM_REGISTRY (see backend/app/scanner/engine.py), so
// runtime findings share the same taxonomy, risk levels and NIST
// replacements as the static source-code scanner.
package mapper

// Probe describes one uprobe target: a symbol exported by a shared library,
// tagged with a stable numeric ID (used as the eBPF "attach cookie" so a
// single compiled program can serve every probe) and the algorithm name it
// represents.
type Probe struct {
	ID        uint64
	Library   string // "libcrypto" | "libssl" | "liboqs"
	Symbol    string // exported symbol name to attach the uprobe to
	Algorithm string // key into ALGORITHM_REGISTRY on the backend
}

// Probes is the canonical, ordered list of uprobe targets. ID values are
// stable identifiers sent to the backend as "probe_id" — do not reorder or
// reuse IDs across releases, only append.
var Probes = []Probe{
	{ID: 0, Library: "libcrypto", Symbol: "MD5_Init", Algorithm: "MD5"},
	{ID: 1, Library: "libcrypto", Symbol: "SHA1_Init", Algorithm: "SHA-1"},
	{ID: 2, Library: "libcrypto", Symbol: "DES_set_key", Algorithm: "DES"},
	{ID: 3, Library: "libcrypto", Symbol: "EVP_des_ede3_cbc", Algorithm: "DES"},
	{ID: 4, Library: "libcrypto", Symbol: "RC4_set_key", Algorithm: "RC4"},
	{ID: 5, Library: "libcrypto", Symbol: "EVP_aes_128_gcm", Algorithm: "AES-128"},
	{ID: 6, Library: "libcrypto", Symbol: "EVP_aes_128_cbc", Algorithm: "AES-128"},
	{ID: 7, Library: "libcrypto", Symbol: "ECDSA_sign", Algorithm: "ECDSA"},
	{ID: 8, Library: "libcrypto", Symbol: "EC_KEY_generate_key", Algorithm: "ECDSA"},
	{ID: 9, Library: "libcrypto", Symbol: "ECDH_compute_key", Algorithm: "ECDH"},
	{ID: 10, Library: "libcrypto", Symbol: "PKCS5_PBKDF2_HMAC", Algorithm: "PBKDF2"},
	{ID: 11, Library: "libcrypto", Symbol: "EVP_bf_cbc", Algorithm: "BLOWFISH"},
	{ID: 12, Library: "libcrypto", Symbol: "RSA_generate_key_ex", Algorithm: "RSA-KEYGEN-CLI"},
	{ID: 13, Library: "libssl", Symbol: "TLSv1_method", Algorithm: "TLS-1.0"},
	{ID: 14, Library: "libssl", Symbol: "TLSv1_1_method", Algorithm: "TLS-1.1"},
	{ID: 15, Library: "libssl", Symbol: "TLSv1_2_method", Algorithm: "TLS-1.2"},
	{ID: 16, Library: "liboqs", Symbol: "OQS_KEM_ml_kem_768_keypair", Algorithm: "ML-KEM-768"},
	{ID: 17, Library: "liboqs", Symbol: "OQS_SIG_ml_dsa_65_sign", Algorithm: "ML-DSA-65"},
}

// ByID returns the probe with the given ID, or false if no probe has it.
func ByID(id uint64) (Probe, bool) {
	for _, p := range Probes {
		if p.ID == id {
			return p, true
		}
	}
	return Probe{}, false
}

// BySymbol returns the probe targeting the given symbol, or false if none
// does.
func BySymbol(symbol string) (Probe, bool) {
	for _, p := range Probes {
		if p.Symbol == symbol {
			return p, true
		}
	}
	return Probe{}, false
}

// Libraries returns the distinct library names referenced by Probes, in
// first-seen order.
func Libraries() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range Probes {
		if !seen[p.Library] {
			seen[p.Library] = true
			out = append(out, p.Library)
		}
	}
	return out
}

// ForLibrary returns the probes that attach to the given library.
func ForLibrary(lib string) []Probe {
	var out []Probe
	for _, p := range Probes {
		if p.Library == lib {
			out = append(out, p)
		}
	}
	return out
}
