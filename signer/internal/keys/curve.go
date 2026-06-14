package keys

import "sort"

// Hash-function wire identifiers shared across curves. Each curve's Sign method
// references these constants instead of raw string literals so the wire enum is
// defined in exactly one place.
const (
	HashFunctionKeccak256     = "HASH_FUNCTION_KECCAK256"
	HashFunctionNoOp          = "HASH_FUNCTION_NO_OP"
	HashFunctionNotApplicable = "HASH_FUNCTION_NOT_APPLICABLE"
)

// Generated holds a freshly generated or imported key pair. The PrivateKey field
// contains the raw key material in its canonical minimal form (a 32-byte
// secp256k1/p256 scalar, or a 32-byte ed25519 seed); the caller MUST zeroize it
// after envelope-encrypting it. Address derivation is decoupled from key
// generation — callers derive the chain address from PublicKey via the curve's
// DefaultAddress method.
type Generated struct {
	PrivateKey []byte // raw key material — caller must zeroize
	PublicKey  string // public key hex (curve-specific encoding)
}

// Signature is the curve-agnostic signature shape returned to the API. R and S
// are lowercase hex (32 bytes each for the curves implemented here); V is a hex
// recovery byte ("00"/"01" for secp256k1, fixed "00" where not applicable).
type Signature struct {
	R string
	S string
	V string
}

// Curve is a self-contained signing algorithm (key generation, guarded import,
// and signing). Each implementation lives in its own file and registers itself
// via Register in an init() — adding a new curve is a drop-in file with no
// handler edits.
type Curve interface {
	// Name is the wire curve identifier, e.g. "CURVE_SECP256K1".
	Name() string

	// Generate creates a fresh key pair for this curve.
	Generate() (Generated, error)

	// Import validates a hex-encoded private key (the guarded import path) and
	// derives the public key.
	Import(hexKey string) (Generated, error)

	// Sign signs the (already hex-decoded) payload, applying and/or validating
	// hashFunction for this curve. It returns the signature (R/S/V hex) and the
	// public key hex for the signer receipt. priv is the raw private key material;
	// the caller is responsible for zeroizing it.
	Sign(priv []byte, payload []byte, hashFunction string) (Signature, string, error)

	// DefaultAddressFormat returns the wire address-format identifier this curve
	// derives by default (e.g. "ADDRESS_FORMAT_ETHEREUM").
	DefaultAddressFormat() string

	// DefaultAddress derives the curve's default chain address from a public key
	// hex (the encoding returned in Generated.PublicKey).
	DefaultAddress(publicKeyHex string) (string, error)
}

// registry holds the curves registered at init time, keyed by wire name.
var registry = map[string]Curve{}

// Register adds a curve to the registry. Called from each curve file's init().
func Register(c Curve) { registry[c.Name()] = c }

// Lookup returns the registered curve for a wire name, and whether it exists.
func Lookup(name string) (Curve, bool) {
	c, ok := registry[name]
	return c, ok
}

// RegisteredCurves returns the sorted list of registered curve names, for use in
// "unsupported curve" error messages.
func RegisteredCurves() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
