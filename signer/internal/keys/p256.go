package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
)

// CurveP256 is the wire name for the NIST P-256 (secp256r1) curve.
const CurveP256 = "CURVE_P256"

// AddressFormatCompressed is the wire address-format identifier for the raw
// compressed public key hex, the P-256 default (P-256 has no chain-specific
// address format).
const AddressFormatCompressed = "ADDRESS_FORMAT_COMPRESSED"

// p256Curve implements the Curve interface for NIST P-256 keys, using the Go
// standard library's crypto/ecdsa + crypto/elliptic. P-256 has no chain default,
// so the address is just the compressed public key hex.
type p256Curve struct{}

func init() { Register(p256Curve{}) }

func (p256Curve) Name() string { return CurveP256 }

// Generate creates a fresh P-256 key pair. PrivateKey is the 32-byte big-endian
// scalar D; PublicKey is the compressed-point hex. The caller MUST zeroize
// PrivateKey.
func (p256Curve) Generate() (Generated, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Generated{}, fmt.Errorf("keys: p256 GenerateKey: %w", err)
	}
	scalar := make([]byte, 32)
	priv.D.FillBytes(scalar)
	compressed := hex.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y))
	return Generated{
		PrivateKey: scalar,
		PublicKey:  compressed,
	}, nil
}

// Import validates a hex-encoded 32-byte P-256 scalar (with or without 0x
// prefix), checks 0 < d < N, reconstructs the public key, and returns the
// metadata. Used exclusively for the guarded import path; the resulting
// PrivateKey must be zeroized after use.
func (p256Curve) Import(hexKey string) (Generated, error) {
	scalar, err := decodeHex(hexKey)
	if err != nil {
		return Generated{}, fmt.Errorf("keys: invalid p256 scalar hex: %w", err)
	}
	priv, err := p256PrivateKeyFromScalar(scalar)
	if err != nil {
		return Generated{}, err
	}
	canonical := make([]byte, 32)
	priv.D.FillBytes(canonical)
	compressed := hex.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y))
	return Generated{
		PrivateKey: canonical,
		PublicKey:  compressed,
	}, nil
}

// DefaultAddressFormat returns ADDRESS_FORMAT_COMPRESSED.
func (p256Curve) DefaultAddressFormat() string { return AddressFormatCompressed }

// DefaultAddress returns the compressed public key hex — P-256 has no
// chain-specific address format, so its default is ADDRESS_FORMAT_COMPRESSED:
// the compressed public key hex itself.
func (p256Curve) DefaultAddress(publicKeyHex string) (string, error) {
	return publicKeyHex, nil
}

// Sign requires HASH_FUNCTION_NO_OP and a 32-byte pre-hashed digest payload. It
// reconstructs the private key from the scalar, ECDSA-signs the digest, and
// returns R/S (32-byte hex each), V = "00" (P-256 ECDSA is non-recoverable
// here), plus the compressed public key hex for the receipt. The caller zeroizes
// priv.
func (p256Curve) Sign(priv []byte, payload []byte, hashFunction string) (Signature, string, error) {
	if hashFunction != HashFunctionNoOp {
		return Signature{}, "", fmt.Errorf("p256 keys require hashFunction HASH_FUNCTION_NO_OP (pre-hashed 32-byte digest)")
	}
	if len(payload) != 32 {
		return Signature{}, "", fmt.Errorf("p256 HASH_FUNCTION_NO_OP requires a 32-byte digest, got %d bytes", len(payload))
	}
	privKey, err := p256PrivateKeyFromScalar(priv)
	if err != nil {
		return Signature{}, "", err
	}
	r, s, err := ecdsa.Sign(rand.Reader, privKey, payload)
	if err != nil {
		return Signature{}, "", fmt.Errorf("keys: p256 ecdsa.Sign: %w", err)
	}
	rBytes := make([]byte, 32)
	sBytes := make([]byte, 32)
	r.FillBytes(rBytes)
	s.FillBytes(sBytes)
	compressed := hex.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), privKey.X, privKey.Y))
	return Signature{
		R: hex.EncodeToString(rBytes),
		S: hex.EncodeToString(sBytes),
		V: "00",
	}, compressed, nil
}

// p256PrivateKeyFromScalar reconstructs a P-256 ecdsa.PrivateKey from a 32-byte
// big-endian scalar, validating 0 < d < N and deriving the public point via
// ScalarBaseMult.
func p256PrivateKeyFromScalar(scalar []byte) (*ecdsa.PrivateKey, error) {
	if len(scalar) != 32 {
		return nil, fmt.Errorf("keys: p256 scalar must be 32 bytes, got %d", len(scalar))
	}
	curve := elliptic.P256()
	d := new(big.Int).SetBytes(scalar)
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, fmt.Errorf("keys: p256 scalar out of range (must be 0 < d < N)")
	}
	x, y := curve.ScalarBaseMult(scalar)
	priv := &ecdsa.PrivateKey{D: d}
	priv.PublicKey.Curve = curve
	priv.PublicKey.X = x
	priv.PublicKey.Y = y
	return priv, nil
}
