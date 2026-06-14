package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/mr-tron/base58"
)

// CurveEd25519 is the wire name for the ed25519 curve (Solana and other ed25519
// chains).
const CurveEd25519 = "CURVE_ED25519"

// AddressFormatSolana is the wire address-format identifier for base58-encoded
// Solana account addresses, the ed25519 default.
const AddressFormatSolana = "ADDRESS_FORMAT_SOLANA"

// ed25519Curve implements the Curve interface for ed25519 keys, using the Go
// standard library's crypto/ed25519. Addresses are Solana base58.
type ed25519Curve struct{}

func init() { Register(ed25519Curve{}) }

func (ed25519Curve) Name() string { return CurveEd25519 }

// Generate creates a fresh ed25519 key pair.
//
// The returned PrivateKey holds the 32-byte ed25519 *seed* (the canonical,
// minimal representation of the key); the caller MUST zeroize it after
// envelope-encrypting it. PublicKey is the 32-byte ed25519 public key in hex.
func (ed25519Curve) Generate() (Generated, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Generated{}, fmt.Errorf("keys: ed25519.GenerateKey: %w", err)
	}
	return Generated{
		PrivateKey: priv.Seed(), // 32-byte seed
		PublicKey:  hex.EncodeToString(pub),
	}, nil
}

// Import validates a hex-encoded 32-byte ed25519 seed (with or without 0x
// prefix) and derives the public key. Used exclusively for the guarded import
// path; the resulting PrivateKey (the seed) must be zeroized after use.
func (ed25519Curve) Import(hexKey string) (Generated, error) {
	seed, err := decodeHex(hexKey)
	if err != nil {
		return Generated{}, fmt.Errorf("keys: invalid ed25519 seed hex: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return Generated{}, fmt.Errorf("keys: ed25519 seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return Generated{
		PrivateKey: seed,
		PublicKey:  hex.EncodeToString(pub),
	}, nil
}

// DefaultAddressFormat returns ADDRESS_FORMAT_SOLANA.
func (ed25519Curve) DefaultAddressFormat() string { return AddressFormatSolana }

// DefaultAddress derives the base58-encoded Solana account address from an
// ed25519 public key hex. The signer has no address engine, so the derivation is
// inline: base58 of the 32-byte public key.
func (ed25519Curve) DefaultAddress(publicKeyHex string) (string, error) {
	pubBytes, err := decodeHex(publicKeyHex)
	if err != nil {
		return "", fmt.Errorf("keys: invalid ed25519 public key hex: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return "", fmt.Errorf("keys: ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pubBytes))
	}
	return base58.Encode(pubBytes), nil
}

// Sign requires HASH_FUNCTION_NOT_APPLICABLE and signs the message directly
// (ed25519 hashes internally with SHA-512, so the payload must NOT be
// pre-hashed). It returns the 64-byte signature split as R = sig[0:32],
// S = sig[32:64], V = "00" (fixed for response-shape compatibility), plus the
// public key hex for the receipt. The caller zeroizes priv (the seed).
func (ed25519Curve) Sign(priv []byte, payload []byte, hashFunction string) (Signature, string, error) {
	if hashFunction != HashFunctionNotApplicable {
		return Signature{}, "", fmt.Errorf("ed25519 keys require hashFunction HASH_FUNCTION_NOT_APPLICABLE")
	}
	if len(priv) != ed25519.SeedSize {
		return Signature{}, "", fmt.Errorf("keys: ed25519 seed must be %d bytes, got %d", ed25519.SeedSize, len(priv))
	}
	signer := ed25519.NewKeyFromSeed(priv)
	sig := ed25519.Sign(signer, payload)
	pubHex := hex.EncodeToString(signer.Public().(ed25519.PublicKey))
	return Signature{
		R: hex.EncodeToString(sig[0:32]),
		S: hex.EncodeToString(sig[32:64]),
		V: "00", // not applicable for ed25519; fixed for response-shape compatibility
	}, pubHex, nil
}
