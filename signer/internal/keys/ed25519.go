package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/mr-tron/base58"
)

// GenerateEd25519 creates a fresh ed25519 key pair with its Solana metadata.
//
// The returned PrivateKey holds the 32-byte ed25519 *seed* (the canonical, minimal
// representation of the key); the caller MUST zeroize it after envelope-encrypting
// it. PublicKey is the 32-byte ed25519 public key in hex, and Address is the
// base58-encoded public key — a Solana account address (ADDRESS_FORMAT_SOLANA).
func GenerateEd25519() (Generated, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Generated{}, fmt.Errorf("keys: ed25519.GenerateKey: %w", err)
	}
	return Generated{
		PrivateKey: priv.Seed(), // 32-byte seed
		PublicKey:  hex.EncodeToString(pub),
		Address:    base58.Encode(pub),
	}, nil
}

// Ed25519FromSeedHex validates a hex-encoded 32-byte ed25519 seed (with or without
// 0x prefix) and derives the public key and Solana address. Used exclusively for the
// guarded import path; the resulting PrivateKey (the seed) must be zeroized after use.
func Ed25519FromSeedHex(seedHex string) (Generated, error) {
	seedHex = strings.TrimPrefix(seedHex, "0x")
	if seedHex == "" {
		return Generated{}, fmt.Errorf("keys: ed25519 seed hex is empty")
	}
	seed, err := hex.DecodeString(seedHex)
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
		Address:    base58.Encode(pub),
	}, nil
}

// SignEd25519 signs an arbitrary-length message with the ed25519 key derived from
// the given 32-byte seed and returns the 64-byte signature.
//
// Unlike ECDSA, ed25519 signs the message directly (it hashes internally with
// SHA-512), so the caller must NOT pre-hash the payload. The caller is responsible
// for zeroizing seed after this call.
func SignEd25519(seed []byte, message []byte) ([]byte, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("keys: ed25519 seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return ed25519.Sign(ed25519.NewKeyFromSeed(seed), message), nil
}

// Ed25519PublicKeyHex derives the hex-encoded public key from a 32-byte seed. Used
// for the signer receipt (which never contains private key material).
func Ed25519PublicKeyHex(seed []byte) (string, error) {
	if len(seed) != ed25519.SeedSize {
		return "", fmt.Errorf("keys: ed25519 seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return hex.EncodeToString(priv.Public().(ed25519.PublicKey)), nil
}
