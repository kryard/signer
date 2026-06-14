package keys

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/mr-tron/base58"
)

func TestEd25519FromSeedHexKnownVector(t *testing.T) {
	// The ed25519 public key for the all-zero 32-byte seed is a well-known vector.
	const zeroSeed = "0000000000000000000000000000000000000000000000000000000000000000"
	const wantPub = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"

	gen, err := Ed25519FromSeedHex(zeroSeed)
	if err != nil {
		t.Fatalf("Ed25519FromSeedHex: %v", err)
	}
	if gen.PublicKey != wantPub {
		t.Errorf("PublicKey = %q, want %q", gen.PublicKey, wantPub)
	}
	// The Solana address is base58 of the 32-byte public key; decoding it must
	// yield exactly that public key.
	decoded, err := base58.Decode(gen.Address)
	if err != nil {
		t.Fatalf("address %q is not valid base58: %v", gen.Address, err)
	}
	if hex.EncodeToString(decoded) != wantPub {
		t.Errorf("base58-decoded address = %x, want %s", decoded, wantPub)
	}
	if hex.EncodeToString(gen.PrivateKey) != zeroSeed {
		t.Errorf("seed = %x, want %s", gen.PrivateKey, zeroSeed)
	}
}

func TestGenerateEd25519AndSign(t *testing.T) {
	gen, err := GenerateEd25519()
	if err != nil {
		t.Fatalf("GenerateEd25519: %v", err)
	}
	if len(gen.PrivateKey) != ed25519.SeedSize {
		t.Fatalf("seed len = %d, want %d", len(gen.PrivateKey), ed25519.SeedSize)
	}
	pubBytes, err := hex.DecodeString(gen.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		t.Fatalf("public key hex invalid: %v (len %d)", err, len(pubBytes))
	}
	if dec, _ := base58.Decode(gen.Address); hex.EncodeToString(dec) != gen.PublicKey {
		t.Errorf("address %q does not base58-decode to the public key", gen.Address)
	}

	msg := []byte("solana transaction message bytes")
	sig, err := SignEd25519(gen.PrivateKey, msg)
	if err != nil {
		t.Fatalf("SignEd25519: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("sig len = %d, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pubBytes, msg, sig) {
		t.Error("signature did not verify against the public key")
	}
	if ed25519.Verify(pubBytes, []byte("tampered message"), sig) {
		t.Error("signature wrongly verified against a different message")
	}

	// The receipt's public key (derived from the seed) must match.
	pkHex, err := Ed25519PublicKeyHex(gen.PrivateKey)
	if err != nil || pkHex != gen.PublicKey {
		t.Errorf("Ed25519PublicKeyHex = %q (err %v), want %q", pkHex, err, gen.PublicKey)
	}
}

func TestEd25519RejectsBadSeedLength(t *testing.T) {
	if _, err := Ed25519FromSeedHex("00"); err == nil {
		t.Error("expected error for a too-short seed")
	}
	if _, err := SignEd25519([]byte{1, 2, 3}, []byte("x")); err == nil {
		t.Error("expected error signing with a bad-length seed")
	}
	if _, err := Ed25519PublicKeyHex(make([]byte, 16)); err == nil {
		t.Error("expected error deriving pubkey from a bad-length seed")
	}
}
