package keys_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/mr-tron/base58"

	"kryard/signer/internal/keys"
)

func ed25519Lookup(t *testing.T) keys.Curve {
	t.Helper()
	c, ok := keys.Lookup(keys.CurveEd25519)
	if !ok {
		t.Fatal("CURVE_ED25519 not registered")
	}
	return c
}

func TestEd25519ImportKnownVector(t *testing.T) {
	c := ed25519Lookup(t)
	// The ed25519 public key for the all-zero 32-byte seed is a well-known vector.
	const zeroSeed = "0000000000000000000000000000000000000000000000000000000000000000"
	const wantPub = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"

	gen, err := c.Import(zeroSeed)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if gen.PublicKey != wantPub {
		t.Errorf("PublicKey = %q, want %q", gen.PublicKey, wantPub)
	}
	addr, err := c.DefaultAddress(gen.PublicKey)
	if err != nil {
		t.Fatalf("DefaultAddress: %v", err)
	}
	decoded, err := base58.Decode(addr)
	if err != nil {
		t.Fatalf("address %q is not valid base58: %v", addr, err)
	}
	if hex.EncodeToString(decoded) != wantPub {
		t.Errorf("base58-decoded address = %x, want %s", decoded, wantPub)
	}
	if c.DefaultAddressFormat() != keys.AddressFormatSolana {
		t.Errorf("DefaultAddressFormat = %q, want %q", c.DefaultAddressFormat(), keys.AddressFormatSolana)
	}
	if hex.EncodeToString(gen.PrivateKey) != zeroSeed {
		t.Errorf("seed = %x, want %s", gen.PrivateKey, zeroSeed)
	}
}

func TestEd25519GenerateAndSign(t *testing.T) {
	c := ed25519Lookup(t)
	gen, err := c.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(gen.PrivateKey) != ed25519.SeedSize {
		t.Fatalf("seed len = %d, want %d", len(gen.PrivateKey), ed25519.SeedSize)
	}
	pubBytes, err := hex.DecodeString(gen.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		t.Fatalf("public key hex invalid: %v (len %d)", err, len(pubBytes))
	}
	addr, err := c.DefaultAddress(gen.PublicKey)
	if err != nil {
		t.Fatalf("DefaultAddress: %v", err)
	}
	if dec, _ := base58.Decode(addr); hex.EncodeToString(dec) != gen.PublicKey {
		t.Errorf("address %q does not base58-decode to the public key", addr)
	}

	msg := []byte("solana transaction message bytes")
	sig, pubHex, err := c.Sign(gen.PrivateKey, msg, "HASH_FUNCTION_NOT_APPLICABLE")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.V != "00" {
		t.Errorf("v = %q, want 00", sig.V)
	}
	if pubHex != gen.PublicKey {
		t.Errorf("receipt pubkey = %q, want %q", pubHex, gen.PublicKey)
	}
	rBytes, _ := hex.DecodeString(sig.R)
	sBytes, _ := hex.DecodeString(sig.S)
	full := append(append([]byte{}, rBytes...), sBytes...)
	if len(full) != ed25519.SignatureSize {
		t.Fatalf("reconstructed sig len = %d, want %d", len(full), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pubBytes, msg, full) {
		t.Error("signature did not verify against the public key")
	}
	if ed25519.Verify(pubBytes, []byte("tampered message"), full) {
		t.Error("signature wrongly verified against a different message")
	}
}

func TestEd25519RejectsWrongHashFunction(t *testing.T) {
	c := ed25519Lookup(t)
	gen, err := c.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, _, err := c.Sign(gen.PrivateKey, []byte("x"), "HASH_FUNCTION_KECCAK256"); err == nil {
		t.Error("expected error signing ed25519 with KECCAK256 hash function")
	}
}

func TestEd25519RejectsBadSeedLength(t *testing.T) {
	c := ed25519Lookup(t)
	if _, err := c.Import("00"); err == nil {
		t.Error("expected error for a too-short seed")
	}
	if _, _, err := c.Sign([]byte{1, 2, 3}, []byte("x"), "HASH_FUNCTION_NOT_APPLICABLE"); err == nil {
		t.Error("expected error signing with a bad-length seed")
	}
}
