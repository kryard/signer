package keys_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"kryard/signer/internal/keys"
)

func p256Lookup(t *testing.T) keys.Curve {
	t.Helper()
	c, ok := keys.Lookup(keys.CurveP256)
	if !ok {
		t.Fatal("CURVE_P256 not registered")
	}
	return c
}

// TestP256ImportBasePointVector imports scalar=1 and checks the compressed
// public key equals the P-256 base point (a well-known vector).
func TestP256ImportBasePointVector(t *testing.T) {
	c := p256Lookup(t)
	const scalarOne = "0000000000000000000000000000000000000000000000000000000000000001"
	const wantPub = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"

	gen, err := c.Import(scalarOne)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if gen.PublicKey != wantPub {
		t.Errorf("PublicKey = %q, want %q (P-256 base point)", gen.PublicKey, wantPub)
	}
	addr, err := c.DefaultAddress(gen.PublicKey)
	if err != nil {
		t.Fatalf("DefaultAddress: %v", err)
	}
	if addr != wantPub {
		t.Errorf("Address = %q, want %q (compressed pubkey)", addr, wantPub)
	}
	if c.DefaultAddressFormat() != keys.AddressFormatCompressed {
		t.Errorf("DefaultAddressFormat = %q, want %q", c.DefaultAddressFormat(), keys.AddressFormatCompressed)
	}
	if hex.EncodeToString(gen.PrivateKey) != scalarOne {
		t.Errorf("scalar = %x, want %s", gen.PrivateKey, scalarOne)
	}
}

func TestP256GenerateSignVerify(t *testing.T) {
	c := p256Lookup(t)
	gen, err := c.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(gen.PrivateKey) != 32 {
		t.Fatalf("scalar len = %d, want 32", len(gen.PrivateKey))
	}
	// Public key must be a valid compressed P-256 point.
	pubBytes, err := hex.DecodeString(gen.PublicKey)
	if err != nil || len(pubBytes) != 33 {
		t.Fatalf("public key hex invalid: %v (len %d)", err, len(pubBytes))
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pubBytes)
	if x == nil {
		t.Fatal("public key is not a valid compressed P-256 point")
	}

	digestArr := sha256.Sum256([]byte("p256 signing test payload"))
	digest := digestArr[:]
	sig, pubHex, err := c.Sign(gen.PrivateKey, digest, "HASH_FUNCTION_NO_OP")
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
	if len(rBytes) != 32 || len(sBytes) != 32 {
		t.Fatalf("r/s lengths = %d/%d, want 32/32", len(rBytes), len(sBytes))
	}
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if !ecdsa.Verify(pub, digest, r, s) {
		t.Error("P-256 signature did not verify against the returned public key")
	}
	tampered := sha256.Sum256([]byte("different payload"))
	if ecdsa.Verify(pub, tampered[:], r, s) {
		t.Error("P-256 signature wrongly verified against a different digest")
	}
}

func TestP256RejectsWrongHashFunction(t *testing.T) {
	c := p256Lookup(t)
	gen, err := c.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	digest := sha256.Sum256([]byte("x"))
	if _, _, err := c.Sign(gen.PrivateKey, digest[:], "HASH_FUNCTION_KECCAK256"); err == nil {
		t.Error("expected error: p256 requires HASH_FUNCTION_NO_OP")
	}
}

func TestP256RejectsBadSizes(t *testing.T) {
	c := p256Lookup(t)
	gen, err := c.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Non-32-byte digest.
	if _, _, err := c.Sign(gen.PrivateKey, []byte("short"), "HASH_FUNCTION_NO_OP"); err == nil {
		t.Error("expected error for non-32-byte digest")
	}
	// Out-of-range scalar (zero) on import.
	if _, err := c.Import("0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Error("expected error importing zero scalar")
	}
	// Non-32-byte scalar on import.
	if _, err := c.Import("00"); err == nil {
		t.Error("expected error importing too-short scalar")
	}
}
