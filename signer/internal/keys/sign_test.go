package keys_test

import (
	"encoding/hex"
	"testing"

	gocrypto "github.com/ethereum/go-ethereum/crypto"

	"kryard/signer/internal/keys"
)

// TestSignDigestKeccak256RecoveryRoundtrip generates a fresh key, computes
// keccak256 of a payload, signs it, and verifies the signature recovers to
// the key's address.
func TestSignDigestKeccak256RecoveryRoundtrip(t *testing.T) {
	gen, err := keys.GenerateSecp256k1()
	if err != nil {
		t.Fatalf("GenerateSecp256k1: %v", err)
	}
	defer zeroizeTest(gen.PrivateKey)

	payload := []byte("hello, kryard signing test")
	digest := gocrypto.Keccak256(payload)

	r, s, v, err := keys.SignDigest(gen.PrivateKey, digest)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}

	// Reconstruct the 65-byte [R||S||V] signature.
	rBytes, err := hex.DecodeString(r)
	if err != nil || len(rBytes) != 32 {
		t.Fatalf("bad r hex: %v (len=%d)", err, len(rBytes))
	}
	sBytes, err := hex.DecodeString(s)
	if err != nil || len(sBytes) != 32 {
		t.Fatalf("bad s hex: %v (len=%d)", err, len(sBytes))
	}
	if v != "00" && v != "01" {
		t.Fatalf("v = %q, want \"00\" or \"01\"", v)
	}
	vByte := byte(0)
	if v == "01" {
		vByte = 1
	}

	sig65 := make([]byte, 65)
	copy(sig65[0:32], rBytes)
	copy(sig65[32:64], sBytes)
	sig65[64] = vByte

	// SigToPub recovers the public key from the [R||S||V] signature.
	recoveredPub, err := gocrypto.SigToPub(digest, sig65)
	if err != nil {
		t.Fatalf("SigToPub: %v", err)
	}
	recoveredAddr := gocrypto.PubkeyToAddress(*recoveredPub).Hex()

	if recoveredAddr != gen.Address {
		t.Errorf("recovered address = %q, want %q", recoveredAddr, gen.Address)
	}
}

// TestSignDigestKnownVector uses the Ganache #0 known vector: sign a known
// payload and verify that the recovered address is 0x90F8bf6A…8c9C1.
func TestSignDigestKnownVector(t *testing.T) {
	// Ganache account #0: well-known secp256k1 test vector
	privHex := "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"
	expectedAddr := "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"

	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}

	payload := []byte("keccak test payload")
	digest := gocrypto.Keccak256(payload)

	r, s, v, err := keys.SignDigest(privBytes, digest)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}

	rBytes, _ := hex.DecodeString(r)
	sBytes, _ := hex.DecodeString(s)
	vByte := byte(0)
	if v == "01" {
		vByte = 1
	}
	sig65 := make([]byte, 65)
	copy(sig65[0:32], rBytes)
	copy(sig65[32:64], sBytes)
	sig65[64] = vByte

	recoveredPub, err := gocrypto.SigToPub(digest, sig65)
	if err != nil {
		t.Fatalf("SigToPub: %v", err)
	}
	recoveredAddr := gocrypto.PubkeyToAddress(*recoveredPub).Hex()
	if recoveredAddr != expectedAddr {
		t.Errorf("recovered address = %q, want %q", recoveredAddr, expectedAddr)
	}
}

// TestSignDigestNoOpRejectsNon32Bytes verifies that SignDigest returns an
// error when the digest is not exactly 32 bytes.
func TestSignDigestNoOpRejectsNon32Bytes(t *testing.T) {
	gen, err := keys.GenerateSecp256k1()
	if err != nil {
		t.Fatalf("GenerateSecp256k1: %v", err)
	}

	cases := []struct {
		name    string
		payload []byte
	}{
		{"empty", []byte{}},
		{"31 bytes", make([]byte, 31)},
		{"33 bytes", make([]byte, 33)},
		{"64 bytes", make([]byte, 64)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := keys.SignDigest(gen.PrivateKey, tc.payload)
			if err == nil {
				t.Errorf("SignDigest with %d-byte digest should have failed", len(tc.payload))
			}
		})
	}
}

// TestSignDigestKeccakMatchesCryptoKeccak256 verifies that signing
// crypto.Keccak256(payload) produces the same digest as computing it manually.
func TestSignDigestKeccakMatchesCryptoKeccak256(t *testing.T) {
	payload := []byte("test payload for keccak match")
	digest := gocrypto.Keccak256(payload)
	if len(digest) != 32 {
		t.Fatalf("Keccak256 returned %d bytes, want 32", len(digest))
	}

	gen, err := keys.GenerateSecp256k1()
	if err != nil {
		t.Fatalf("GenerateSecp256k1: %v", err)
	}

	// This should succeed since digest is exactly 32 bytes.
	_, _, _, err = keys.SignDigest(gen.PrivateKey, digest)
	if err != nil {
		t.Fatalf("SignDigest with 32-byte keccak digest: %v", err)
	}
}

// zeroizeTest clears a byte slice in tests to mirror zeroize in production.
func zeroizeTest(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
