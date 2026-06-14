package keys_test

import (
	"strings"
	"testing"

	"kryard/signer/internal/keys"
)

func TestGenerateSecp256k1AddressDerivesFromPubkey(t *testing.T) {
	gen, err := keys.GenerateSecp256k1()
	if err != nil {
		t.Fatalf("GenerateSecp256k1: %v", err)
	}

	if len(gen.PrivateKey) != 32 {
		t.Errorf("PrivateKey length = %d, want 32", len(gen.PrivateKey))
	}
	if gen.PublicKey == "" {
		t.Error("PublicKey is empty")
	}
	if !strings.HasPrefix(gen.Address, "0x") {
		t.Errorf("Address = %q, want 0x prefix", gen.Address)
	}
	// Compressed public key is 33 bytes = 66 hex chars
	if len(gen.PublicKey) != 66 {
		t.Errorf("PublicKey hex length = %d, want 66 (33 bytes compressed)", len(gen.PublicKey))
	}
	// Address should be 42 chars: "0x" + 40 hex chars
	if len(gen.Address) != 42 {
		t.Errorf("Address length = %d, want 42", len(gen.Address))
	}
}

func TestGenerateSecp256k1UniqueKeys(t *testing.T) {
	g1, err := keys.GenerateSecp256k1()
	if err != nil {
		t.Fatalf("first GenerateSecp256k1: %v", err)
	}
	g2, err := keys.GenerateSecp256k1()
	if err != nil {
		t.Fatalf("second GenerateSecp256k1: %v", err)
	}
	if g1.Address == g2.Address {
		t.Error("two generated keys produced the same address (collision?)")
	}
	if g1.PublicKey == g2.PublicKey {
		t.Error("two generated keys produced the same public key")
	}
}

// TestFromPrivateKeyHexKnownVector tests a well-known secp256k1 test vector.
// Private key: 0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d
// Expected address: 0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1
// (Ganache account #0 deterministic mnemonic; widely used test vector)
func TestFromPrivateKeyHexKnownVector(t *testing.T) {
	privHex := "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"
	expectedAddr := "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"

	gen, err := keys.FromPrivateKeyHex(privHex)
	if err != nil {
		t.Fatalf("FromPrivateKeyHex: %v", err)
	}
	if gen.Address != expectedAddr {
		t.Errorf("Address = %q, want %q", gen.Address, expectedAddr)
	}
	if len(gen.PublicKey) != 66 {
		t.Errorf("PublicKey hex length = %d, want 66", len(gen.PublicKey))
	}
	if len(gen.PrivateKey) != 32 {
		t.Errorf("PrivateKey length = %d, want 32", len(gen.PrivateKey))
	}
}

func TestFromPrivateKeyHexWithPrefix(t *testing.T) {
	// Same vector with 0x prefix
	privHex := "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"
	expectedAddr := "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"

	gen, err := keys.FromPrivateKeyHex(privHex)
	if err != nil {
		t.Fatalf("FromPrivateKeyHex with 0x prefix: %v", err)
	}
	if gen.Address != expectedAddr {
		t.Errorf("Address = %q, want %q", gen.Address, expectedAddr)
	}
}

func TestFromPrivateKeyHexInvalidFails(t *testing.T) {
	cases := []struct {
		name string
		hex  string
	}{
		{"empty", ""},
		{"too short", "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1"},
		{"non-hex", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := keys.FromPrivateKeyHex(tc.hex)
			if err == nil {
				t.Fatalf("FromPrivateKeyHex(%q) should have failed", tc.hex)
			}
		})
	}
}
