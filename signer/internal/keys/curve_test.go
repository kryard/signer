package keys_test

import (
	"encoding/hex"
	"testing"

	gocrypto "github.com/ethereum/go-ethereum/crypto"

	"kryard/signer/internal/keys"
)

// TestRegistryHasAllCurves asserts the three curves self-register at init.
func TestRegistryHasAllCurves(t *testing.T) {
	for _, name := range []string{keys.CurveSecp256k1, keys.CurveEd25519, keys.CurveP256} {
		if _, ok := keys.Lookup(name); !ok {
			t.Errorf("curve %q not registered", name)
		}
	}

	got := keys.RegisteredCurves()
	if len(got) < 3 {
		t.Errorf("RegisteredCurves() = %v, want at least 3", got)
	}
	// RegisteredCurves must be sorted (used in deterministic error messages).
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Errorf("RegisteredCurves() not sorted: %v", got)
			break
		}
	}
}

func TestLookupUnknownCurve(t *testing.T) {
	if _, ok := keys.Lookup("CURVE_DOES_NOT_EXIST"); ok {
		t.Error("Lookup of unknown curve returned ok=true")
	}
}

func secp256k1Lookup(t *testing.T) keys.Curve {
	t.Helper()
	c, ok := keys.Lookup(keys.CurveSecp256k1)
	if !ok {
		t.Fatal("CURVE_SECP256K1 not registered")
	}
	return c
}

// TestSecp256k1ImportKnownVector imports the well-known Ganache #0 vector and
// checks the inline Ethereum address derivation through the curve interface.
// Private key: 0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d
// Expected address: 0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1
func TestSecp256k1ImportKnownVector(t *testing.T) {
	c := secp256k1Lookup(t)
	const privHex = "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"
	const wantAddr = "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"

	gen, err := c.Import(privHex)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if len(gen.PrivateKey) != 32 {
		t.Errorf("PrivateKey length = %d, want 32", len(gen.PrivateKey))
	}
	if len(gen.PublicKey) != 66 {
		t.Errorf("PublicKey hex length = %d, want 66 (33 bytes compressed)", len(gen.PublicKey))
	}
	addr, err := c.DefaultAddress(gen.PublicKey)
	if err != nil {
		t.Fatalf("DefaultAddress: %v", err)
	}
	if addr != wantAddr {
		t.Errorf("Address = %q, want %q", addr, wantAddr)
	}
	if c.DefaultAddressFormat() != keys.AddressFormatEthereum {
		t.Errorf("DefaultAddressFormat = %q, want %q", c.DefaultAddressFormat(), keys.AddressFormatEthereum)
	}
	// Import with a 0x prefix yields the same address.
	gen2, err := c.Import("0x" + privHex)
	if err != nil {
		t.Fatalf("Import with prefix: %v", err)
	}
	addr2, _ := c.DefaultAddress(gen2.PublicKey)
	if addr2 != wantAddr {
		t.Errorf("prefixed Address = %q, want %q", addr2, wantAddr)
	}
}

// TestSecp256k1GenerateSignRecover generates a key, signs a keccak digest, and
// verifies the signature recovers to the key's address — all through the curve.
func TestSecp256k1GenerateSignRecover(t *testing.T) {
	c := secp256k1Lookup(t)
	gen, err := c.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	wantAddr, err := c.DefaultAddress(gen.PublicKey)
	if err != nil {
		t.Fatalf("DefaultAddress: %v", err)
	}

	payload := []byte("hello, kryard signing test")
	sig, pubHex, err := c.Sign(gen.PrivateKey, payload, keys.HashFunctionKeccak256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if pubHex != gen.PublicKey {
		t.Errorf("receipt pubkey = %q, want %q", pubHex, gen.PublicKey)
	}
	if sig.V != "00" && sig.V != "01" {
		t.Fatalf("v = %q, want 00 or 01", sig.V)
	}

	digest := gocrypto.Keccak256(payload)
	rBytes, _ := hex.DecodeString(sig.R)
	sBytes, _ := hex.DecodeString(sig.S)
	vByte := byte(0)
	if sig.V == "01" {
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
	if got := gocrypto.PubkeyToAddress(*recoveredPub).Hex(); got != wantAddr {
		t.Errorf("recovered address = %q, want %q", got, wantAddr)
	}
}

// TestSecp256k1NoOpRejectsNon32Bytes verifies HASH_FUNCTION_NO_OP requires a
// 32-byte payload, and an unknown hash function is rejected.
func TestSecp256k1NoOpRejectsNon32Bytes(t *testing.T) {
	c := secp256k1Lookup(t)
	gen, err := c.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, _, err := c.Sign(gen.PrivateKey, make([]byte, 31), keys.HashFunctionNoOp); err == nil {
		t.Error("expected error for a 31-byte NO_OP payload")
	}
	if _, _, err := c.Sign(gen.PrivateKey, make([]byte, 32), "HASH_FUNCTION_BOGUS"); err == nil {
		t.Error("expected error for an unsupported hash function")
	}
}
