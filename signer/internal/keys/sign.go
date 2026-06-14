package keys

import (
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

// SignDigest signs a 32-byte digest with the secp256k1 private key and returns
// r, s, v as lowercase hex strings. v is "00" or "01" (the recovery id).
//
// Uses go-ethereum crypto.Sign which produces [R||S||V] (65 bytes) where
// V is already the recovery id (0 or 1), NOT the EIP-155 chain-adjusted value.
// The caller is responsible for zeroizing privKey after this call.
func SignDigest(privKey []byte, digest []byte) (r, s, v string, err error) {
	if len(digest) != 32 {
		return "", "", "", fmt.Errorf("keys: digest must be exactly 32 bytes, got %d", len(digest))
	}

	ecKey, e := crypto.ToECDSA(privKey)
	if e != nil {
		return "", "", "", fmt.Errorf("keys: invalid private key: %w", e)
	}

	// crypto.Sign returns [R||S||V] (65 bytes). V is 0 or 1.
	sig, e := crypto.Sign(digest, ecKey)
	if e != nil {
		return "", "", "", fmt.Errorf("keys: crypto.Sign: %w", e)
	}

	// sig[0:32] = R, sig[32:64] = S, sig[64] = V (0 or 1).
	r = hex.EncodeToString(sig[0:32])
	s = hex.EncodeToString(sig[32:64])
	if sig[64] == 0 {
		v = "00"
	} else {
		v = "01"
	}
	return r, s, v, nil
}
