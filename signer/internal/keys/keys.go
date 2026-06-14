package keys

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// Generated holds a secp256k1 key pair with its Ethereum metadata.
// The PrivateKey field contains the raw 32-byte scalar; the caller MUST
// zeroize it after envelope-encrypting it.
type Generated struct {
	PrivateKey []byte // 32-byte secp256k1 scalar — caller must zeroize
	PublicKey  string // compressed-point hex (33 bytes = 66 hex chars)
	Address    string // EIP-55 checksummed 0x... Ethereum address
}

// GenerateSecp256k1 creates a fresh secp256k1 key pair using go-ethereum's
// audited crypto package. The caller is responsible for zeroizing PrivateKey
// after it has been envelope-encrypted.
func GenerateSecp256k1() (Generated, error) {
	k, err := crypto.GenerateKey()
	if err != nil {
		return Generated{}, fmt.Errorf("keys: crypto.GenerateKey: %w", err)
	}
	return Generated{
		PrivateKey: crypto.FromECDSA(k),
		PublicKey:  hex.EncodeToString(crypto.CompressPubkey(&k.PublicKey)),
		Address:    crypto.PubkeyToAddress(k.PublicKey).Hex(),
	}, nil
}

// FromPrivateKeyHex validates a hex-encoded private key (with or without 0x prefix)
// and derives the compressed public key and Ethereum address. Used exclusively for
// the guarded import path; the resulting PrivateKey must be zeroized after use.
func FromPrivateKeyHex(privHex string) (Generated, error) {
	privHex = strings.TrimPrefix(privHex, "0x")
	if privHex == "" {
		return Generated{}, fmt.Errorf("keys: private key hex is empty")
	}
	k, err := crypto.HexToECDSA(privHex)
	if err != nil {
		return Generated{}, fmt.Errorf("keys: invalid private key hex: %w", err)
	}
	return Generated{
		PrivateKey: crypto.FromECDSA(k),
		PublicKey:  hex.EncodeToString(crypto.CompressPubkey(&k.PublicKey)),
		Address:    crypto.PubkeyToAddress(k.PublicKey).Hex(),
	}, nil
}
