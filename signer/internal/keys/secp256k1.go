package keys

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// CurveSecp256k1 is the wire name for the secp256k1 curve (EVM and other
// secp256k1 chains). It is the default curve for backward compatibility.
const CurveSecp256k1 = "CURVE_SECP256K1"

// AddressFormatEthereum is the wire address-format identifier for EIP-55
// checksummed Ethereum addresses, the secp256k1 default.
const AddressFormatEthereum = "ADDRESS_FORMAT_ETHEREUM"

// secp256k1Curve implements the Curve interface for secp256k1 keys using
// go-ethereum's audited crypto package.
type secp256k1Curve struct{}

func init() { Register(secp256k1Curve{}) }

func (secp256k1Curve) Name() string { return CurveSecp256k1 }

// Generate creates a fresh secp256k1 key pair. The caller MUST zeroize
// PrivateKey after it has been envelope-encrypted.
func (secp256k1Curve) Generate() (Generated, error) {
	k, err := crypto.GenerateKey()
	if err != nil {
		return Generated{}, fmt.Errorf("keys: crypto.GenerateKey: %w", err)
	}
	return Generated{
		PrivateKey: crypto.FromECDSA(k),
		PublicKey:  hex.EncodeToString(crypto.CompressPubkey(&k.PublicKey)),
	}, nil
}

// Import validates a hex-encoded private key (with or without 0x prefix) and
// derives the compressed public key. Used exclusively for the guarded import
// path; the resulting PrivateKey must be zeroized after use.
func (secp256k1Curve) Import(hexKey string) (Generated, error) {
	privHex := strings.TrimPrefix(hexKey, "0x")
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
	}, nil
}

// DefaultAddressFormat returns ADDRESS_FORMAT_ETHEREUM.
func (secp256k1Curve) DefaultAddressFormat() string { return AddressFormatEthereum }

// DefaultAddress derives the EIP-55 checksummed Ethereum address from a
// compressed secp256k1 public key hex. The signer has no address engine, so the
// derivation is inline: decompress the public key, then take the go-ethereum
// address.
func (secp256k1Curve) DefaultAddress(publicKeyHex string) (string, error) {
	pubBytes, err := decodeHex(publicKeyHex)
	if err != nil {
		return "", fmt.Errorf("keys: invalid secp256k1 public key hex: %w", err)
	}
	pub, err := crypto.DecompressPubkey(pubBytes)
	if err != nil {
		return "", fmt.Errorf("keys: invalid compressed secp256k1 public key: %w", err)
	}
	return crypto.PubkeyToAddress(*pub).Hex(), nil
}

// Sign validates the secp256k1 hash function (KECCAK256 or NO_OP), computes the
// 32-byte digest, signs it, and returns R/S/V plus the recovered compressed
// public key hex for the receipt. The caller zeroizes priv.
func (secp256k1Curve) Sign(priv []byte, payload []byte, hashFunction string) (Signature, string, error) {
	var digest []byte
	switch hashFunction {
	case HashFunctionKeccak256:
		digest = crypto.Keccak256(payload)
	case HashFunctionNoOp:
		if len(payload) != 32 {
			return Signature{}, "", fmt.Errorf("HASH_FUNCTION_NO_OP requires a 32-byte payload, got %d bytes", len(payload))
		}
		digest = payload
	default:
		return Signature{}, "", fmt.Errorf("unsupported hashFunction %q for secp256k1; use HASH_FUNCTION_KECCAK256 or HASH_FUNCTION_NO_OP", hashFunction)
	}

	ecKey, err := crypto.ToECDSA(priv)
	if err != nil {
		return Signature{}, "", fmt.Errorf("keys: invalid private key: %w", err)
	}

	// crypto.Sign returns [R||S||V] (65 bytes). V is 0 or 1 (the recovery id, NOT
	// the EIP-155 chain-adjusted value).
	sig, err := crypto.Sign(digest, ecKey)
	if err != nil {
		return Signature{}, "", fmt.Errorf("keys: crypto.Sign: %w", err)
	}
	r := hex.EncodeToString(sig[0:32])
	s := hex.EncodeToString(sig[32:64])
	v := "00"
	if sig[64] == 1 {
		v = "01"
	}

	// Recover the compressed public key for the receipt from [R||S||V].
	pubKeyHex := ""
	if recoveredPub, pubErr := crypto.SigToPub(digest, sig); pubErr == nil {
		pubKeyHex = hex.EncodeToString(crypto.CompressPubkey(recoveredPub))
	}

	return Signature{R: r, S: s, V: v}, pubKeyHex, nil
}
