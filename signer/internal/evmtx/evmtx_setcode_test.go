package evmtx_test

import (
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"

	"kryard/signer/internal/evmtx"
)

// A second well-known key plays the authorizing EOA ("the user"); the relayer
// (testKey, Ganache #0) signs the OUTER type-4 transaction and pays gas.
// Ganache account #1.
const (
	userPrivHex    = "6cbed15c793ce57650b9877cf6fa156fbef513c4e6134f022a85b1ffdd59b2a1"
	userKeyAddress = "0xFFcf8FDEE72ac11b5c542428B35EEF5769C409f0"
	// The delegate implementation the user delegates their EOA to.
	delegateImplAddr = "0x00000000000000000000000000000000DEADbeEF"
	exampleSelector    = "0x7fea8778"
)

// authTuple mirrors a single EIP-7702 authorization tuple for RLP encoding:
// [chainId, address, nonce, yParity, r, s].
type authTuple struct {
	ChainID *big.Int
	Address common.Address
	Nonce   uint64
	YParity uint64
	R       *big.Int
	S       *big.Int
}

// setCodeUnsigned mirrors the EIP-7702 unsigned tx RLP (10 fields, no outer
// v/r/s) so the test can build a valid unsigned type-4 tx hex to feed the signer.
type setCodeUnsigned struct {
	ChainID              *big.Int
	Nonce                uint64
	MaxPriorityFeePerGas *big.Int
	MaxFeePerGas         *big.Int
	Gas                  uint64
	To                   common.Address
	Value                *big.Int
	Data                 []byte
	AccessList           types.AccessList
	AuthList             []authTuple
}

func loadKey(t *testing.T, privHex string) *ecdsa.PrivateKey {
	t.Helper()
	k, err := crypto.HexToECDSA(privHex)
	if err != nil {
		t.Fatalf("HexToECDSA: %v", err)
	}
	return k
}

// buildUnsignedSetCodeTx constructs a valid unsigned EIP-7702 tx hex: the user
// signs an authorization delegating their EOA to delegateImplAddr, and the tx
// (sent by the relayer) calls the user's now-delegated EOA with example calldata.
func buildUnsignedSetCodeTx(t *testing.T, chainID *big.Int) (unsignedHex string, userAddr common.Address) {
	t.Helper()
	userKey := loadKey(t, userPrivHex)
	userAddr = crypto.PubkeyToAddress(userKey.PublicKey)

	cid, _ := uint256.FromBig(chainID)
	auth := types.SetCodeAuthorization{
		ChainID: *cid,
		Address: common.HexToAddress(delegateImplAddr),
		Nonce:   0,
	}
	signedAuth, err := types.SignSetCode(userKey, auth)
	if err != nil {
		t.Fatalf("SignSetCode: %v", err)
	}

	data, _ := hex.DecodeString(strings.TrimPrefix(exampleSelector, "0x"))

	unsigned := setCodeUnsigned{
		ChainID:              chainID,
		Nonce:                0,
		MaxPriorityFeePerGas: big.NewInt(1_000_000_000),
		MaxFeePerGas:         big.NewInt(1_000_000_000),
		Gas:                  200_000,
		To:                   userAddr, // 7702: relayer calls the user's delegated EOA
		Value:                big.NewInt(0),
		Data:                 data,
		AccessList:           types.AccessList{},
		AuthList: []authTuple{{
			ChainID: signedAuth.ChainID.ToBig(),
			Address: signedAuth.Address,
			Nonce:   signedAuth.Nonce,
			YParity: uint64(signedAuth.V),
			R:       signedAuth.R.ToBig(),
			S:       signedAuth.S.ToBig(),
		}},
	}

	payload, err := rlp.EncodeToBytes(&unsigned)
	if err != nil {
		t.Fatalf("rlp encode unsigned set-code tx: %v", err)
	}
	return "0x" + hex.EncodeToString(append([]byte{0x04}, payload...)), userAddr
}

// TestSetCodeSignAndRecover signs a type-4 (EIP-7702) tx with the relayer key and
// verifies: the output is a valid type-4 tx, the OUTER signature recovers to the
// relayer, and the inner authorization's authority recovers to the user.
func TestSetCodeSignAndRecover(t *testing.T) {
	relayer := loadTestKey(t)
	chainID := big.NewInt(sepoliaChainID)

	unsignedHex, userAddr := buildUnsignedSetCodeTx(t, chainID)

	result, err := evmtx.SignUnsignedTx(unsignedHex, relayer)
	if err != nil {
		t.Fatalf("SignUnsignedTx EIP-7702: %v", err)
	}
	if !strings.HasPrefix(result.SignedTransaction, "0x") {
		t.Errorf("SignedTransaction missing 0x prefix: %q", result.SignedTransaction)
	}

	// Decode the signed tx and assert it is a type-4 transaction.
	raw, err := hex.DecodeString(strings.TrimPrefix(result.SignedTransaction, "0x"))
	if err != nil {
		t.Fatalf("decode signed tx: %v", err)
	}
	var tx types.Transaction
	if err := tx.UnmarshalBinary(raw); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if tx.Type() != types.SetCodeTxType {
		t.Fatalf("tx type = %d, want %d (SetCodeTxType)", tx.Type(), types.SetCodeTxType)
	}

	// OUTER signature must recover to the relayer.
	recovered := recoverSender(t, result.SignedTransaction, chainID)
	if !strings.EqualFold(recovered, testKeyAddress) {
		t.Errorf("outer sender = %q, want relayer %q", recovered, testKeyAddress)
	}

	// The inner authorization must be preserved and its authority recover to the user.
	auths := tx.SetCodeAuthorizations()
	if len(auths) != 1 {
		t.Fatalf("authorization count = %d, want 1", len(auths))
	}
	if !strings.EqualFold(auths[0].Address.Hex(), delegateImplAddr) {
		t.Errorf("delegate address = %q, want %q", auths[0].Address.Hex(), delegateImplAddr)
	}
	authority, err := auths[0].Authority()
	if err != nil {
		t.Fatalf("Authority(): %v", err)
	}
	if !strings.EqualFold(authority.Hex(), userAddr.Hex()) {
		t.Errorf("authorization authority = %q, want user %q", authority.Hex(), userAddr.Hex())
	}

	// Fields: `to` is the user EOA; the delegate impl is surfaced separately.
	if !strings.EqualFold(result.Fields.To, userAddr.Hex()) {
		t.Errorf("fields.To = %q, want user EOA %q", result.Fields.To, userAddr.Hex())
	}
	if result.Fields.MethodSelector != exampleSelector {
		t.Errorf("fields.MethodSelector = %q, want %q", result.Fields.MethodSelector, exampleSelector)
	}
	if len(result.Fields.AuthorizationAddresses) != 1 ||
		!strings.EqualFold(result.Fields.AuthorizationAddresses[0], delegateImplAddr) {
		t.Errorf("fields.AuthorizationAddresses = %v, want [%s]", result.Fields.AuthorizationAddresses, delegateImplAddr)
	}

	// The recovered authority must be the user EOA (used by policy to bind `to`).
	if len(result.Fields.AuthorizationAuthorities) != 1 ||
		!strings.EqualFold(result.Fields.AuthorizationAuthorities[0], userAddr.Hex()) {
		t.Errorf("fields.AuthorizationAuthorities = %v, want [%s]", result.Fields.AuthorizationAuthorities, userAddr.Hex())
	}
}

// TestSetCodeParseMatchesSign asserts ParseUnsignedTx (no key) extracts the same
// policy-relevant fields the signer extracts.
func TestSetCodeParseMatchesSign(t *testing.T) {
	chainID := big.NewInt(sepoliaChainID)
	unsignedHex, userAddr := buildUnsignedSetCodeTx(t, chainID)

	fields, err := evmtx.ParseUnsignedTx(unsignedHex)
	if err != nil {
		t.Fatalf("ParseUnsignedTx EIP-7702: %v", err)
	}
	if !strings.EqualFold(fields.To, userAddr.Hex()) {
		t.Errorf("parse fields.To = %q, want %q", fields.To, userAddr.Hex())
	}
	if fields.MethodSelector != exampleSelector {
		t.Errorf("parse fields.MethodSelector = %q, want %q", fields.MethodSelector, exampleSelector)
	}
	if len(fields.AuthorizationAddresses) != 1 ||
		!strings.EqualFold(fields.AuthorizationAddresses[0], delegateImplAddr) {
		t.Errorf("parse fields.AuthorizationAddresses = %v, want [%s]", fields.AuthorizationAddresses, delegateImplAddr)
	}
}

// TestSetCodeRejectsEmptyAuthList rejects a type-4 tx with no authorizations.
func TestSetCodeRejectsEmptyAuthList(t *testing.T) {
	relayer := loadTestKey(t)
	chainID := big.NewInt(sepoliaChainID)

	unsigned := setCodeUnsigned{
		ChainID:              chainID,
		Nonce:                0,
		MaxPriorityFeePerGas: big.NewInt(1_000_000_000),
		MaxFeePerGas:         big.NewInt(1_000_000_000),
		Gas:                  200_000,
		To:                   common.HexToAddress(userKeyAddress),
		Value:                big.NewInt(0),
		Data:                 []byte{},
		AccessList:           types.AccessList{},
		AuthList:             []authTuple{}, // empty — invalid per EIP-7702
	}
	payload, err := rlp.EncodeToBytes(&unsigned)
	if err != nil {
		t.Fatalf("rlp encode: %v", err)
	}
	unsignedHex := "0x" + hex.EncodeToString(append([]byte{0x04}, payload...))

	if _, err := evmtx.SignUnsignedTx(unsignedHex, relayer); err == nil {
		t.Fatal("expected error signing type-4 tx with empty authorization_list, got nil")
	}
}
