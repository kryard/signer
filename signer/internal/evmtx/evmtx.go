// Package evmtx decodes unsigned EVM transactions and signs them using
// go-ethereum's audited core/types and rlp libraries. Callers MUST NOT
// hand-roll RLP, ECDSA, or Keccak-256 — always use the go-ethereum primitives.
package evmtx

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// TxFields holds policy-relevant fields extracted from a decoded unsigned transaction.
// All *big.Int fields are hex strings (0x-prefixed); nil pointers are represented as
// empty strings.
type TxFields struct {
	ChainID              string // hex, e.g. "0xaa36a7" (Sepolia)
	To                   string // "0x..." or "" for contract-create
	Value                string // hex wei
	Nonce                uint64
	Gas                  uint64
	MaxFeePerGas         string // hex (EIP-1559) or "" for legacy
	MaxPriorityFeePerGas string // hex (EIP-1559) or "" for legacy
	GasPrice             string // hex (legacy) or "" for EIP-1559
	Data                 string // 0x-prefixed hex
	MethodSelector       string // first 4 bytes of Data as "0x........", or ""

	// AuthorizationAddresses holds the delegation target addresses from an
	// EIP-7702 (type-4) transaction's authorization_list — the contract code
	// each authorizing EOA delegates to. Empty for type-2 / legacy. Policy uses
	// these to allowlist the delegate IMPLEMENTATION (the `to` of a 7702 sweep
	// is the user's own EOA, not a fixed router, so destination-allowlisting
	// the `to` does not apply).
	AuthorizationAddresses []string

	// AuthorizationAuthorities holds the recovered signer (authority) of each
	// authorization tuple — the EOA that consented to the delegation. Empty for
	// type-2 / legacy. Policy requires the tx `to` to be one of these: a 7702
	// sweep must call an EOA that ACTUALLY authorized the delegation, never an
	// arbitrary target. Tuples whose signature fails to recover are omitted (so
	// they cannot satisfy the `to ∈ authorities` check). Same index order as the
	// authorization_list.
	AuthorizationAuthorities []string
}

// SignResult is returned by SignUnsignedTx.
type SignResult struct {
	// SignedTransaction is the 0x-prefixed hex of the signed transaction
	// (MarshalBinary format: type-byte || RLP for typed, bare RLP for legacy).
	SignedTransaction string
	Fields            TxFields
}

// eip1559UnsignedRLP is the RLP list decoded from an EIP-1559 unsigned transaction.
// The unsigned form has 9 fields: [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
// gas, to, value, data, accessList]. There are NO v/r/s fields.
type eip1559UnsignedRLP struct {
	ChainID              *big.Int
	Nonce                uint64
	MaxPriorityFeePerGas *big.Int
	MaxFeePerGas         *big.Int
	Gas                  uint64
	To                   []byte // 20 bytes, or empty for contract-create
	Value                *big.Int
	Data                 []byte
	AccessList           types.AccessList
}

// legacyUnsignedRLP is the RLP list for a legacy unsigned EIP-155 transaction.
// With EIP-155 replay protection the unsigned form has 9 fields:
//
//	[nonce, gasPrice, gas, to, value, data, chainId, 0, 0]
//
// Without EIP-155 (unlikely but handled) it has 6 fields:
//
//	[nonce, gasPrice, gas, to, value, data]
type legacyUnsignedRLP struct {
	Nonce    uint64
	GasPrice *big.Int
	Gas      uint64
	To       []byte // 20 bytes, or empty for contract-create
	Value    *big.Int
	Data     []byte
	// EIP-155 trailing fields (may be absent in older 6-field transactions).
	V *big.Int
	R *big.Int
	S *big.Int
}

// setCodeUnsignedRLP is the RLP list decoded from an EIP-7702 (type-4) unsigned
// transaction. The unsigned form has 10 fields:
//
//	[chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gas, to, value, data,
//	 accessList, authorizationList]
//
// There are NO outer v/r/s fields (those are added when the relayer signs). The
// authorization tuples inside authorizationList ARE already signed by the
// authorizing EOAs (the users). 7702 has no contract-creation form — `to` is a
// mandatory 20-byte address.
type setCodeUnsignedRLP struct {
	ChainID              *big.Int
	Nonce                uint64
	MaxPriorityFeePerGas *big.Int
	MaxFeePerGas         *big.Int
	Gas                  uint64
	To                   []byte
	Value                *big.Int
	Data                 []byte
	AccessList           types.AccessList
	AuthList             []authTupleRLP
}

// authTupleRLP is a single EIP-7702 authorization tuple:
//
//	[chainId, address, nonce, yParity, r, s]
//
// signed off-chain by the authorizing EOA (MAGIC 0x05 over keccak(rlp([chainId,
// address, nonce]))). We decode it and reconstruct go-ethereum's
// types.SetCodeAuthorization, never hand-rolling the signature recovery.
type authTupleRLP struct {
	ChainID *big.Int
	Address []byte
	Nonce   uint64
	YParity uint64
	R       *big.Int
	S       *big.Int
}

// ParseUnsignedTx decodes an unsigned EVM transaction hex string and returns
// the policy-relevant fields WITHOUT signing. No key material is required.
// Supports the same transaction types as SignUnsignedTx.
func ParseUnsignedTx(unsignedTxHex string) (*TxFields, error) {
	hexStr := unsignedTxHex
	if len(hexStr) >= 2 && (hexStr[:2] == "0x" || hexStr[:2] == "0X") {
		hexStr = hexStr[2:]
	}
	if len(hexStr) == 0 {
		return nil, fmt.Errorf("evmtx: empty unsignedTransaction")
	}

	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("evmtx: invalid hex: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("evmtx: empty transaction bytes")
	}

	if raw[0] == 0x02 {
		var decoded eip1559UnsignedRLP
		if err := rlp.DecodeBytes(raw[1:], &decoded); err != nil {
			return nil, fmt.Errorf("evmtx: EIP-1559 RLP decode: %w", err)
		}
		var toAddr *common.Address
		if len(decoded.To) == 20 {
			addr := common.BytesToAddress(decoded.To)
			toAddr = &addr
		}
		fields := extractFields1559(decoded, toAddr)
		return &fields, nil
	}

	if raw[0] == 0x04 {
		var decoded setCodeUnsignedRLP
		if err := rlp.DecodeBytes(raw[1:], &decoded); err != nil {
			return nil, fmt.Errorf("evmtx: EIP-7702 RLP decode: %w", err)
		}
		fields := extractFieldsSetCode(decoded)
		return &fields, nil
	}

	// Legacy.
	var decoded legacyUnsignedRLP
	if err := rlp.DecodeBytes(raw, &decoded); err != nil {
		return nil, fmt.Errorf("evmtx: legacy RLP decode: %w", err)
	}
	var chainID *big.Int
	if decoded.V != nil && decoded.V.Sign() > 0 {
		rIsZero := decoded.R == nil || decoded.R.Sign() == 0
		sIsZero := decoded.S == nil || decoded.S.Sign() == 0
		if rIsZero && sIsZero {
			chainID = new(big.Int).Set(decoded.V)
		}
	}
	if chainID == nil {
		chainID = big.NewInt(0)
	}
	var toAddr *common.Address
	if len(decoded.To) == 20 {
		addr := common.BytesToAddress(decoded.To)
		toAddr = &addr
	}
	fields := extractFieldsLegacy(decoded, toAddr, chainID)
	return &fields, nil
}

// SignUnsignedTx decodes an unsigned EVM transaction hex string and signs it
// with the provided secp256k1 private key. It returns the signed transaction
// binary (0x-prefixed) and the extracted policy-relevant fields.
//
// Supported forms:
//   - EIP-1559 (type-2): first byte is 0x02.
//   - Legacy / EIP-155: no type byte; raw RLP.
//
// The unsignedTxHex may have a leading "0x" or "0X" prefix; it is stripped
// before decoding.
func SignUnsignedTx(unsignedTxHex string, ecKey *ecdsa.PrivateKey) (*SignResult, error) {
	// Strip optional 0x prefix.
	hexStr := unsignedTxHex
	if len(hexStr) >= 2 && (hexStr[:2] == "0x" || hexStr[:2] == "0X") {
		hexStr = hexStr[2:]
	}
	if len(hexStr) == 0 {
		return nil, fmt.Errorf("evmtx: empty unsignedTransaction")
	}

	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("evmtx: invalid hex: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("evmtx: empty transaction bytes")
	}

	// Detect transaction type by first byte.
	if raw[0] == 0x02 {
		return signEIP1559(raw[1:], ecKey)
	}
	if raw[0] == 0x04 {
		return signSetCode(raw[1:], ecKey)
	}
	// Treat as legacy (EIP-155 or pre-155).
	return signLegacy(raw, ecKey)
}

// signEIP1559 decodes and signs an EIP-1559 (type-2) unsigned transaction.
// payload is the raw bytes after the 0x02 type prefix.
func signEIP1559(payload []byte, ecKey *ecdsa.PrivateKey) (*SignResult, error) {
	var decoded eip1559UnsignedRLP
	if err := rlp.DecodeBytes(payload, &decoded); err != nil {
		return nil, fmt.Errorf("evmtx: EIP-1559 RLP decode: %w", err)
	}

	if decoded.ChainID == nil || decoded.ChainID.Sign() == 0 {
		return nil, fmt.Errorf("evmtx: EIP-1559 chainId must be non-zero")
	}

	// Build the go-ethereum inner transaction.
	var toAddr *common.Address
	if len(decoded.To) == 20 {
		addr := common.BytesToAddress(decoded.To)
		toAddr = &addr
	}

	inner := &types.DynamicFeeTx{
		ChainID:    decoded.ChainID,
		Nonce:      decoded.Nonce,
		GasTipCap:  decoded.MaxPriorityFeePerGas,
		GasFeeCap:  decoded.MaxFeePerGas,
		Gas:        decoded.Gas,
		To:         toAddr,
		Value:      decoded.Value,
		Data:       decoded.Data,
		AccessList: decoded.AccessList,
	}

	tx := types.NewTx(inner)
	signer := types.LatestSignerForChainID(decoded.ChainID)

	signed, err := types.SignTx(tx, signer, ecKey)
	if err != nil {
		return nil, fmt.Errorf("evmtx: SignTx EIP-1559: %w", err)
	}

	signedBytes, err := signed.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("evmtx: MarshalBinary EIP-1559: %w", err)
	}

	fields := extractFields1559(decoded, toAddr)

	return &SignResult{
		SignedTransaction: "0x" + hex.EncodeToString(signedBytes),
		Fields:            fields,
	}, nil
}

// signLegacy decodes and signs a legacy (pre-EIP-2718) unsigned transaction.
// Supports both EIP-155 (9-field: nonce,gasPrice,gas,to,value,data,chainId,0,0)
// and pre-155 (6-field: nonce,gasPrice,gas,to,value,data).
func signLegacy(raw []byte, ecKey *ecdsa.PrivateKey) (*SignResult, error) {
	var decoded legacyUnsignedRLP
	if err := rlp.DecodeBytes(raw, &decoded); err != nil {
		return nil, fmt.Errorf("evmtx: legacy RLP decode: %w", err)
	}

	// Determine chainId: for EIP-155 unsigned tx the V field holds the chainId,
	// R and S are both zero (or nil).
	var chainID *big.Int
	isEIP155 := false
	if decoded.V != nil && decoded.V.Sign() > 0 {
		// R and S should be zero (nil or 0) in the unsigned EIP-155 form.
		rIsZero := decoded.R == nil || decoded.R.Sign() == 0
		sIsZero := decoded.S == nil || decoded.S.Sign() == 0
		if rIsZero && sIsZero {
			chainID = new(big.Int).Set(decoded.V)
			isEIP155 = true
		}
	}

	var toAddr *common.Address
	if len(decoded.To) == 20 {
		addr := common.BytesToAddress(decoded.To)
		toAddr = &addr
	}

	inner := &types.LegacyTx{
		Nonce:    decoded.Nonce,
		GasPrice: decoded.GasPrice,
		Gas:      decoded.Gas,
		To:       toAddr,
		Value:    decoded.Value,
		Data:     decoded.Data,
	}

	tx := types.NewTx(inner)

	var signer types.Signer
	if isEIP155 && chainID != nil {
		signer = types.LatestSignerForChainID(chainID)
	} else {
		// Pre-EIP-155: use HomesteadSigner (no replay protection).
		signer = types.HomesteadSigner{}
		chainID = big.NewInt(0)
	}

	signed, err := types.SignTx(tx, signer, ecKey)
	if err != nil {
		return nil, fmt.Errorf("evmtx: SignTx legacy: %w", err)
	}

	signedBytes, err := signed.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("evmtx: MarshalBinary legacy: %w", err)
	}

	fields := extractFieldsLegacy(decoded, toAddr, chainID)

	return &SignResult{
		SignedTransaction: "0x" + hex.EncodeToString(signedBytes),
		Fields:            fields,
	}, nil
}

// signSetCode decodes and signs an EIP-7702 (type-4) unsigned transaction.
// payload is the raw bytes after the 0x04 type prefix. The authorization tuples
// are already signed by the authorizing EOAs; only the OUTER transaction is
// signed here (by the relayer key). go-ethereum's Prague signer handles the
// type-4 signing hash — we never hand-roll it.
func signSetCode(payload []byte, ecKey *ecdsa.PrivateKey) (*SignResult, error) {
	var decoded setCodeUnsignedRLP
	if err := rlp.DecodeBytes(payload, &decoded); err != nil {
		return nil, fmt.Errorf("evmtx: EIP-7702 RLP decode: %w", err)
	}

	if decoded.ChainID == nil || decoded.ChainID.Sign() == 0 {
		return nil, fmt.Errorf("evmtx: EIP-7702 chainId must be non-zero")
	}
	// 7702 mandates a 20-byte `to` (no contract-creation form) and a NON-EMPTY
	// authorization_list — a SetCodeTx with neither is invalid per spec.
	if len(decoded.To) != 20 {
		return nil, fmt.Errorf("evmtx: EIP-7702 requires a 20-byte `to` address")
	}
	if len(decoded.AuthList) == 0 {
		return nil, fmt.Errorf("evmtx: EIP-7702 authorization_list must not be empty")
	}

	authList := make([]types.SetCodeAuthorization, len(decoded.AuthList))
	for i, a := range decoded.AuthList {
		if len(a.Address) != 20 {
			return nil, fmt.Errorf("evmtx: EIP-7702 authorization[%d] address must be 20 bytes", i)
		}
		authList[i] = toSetCodeAuth(a)
	}

	inner := &types.SetCodeTx{
		ChainID:    uint256FromBig(decoded.ChainID),
		Nonce:      decoded.Nonce,
		GasTipCap:  uint256FromBig(decoded.MaxPriorityFeePerGas),
		GasFeeCap:  uint256FromBig(decoded.MaxFeePerGas),
		Gas:        decoded.Gas,
		To:         common.BytesToAddress(decoded.To),
		Value:      uint256FromBig(decoded.Value),
		Data:       decoded.Data,
		AccessList: decoded.AccessList,
		AuthList:   authList,
	}

	tx := types.NewTx(inner)
	signer := types.LatestSignerForChainID(decoded.ChainID)

	signed, err := types.SignTx(tx, signer, ecKey)
	if err != nil {
		return nil, fmt.Errorf("evmtx: SignTx EIP-7702: %w", err)
	}

	signedBytes, err := signed.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("evmtx: MarshalBinary EIP-7702: %w", err)
	}

	fields := extractFieldsSetCode(decoded)

	return &SignResult{
		SignedTransaction: "0x" + hex.EncodeToString(signedBytes),
		Fields:            fields,
	}, nil
}

// extractFieldsSetCode builds TxFields from a decoded EIP-7702 unsigned tx.
// The `to` is the (delegated) EOA being invoked; the security-relevant addresses
// for policy are the authorization delegation targets, surfaced separately.
func extractFieldsSetCode(d setCodeUnsignedRLP) TxFields {
	f := TxFields{
		ChainID:              bigToHex(d.ChainID),
		Nonce:                d.Nonce,
		Gas:                  d.Gas,
		MaxFeePerGas:         bigToHex(d.MaxFeePerGas),
		MaxPriorityFeePerGas: bigToHex(d.MaxPriorityFeePerGas),
		Value:                bigToHex(d.Value),
		Data:                 "0x" + hex.EncodeToString(d.Data),
	}
	if len(d.To) == 20 {
		addr := common.BytesToAddress(d.To)
		f.To = addr.Hex()
	}
	f.MethodSelector = methodSelector(d.Data)
	f.AuthorizationAddresses = make([]string, 0, len(d.AuthList))
	f.AuthorizationAuthorities = make([]string, 0, len(d.AuthList))
	for _, a := range d.AuthList {
		if len(a.Address) == 20 {
			f.AuthorizationAddresses = append(f.AuthorizationAddresses, common.BytesToAddress(a.Address).Hex())
		}
		// Recover the authorizing EOA. go-ethereum's Authority() does the
		// secp256k1 recovery + range checks; a tuple that fails to recover is
		// omitted so it cannot satisfy the policy's `to ∈ authorities` check.
		auth := toSetCodeAuth(a)
		if authority, err := auth.Authority(); err == nil {
			f.AuthorizationAuthorities = append(f.AuthorizationAuthorities, authority.Hex())
		}
	}
	return f
}

// toSetCodeAuth converts a decoded RLP authorization tuple into go-ethereum's
// types.SetCodeAuthorization (used both for signing and authority recovery).
func toSetCodeAuth(a authTupleRLP) types.SetCodeAuthorization {
	return types.SetCodeAuthorization{
		ChainID: *uint256FromBig(a.ChainID),
		Address: common.BytesToAddress(a.Address),
		Nonce:   a.Nonce,
		V:       uint8(a.YParity),
		R:       *uint256FromBig(a.R),
		S:       *uint256FromBig(a.S),
	}
}

// uint256FromBig converts a *big.Int to a *uint256.Int, treating nil as zero.
// Negative or overflowing values are clamped to zero (callers validate ranges
// upstream; transaction field values are non-negative by construction).
func uint256FromBig(n *big.Int) *uint256.Int {
	if n == nil {
		return new(uint256.Int)
	}
	v, overflow := uint256.FromBig(n)
	if overflow {
		return new(uint256.Int)
	}
	return v
}

// extractFields1559 builds TxFields from a decoded EIP-1559 unsigned tx.
func extractFields1559(d eip1559UnsignedRLP, to *common.Address) TxFields {
	f := TxFields{
		ChainID:              bigToHex(d.ChainID),
		Nonce:                d.Nonce,
		Gas:                  d.Gas,
		MaxFeePerGas:         bigToHex(d.MaxFeePerGas),
		MaxPriorityFeePerGas: bigToHex(d.MaxPriorityFeePerGas),
		Value:                bigToHex(d.Value),
		Data:                 "0x" + hex.EncodeToString(d.Data),
	}
	if to != nil {
		f.To = to.Hex()
	}
	f.MethodSelector = methodSelector(d.Data)
	return f
}

// extractFieldsLegacy builds TxFields from a decoded legacy unsigned tx.
func extractFieldsLegacy(d legacyUnsignedRLP, to *common.Address, chainID *big.Int) TxFields {
	f := TxFields{
		ChainID:  bigToHex(chainID),
		Nonce:    d.Nonce,
		Gas:      d.Gas,
		GasPrice: bigToHex(d.GasPrice),
		Value:    bigToHex(d.Value),
		Data:     "0x" + hex.EncodeToString(d.Data),
	}
	if to != nil {
		f.To = to.Hex()
	}
	f.MethodSelector = methodSelector(d.Data)
	return f
}

// bigToHex returns the 0x-prefixed hex representation of a *big.Int.
// Returns "0x0" for nil or zero.
func bigToHex(n *big.Int) string {
	if n == nil {
		return "0x0"
	}
	return "0x" + n.Text(16)
}

// methodSelector returns the first 4 bytes of data as "0x........",
// or an empty string if data is shorter than 4 bytes.
func methodSelector(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	return "0x" + hex.EncodeToString(data[:4])
}
