// Package canonicaljson provides deterministic JSON serialization with recursively
// sorted object keys (arrays kept in order). This MUST match the TypeScript
// canonicalize() in src/canonicalJson.ts exactly so that the evaluatedInputHash
// computed in the TS API and verified in the Go signer are identical.
//
// Algorithm:
//   - Objects: sort keys lexicographically (Unicode code point order, same as JS sort)
//   - Arrays: keep order
//   - Primitives: marshal as-is
//   - The output is compact JSON (no extra whitespace)
package canonicaljson

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Canonicalize returns the canonical JSON representation of v.
// v must be a value that can be round-tripped through encoding/json
// (i.e. maps, slices, primitives — the same types JSON.stringify handles).
func Canonicalize(v any) (string, error) {
	// First marshal to get a JSON value, then re-sort via sortedValue.
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("canonicaljson: marshal: %w", err)
	}

	// Decode into a generic Go value (map[string]any, []any, etc.).
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return "", fmt.Errorf("canonicaljson: unmarshal: %w", err)
	}

	sorted := sortValue(generic)
	out, err := json.Marshal(sorted)
	if err != nil {
		return "", fmt.Errorf("canonicaljson: marshal sorted: %w", err)
	}
	return string(out), nil
}

// SHA256Hex returns the SHA-256 of the canonical JSON of v as a lowercase hex string.
func SHA256Hex(v any) (string, error) {
	canon, err := Canonicalize(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canon))
	return hex.EncodeToString(sum[:]), nil
}

// sortValue recursively sorts map keys. Arrays and primitives are unchanged.
func sortValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		// Use an ordered slice of key-value pairs encoded as a sortedObject
		// that will marshal with keys in sorted order.
		result := make(sortedObject, 0, len(keys))
		for _, k := range keys {
			result = append(result, kv{Key: k, Value: sortValue(val[k])})
		}
		return result
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = sortValue(item)
		}
		return out
	default:
		return val
	}
}

// sortedObject is a slice of key-value pairs that marshals to a JSON object
// with keys in the order of the slice (which is the sorted order).
type kv struct {
	Key   string
	Value any
}

type sortedObject []kv

func (s sortedObject) MarshalJSON() ([]byte, error) {
	buf := []byte{'{'}
	for i, item := range s {
		if i > 0 {
			buf = append(buf, ',')
		}
		keyBytes, err := json.Marshal(item.Key)
		if err != nil {
			return nil, err
		}
		valBytes, err := json.Marshal(item.Value)
		if err != nil {
			return nil, err
		}
		buf = append(buf, keyBytes...)
		buf = append(buf, ':')
		buf = append(buf, valBytes...)
	}
	buf = append(buf, '}')
	return buf, nil
}
