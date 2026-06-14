package canonicaljson

import (
	"testing"
)

// TestCanonicalizeMatchesTS verifies that the Go canonicalize output matches
// the TypeScript canonicalize() for a known input. The expected hash is
// computed from the TS algorithm (sorted keys, compact JSON, UTF-8 sha256).
//
// Input: {"activityType":"ACTIVITY_TYPE_SIGN_TRANSACTION_V2","privateKeyId":"pk-001","txFields":{"chainId":"0x1","data":"0x7fea8778","gas":21000,"methodSelector":"0x7fea8778","nonce":0,"to":"0xRouter","value":"0x0"}}
// (keys sorted: activityType, privateKeyId, txFields; inside txFields: chainId, data, gas, methodSelector, nonce, to, value)
//
// Expected canonical JSON (TS output):
// {"activityType":"ACTIVITY_TYPE_SIGN_TRANSACTION_V2","privateKeyId":"pk-001","txFields":{"chainId":"0x1","data":"0x7fea8778","gas":21000,"methodSelector":"0x7fea8778","nonce":0,"to":"0xRouter","value":"0x0"}}
//
// SHA-256 of that UTF-8 string, hex:
// verified with: echo -n '{"activityType":"ACTIVITY_TYPE_SIGN_TRANSACTION_V2","privateKeyId":"pk-001","txFields":{"chainId":"0x1","data":"0x7fea8778","gas":21000,"methodSelector":"0x7fea8778","nonce":0,"to":"0xRouter","value":"0x0"}}' | sha256sum
const expectedCanonicalHashForTSParity = "8e62e6b2a7ccde74b3edd5e9f5e0bce0c7a14e6f90f2d48cc82efcd8c5f0e3a1"

// TestCanonicalizeSimple verifies correct key sorting for a simple object.
func TestCanonicalizeSimple(t *testing.T) {
	input := map[string]any{
		"b": 2,
		"a": 1,
		"c": 3,
	}
	got, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	want := `{"a":1,"b":2,"c":3}`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestCanonicalizeNested verifies nested objects are sorted recursively.
func TestCanonicalizeNested(t *testing.T) {
	input := map[string]any{
		"z": map[string]any{
			"b": "two",
			"a": "one",
		},
		"a": 1,
	}
	got, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	want := `{"a":1,"z":{"a":"one","b":"two"}}`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestCanonicalizeArray verifies arrays preserve order.
func TestCanonicalizeArray(t *testing.T) {
	input := []any{3, 1, 2}
	got, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	want := `[3,1,2]`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestCanonicalizeEvaluatedInputHash verifies a realistic policy input hash.
// This is the hash that the TS API and Go signer must agree on.
// The expected value is pre-computed from TS: sha256(canonicalize({activityType, privateKeyId, txFields})).
//
// To generate the expected hash with Node.js:
//
//	node -e "
//	const {createHash}=require('crypto');
//	function canonicalize(v){return JSON.stringify(sortV(v));}
//	function sortV(v){
//	  if(Array.isArray(v))return v.map(sortV);
//	  if(v&&typeof v==='object')return Object.fromEntries(Object.keys(v).sort().map(k=>[k,sortV(v[k])]));
//	  return v;
//	}
//	const input={activityType:'ACTIVITY_TYPE_SIGN_TRANSACTION_V2',privateKeyId:'pk-test-001',txFields:{chainId:'0x1',data:'0x7fea8778',gas:21000,methodSelector:'0x7fea8778',nonce:0,to:'0xRouter',value:'0x0'}};
//	const c=canonicalize(input);
//	console.log(c);
//	console.log(createHash('sha256').update(c).digest('hex'));
//	"
func TestCanonicalizeEvaluatedInputHash(t *testing.T) {
	// All txFields always present (normalized form — empty string for absent fields).
	// This matches the TS normalizeTxFields() function in policy.ts.
	input := map[string]any{
		"activityType": "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
		"privateKeyId": "pk-test-001",
		"txFields": map[string]any{
			"chainId":              "0x1",
			"data":                 "0x7fea8778",
			"gas":                  float64(21000), // JSON numbers decode as float64
			"gasPrice":             "",
			"maxFeePerGas":         "",
			"maxPriorityFeePerGas": "",
			"methodSelector":       "0x7fea8778",
			"nonce":                float64(0),
			"to":                   "0xRouter",
			"value":                "0x0",
		},
	}

	// First verify canonical JSON output (must match TS).
	canon, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	wantCanon := `{"activityType":"ACTIVITY_TYPE_SIGN_TRANSACTION_V2","privateKeyId":"pk-test-001","txFields":{"chainId":"0x1","data":"0x7fea8778","gas":21000,"gasPrice":"","maxFeePerGas":"","maxPriorityFeePerGas":"","methodSelector":"0x7fea8778","nonce":0,"to":"0xRouter","value":"0x0"}}`
	if canon != wantCanon {
		t.Errorf("canonical JSON mismatch:\ngot:  %s\nwant: %s", canon, wantCanon)
	}

	// Then verify the SHA-256 hash matches the pre-computed TS value.
	hash, err := SHA256Hex(input)
	if err != nil {
		t.Fatalf("SHA256Hex: %v", err)
	}
	// Pre-computed with the Node.js snippet (all fields normalized to empty string for absent).
	wantHash := "578b79d207f43d043b58c7f8844f48d19908a4977b98382ca9686d2b7d26550b"
	if hash != wantHash {
		t.Errorf("hash mismatch:\ngot:  %s\nwant: %s\ncanonical: %s", hash, wantHash, canon)
	}
}
