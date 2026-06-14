package keys

import (
	"encoding/hex"
	"strings"
)

// decodeHex strips an optional 0x/0X prefix and hex-decodes the remainder. It is
// the single place that handles the optional prefix; the curve import paths use
// it directly and the signer's payload decode uses the exported DecodeHex
// wrapper.
func decodeHex(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return hex.DecodeString(s)
}

// DecodeHex is the exported wrapper around decodeHex for callers outside the keys
// package (e.g. the signer's raw-payload handler), keeping prefix handling in one
// place.
func DecodeHex(s string) ([]byte, error) { return decodeHex(s) }
