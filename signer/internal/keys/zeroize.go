package keys

// Zeroize overwrites a byte slice with zeros to clear key material from memory.
// Callers should invoke it on raw private key material immediately after it is no
// longer needed (e.g. after envelope-encrypting or signing).
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
