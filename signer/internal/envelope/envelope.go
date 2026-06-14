package envelope

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"kryard/signer/internal/kms"
)

const (
	dekSize      = 32 // AES-256
	gcmNonceSize = 12
)

// Encrypted holds an envelope-encrypted payload. It contains NO plaintext
// key material — only the ciphertext, the wrapped DEK, and KMS metadata.
type Encrypted struct {
	Ciphertext  []byte // nonce (12 bytes) || GCM.Seal(plaintext) under the DEK
	WrappedDEK  []byte // DEK encrypted by the KMS provider
	KMSKeyID    string // identifies which KMS key wrapped the DEK
	KMSProvider string // "local" | "aws"
}

// Encrypt generates a random 32-byte DEK, encrypts plaintext with AES-256-GCM
// (AAD = canonical serialization of encCtx), wraps the DEK via the KMS provider,
// and returns an Encrypted value. The DEK is zeroized from memory after use.
func Encrypt(ctx context.Context, p kms.Provider, plaintext []byte, encCtx map[string]string) (Encrypted, error) {
	// Generate a fresh random DEK.
	dek := make([]byte, dekSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return Encrypted{}, fmt.Errorf("envelope: generate DEK: %w", err)
	}
	defer zeroize(dek)

	// Encrypt the plaintext under the DEK.
	ciphertext, err := aesgcmEncrypt(dek, plaintext, encCtx)
	if err != nil {
		return Encrypted{}, fmt.Errorf("envelope: encrypt plaintext: %w", err)
	}

	// Wrap the DEK via the KMS provider.
	wrapped, keyID, err := p.WrapDEK(ctx, dek, encCtx)
	if err != nil {
		return Encrypted{}, fmt.Errorf("envelope: wrap DEK: %w", err)
	}

	return Encrypted{
		Ciphertext:  ciphertext,
		WrappedDEK:  wrapped,
		KMSKeyID:    keyID,
		KMSProvider: p.Name(),
	}, nil
}

// Decrypt unwraps the DEK via the KMS provider (verifying the encryption context),
// then decrypts the ciphertext. The DEK is zeroized from memory after use.
// Decryption fails if the encryption context differs from the one used during Encrypt.
func Decrypt(ctx context.Context, p kms.Provider, e Encrypted, encCtx map[string]string) ([]byte, error) {
	// Unwrap the DEK — GCM authentication ensures the context matches.
	dek, err := p.UnwrapDEK(ctx, e.WrappedDEK, encCtx)
	if err != nil {
		return nil, fmt.Errorf("envelope: unwrap DEK: %w", err)
	}
	defer zeroize(dek)

	plaintext, err := aesgcmDecrypt(dek, e.Ciphertext, encCtx)
	if err != nil {
		return nil, fmt.Errorf("envelope: decrypt ciphertext: %w", err)
	}
	return plaintext, nil
}

// aesgcmEncrypt encrypts plaintext with AES-256-GCM under dek; AAD is the
// canonical encryption context. Returns nonce || ciphertext.
func aesgcmEncrypt(dek, plaintext []byte, encCtx map[string]string) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	aad := canonicalAAD(encCtx)
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// aesgcmDecrypt decrypts a nonce||ciphertext blob produced by aesgcmEncrypt.
func aesgcmDecrypt(dek, data []byte, encCtx map[string]string) ([]byte, error) {
	if len(data) < gcmNonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	nonce := data[:gcmNonceSize]
	ciphertext := data[gcmNonceSize:]
	aad := canonicalAAD(encCtx)
	return gcm.Open(nil, nonce, ciphertext, aad)
}

// zeroize overwrites a byte slice with zeros to clear key material from memory.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// canonicalAAD mirrors kms/local.canonicalAAD — duplicated here so envelope
// is self-contained and the ciphertext AAD is independent of the wrapped-DEK AAD.
// Both must use the same serialization for consistency.
func canonicalAAD(encCtx map[string]string) []byte {
	// Import sort/strings inline to avoid a separate file.
	// This is intentionally duplicated from kms/local to maintain package isolation.
	keys := make([]string, 0, len(encCtx))
	for k := range encCtx {
		keys = append(keys, k)
	}
	// Sort inline.
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	result := make([]byte, 0, 128)
	for idx, k := range keys {
		result = append(result, []byte(k+"="+encCtx[k])...)
		if idx < len(keys)-1 {
			result = append(result, '\n')
		}
	}
	return result
}
