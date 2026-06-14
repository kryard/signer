package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	localKeyID   = "local-master-v1"
	gcmNonceSize = 12
)

// Local is an AES-256-GCM KMS provider for development. The master key bytes
// are held in memory; aes.NewCipher + cipher.NewGCM are constructed PER CALL
// inside WrapDEK/UnwrapDEK so that there is no shared mutable cipher.AEAD
// state and the provider is safe for concurrent use without locking.
//
// The encryption context is serialized canonically (sorted keys, "k=v" joined
// by "\n") and used as GCM AAD, so UnwrapDEK with a different context fails
// with an authentication error.
//
// WARNING: This provider must never be used in production. Use the AWS KMS
// provider (kms.AWS, a documented TODO) with IAM-scoped access in production.
type Local struct {
	masterKey []byte // 32-byte AES-256 key; never modified after construction
}

// NewLocal creates a Local provider from a 32-byte master key.
func NewLocal(masterKey []byte) (*Local, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("kms/local: master key must be 32 bytes, got %d", len(masterKey))
	}
	// Copy the key so the caller's buffer cannot be mutated externally.
	key := make([]byte, 32)
	copy(key, masterKey)
	return &Local{masterKey: key}, nil
}

// newGCM constructs a fresh AES-GCM instance from the stored master key.
// Called per-operation; cheap and removes shared mutable state.
func (l *Local) newGCM() (cipher.AEAD, error) {
	block, err := aes.NewCipher(l.masterKey)
	if err != nil {
		return nil, fmt.Errorf("kms/local: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("kms/local: cipher.NewGCM: %w", err)
	}
	return gcm, nil
}

// WrapDEK encrypts the DEK under the master key with the encryption context as AAD.
// The returned blob is: nonce (12 bytes) || GCM.Seal(dek).
func (l *Local) WrapDEK(_ context.Context, dek []byte, encCtx map[string]string) ([]byte, string, error) {
	gcm, err := l.newGCM()
	if err != nil {
		return nil, "", err
	}
	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, "", fmt.Errorf("kms/local: read nonce: %w", err)
	}
	aad := canonicalAAD(encCtx)
	sealed := gcm.Seal(nonce, nonce, dek, aad)
	return sealed, localKeyID, nil
}

// UnwrapDEK decrypts a blob produced by WrapDEK. It MUST be called with the
// same encryption context used during wrapping; GCM authentication will fail
// if the context differs or the ciphertext was tampered.
func (l *Local) UnwrapDEK(_ context.Context, wrapped []byte, encCtx map[string]string) ([]byte, error) {
	if len(wrapped) < gcmNonceSize {
		return nil, fmt.Errorf("kms/local: wrapped key too short")
	}
	gcm, err := l.newGCM()
	if err != nil {
		return nil, err
	}
	nonce := wrapped[:gcmNonceSize]
	ciphertext := wrapped[gcmNonceSize:]
	aad := canonicalAAD(encCtx)
	dek, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("kms/local: GCM open failed (wrong context or tampered ciphertext): %w", err)
	}
	return dek, nil
}

// Name returns the provider name.
func (l *Local) Name() string { return "local" }

// canonicalAAD serializes an encryption context deterministically: keys are
// sorted lexicographically, each entry formatted as "k=v", joined by "\n".
func canonicalAAD(encCtx map[string]string) []byte {
	keys := make([]string, 0, len(encCtx))
	for k := range encCtx {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+encCtx[k])
	}
	return []byte(strings.Join(parts, "\n"))
}
