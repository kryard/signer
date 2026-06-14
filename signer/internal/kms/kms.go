package kms

import "context"

// Provider wraps/unwraps a data-encryption key (DEK). The encryption context is
// authenticated (AAD locally; KMS EncryptionContext on AWS) and MUST match on unwrap.
type Provider interface {
	WrapDEK(ctx context.Context, dek []byte, encCtx map[string]string) (wrapped []byte, keyID string, err error)
	UnwrapDEK(ctx context.Context, wrapped []byte, encCtx map[string]string) (dek []byte, err error)
	Name() string // "local" | "aws"
}
