package kms

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
)

// AWS is a KMS provider backed by AWS Key Management Service. The KMS key
// identified by keyID performs envelope-decryption of per-wallet DEKs.
//
// Security property: WrapDEK passes encCtx as the AWS EncryptionContext (AAD).
// KMS verifies the context on Decrypt and returns InvalidCiphertextException if
// it does not match — identical to the local GCM AAD guarantee.
//
// The service must have IAM permission to call kms:Encrypt and kms:Decrypt on
// the key. In production the API service has NO such IAM grant; only the signer
// VM does. This struct must never be instantiated in the API service.
type AWS struct {
	client *awskms.Client
	keyID  string // KMS key ID or ARN; used in every Encrypt call
}

// awsOptions holds optional configuration for NewAWS.
type awsOptions struct {
	endpoint string // custom KMS endpoint (e.g. a local-kms emulator); empty = AWS default
}

// AWSOption configures an AWS KMS provider created with NewAWS.
type AWSOption func(*awsOptions)

// WithEndpoint points the KMS client at a custom endpoint instead of the real
// AWS KMS service. This is used to target a local-kms Docker emulator (e.g.
// "http://localhost:8081") for offline development and testing. When the
// endpoint is empty the option is a no-op and the AWS default endpoint is used.
func WithEndpoint(endpoint string) AWSOption {
	return func(o *awsOptions) { o.endpoint = endpoint }
}

// NewAWS creates an AWS KMS provider. keyID may be a key ID, key ARN, alias
// name (prefix "alias/"), or alias ARN. The default AWS config chain is used
// (env vars, shared credentials file, EC2 instance metadata, etc.).
//
// Pass WithEndpoint to target a custom KMS endpoint (e.g. a local-kms
// emulator). With no options the behavior is identical to the real AWS KMS
// service.
func NewAWS(ctx context.Context, keyID string, opts ...AWSOption) (*AWS, error) {
	if keyID == "" {
		return nil, fmt.Errorf("kms/aws: keyID must not be empty")
	}
	var o awsOptions
	for _, opt := range opts {
		opt(&o)
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("kms/aws: load AWS config: %w", err)
	}
	clientOpts := []func(*awskms.Options){}
	if o.endpoint != "" {
		endpoint := o.endpoint
		clientOpts = append(clientOpts, func(opts *awskms.Options) {
			opts.BaseEndpoint = aws.String(endpoint)
		})
	}
	return &AWS{
		client: awskms.NewFromConfig(cfg, clientOpts...),
		keyID:  keyID,
	}, nil
}

// WrapDEK encrypts the DEK with the AWS KMS key. The encCtx is passed as the
// KMS EncryptionContext so it is bound to the ciphertext as authenticated
// additional data; UnwrapDEK MUST supply the same context.
//
// Returns (CiphertextBlob, keyARN-or-ID, error).
func (a *AWS) WrapDEK(ctx context.Context, dek []byte, encCtx map[string]string) ([]byte, string, error) {
	out, err := a.client.Encrypt(ctx, &awskms.EncryptInput{
		KeyId:             aws.String(a.keyID),
		Plaintext:         dek,
		EncryptionContext: encCtx,
	})
	if err != nil {
		return nil, "", fmt.Errorf("kms/aws: Encrypt: %w", err)
	}
	keyID := a.keyID
	if out.KeyId != nil {
		keyID = *out.KeyId
	}
	return out.CiphertextBlob, keyID, nil
}

// UnwrapDEK decrypts a CiphertextBlob produced by WrapDEK. The encCtx must
// match the one used during wrapping exactly; AWS KMS enforces this server-side
// and returns an error on any mismatch (InvalidCiphertextException or
// AccessDeniedException depending on the key policy).
func (a *AWS) UnwrapDEK(ctx context.Context, wrapped []byte, encCtx map[string]string) ([]byte, error) {
	out, err := a.client.Decrypt(ctx, &awskms.DecryptInput{
		CiphertextBlob:    wrapped,
		EncryptionContext: encCtx,
		// KeyId is optional for symmetric keys (KMS infers it from the blob) but
		// providing it adds an extra validation layer: KMS returns an error if the
		// blob was not encrypted with this specific key.
		KeyId: aws.String(a.keyID),
	})
	if err != nil {
		return nil, fmt.Errorf("kms/aws: Decrypt: %w", err)
	}
	return out.Plaintext, nil
}

// Name returns the provider identifier.
func (a *AWS) Name() string { return "aws" }
