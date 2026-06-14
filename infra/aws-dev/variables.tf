# ─── Dev Lambda stack variables (ADR-007) ────────────────────────────────────
#
# This is a SELF-CONTAINED root for the dev/test deployment profile. It creates
# its own dev wallet-signing KMS key, the signer Lambda execution role, the
# signer Lambda behind an AWS_IAM Function URL, and an invoke-only IAM key for
# the Cloudflare Worker that calls it with SigV4.

variable "region" {
  description = "AWS region for the dev stack. The Lambda reaches KMS over the public endpoint (no VPC)."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for all dev resource names. Distinct from the prod prefix so both can coexist in one account/region."
  type        = string
  default     = "kryard-dev"
}

variable "kms_admin_arns" {
  description = "IAM ARNs granted KMS key-administration actions (NOT Encrypt/Decrypt/Sign). Optional; empty = root delegation only."
  type        = list(string)
  default     = []
}

variable "signer_lambda_zip" {
  description = "Path to the signer Lambda zip (signer/dist/signer-lambda.zip from signer/scripts/build-lambda.sh). Built for provided.al2023/arm64."
  type        = string
  default     = "../../signer/dist/signer-lambda.zip"
}

variable "allow_key_import" {
  description = "Set ALLOW_KEY_IMPORT=true on the signer Lambda (guarded private-key import path). Default false; enable only for a controlled import window."
  type        = bool
  default     = false
}

variable "lambda_memory_size" {
  description = "Memory (MB) for the signer Lambda."
  type        = number
  default     = 256
}

variable "lambda_timeout" {
  description = "Timeout (seconds) for the signer Lambda."
  type        = number
  default     = 10
}
