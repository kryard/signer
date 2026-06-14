# ─── Endpoints (wire these into the Worker's .dev.vars / secrets) ────────────

output "signer_lambda_function_url" {
  description = "SIGNER_BASE_URL — signer Lambda Function URL (AWS_IAM; call with SigV4)."
  value       = aws_lambda_function_url.signer.function_url
}

# ─── KMS (for reference / the signer env already points at this) ─────────────

output "wallet_kms_key_id" {
  description = "Dev wallet-signing KMS key id (signer Lambda KMS_KEY_ID)."
  value       = aws_kms_key.wallet_signing.key_id
}

output "wallet_kms_alias" {
  description = "Dev wallet-signing KMS alias."
  value       = aws_kms_alias.wallet_signing.name
}

# ─── Worker SigV4 credentials (sensitive) ────────────────────────────────────

output "region" {
  description = "AWS region (set as the Worker's AWS_REGION for SigV4)."
  value       = var.region
}

output "worker_invoker_access_key_id" {
  description = "Access key id for the Worker's SigV4 invoker. Put in the Worker config."
  value       = aws_iam_access_key.worker_invoker.id
}

output "worker_invoker_secret_access_key" {
  description = "Secret access key for the Worker's SigV4 invoker. Store as a Worker secret — never commit. Read with: terraform output -raw worker_invoker_secret_access_key"
  value       = aws_iam_access_key.worker_invoker.secret
  sensitive   = true
}
