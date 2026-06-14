data "aws_caller_identity" "current" {}

# ═══════════════════════════════════════════════════════════════════════════════
# Dev wallet-signing key (symmetric envelope key) — signer Lambda only
# ═══════════════════════════════════════════════════════════════════════════════
#
# Distinct from the prod wallet key: the signer's KMS encryption context binds
# `environment`, so a dev key with the same security shape is correct (never
# decrypt prod ciphertext with a dev grant, and vice-versa). Same two-step
# create-then-policy pattern as the prod root to break the key↔role cycle.

resource "aws_kms_key" "wallet_signing" {
  description              = "Kryard DEV wallet DEK-wrapping key — signer Lambda only"
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true
  deletion_window_in_days  = 7 # short window for a disposable dev key

  tags = {
    Name      = "${var.name_prefix}-wallet-signing-key"
    Purpose   = "wallet-signing"
    Env       = "dev"
    ManagedBy = "terraform"
  }
}

resource "aws_kms_alias" "wallet_signing" {
  name          = "alias/${var.name_prefix}-wallet-signing"
  target_key_id = aws_kms_key.wallet_signing.key_id
}

data "aws_iam_policy_document" "wallet_key_policy" {
  # Statement 1: root IAM delegation (required — prevents lockout).
  statement {
    sid       = "AllowRootIAMDelegation"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  # Statement 2: key administrators (management only — no Encrypt/Decrypt).
  dynamic "statement" {
    for_each = length(var.kms_admin_arns) > 0 ? [1] : []
    content {
      sid       = "AllowKeyAdministrators"
      effect    = "Allow"
      resources = ["*"]
      principals {
        type        = "AWS"
        identifiers = var.kms_admin_arns
      }
      actions = [
        "kms:DescribeKey", "kms:GetKeyPolicy", "kms:PutKeyPolicy",
        "kms:EnableKeyRotation", "kms:DisableKeyRotation", "kms:GetKeyRotationStatus",
        "kms:CreateAlias", "kms:UpdateAlias", "kms:DeleteAlias", "kms:ListAliases",
        "kms:TagResource", "kms:UntagResource", "kms:ListResourceTags",
        "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
        "kms:EnableKey", "kms:DisableKey",
      ]
    }
  }

  # Statement 3: signer Lambda role — the ONLY Encrypt/Decrypt grantee.
  # Conditioned on the envelope encryption context carrying purpose=wallet-signing
  # (the signer always sends it — signer/internal/keys handler). Precise,
  # single-valued condition (unambiguous vs. a bare EncryptionContextKeys test).
  statement {
    sid       = "AllowSignerLambdaOnly"
    effect    = "Allow"
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.signer_lambda.arn]
    }
    actions = ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:purpose"
      values   = ["wallet-signing"]
    }
  }
}

resource "aws_kms_key_policy" "wallet_signing" {
  key_id     = aws_kms_key.wallet_signing.id
  policy     = data.aws_iam_policy_document.wallet_key_policy.json
  depends_on = [aws_iam_role.signer_lambda]
}
