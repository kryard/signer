# ═══════════════════════════════════════════════════════════════════════════════
# Signer Lambda (ADR-007 dev profile)
# ═══════════════════════════════════════════════════════════════════════════════
#
# Runs OUTSIDE any VPC (no vpc_config): it reaches KMS over the public AWS
# endpoint, so there is no NAT/NLB/VPC-endpoint cost. The Function URL uses
# AWS_IAM auth — only the SigV4-signed Worker IAM principal (worker-iam.tf) can
# invoke. The signer role's only KMS grant is Encrypt/Decrypt on the wallet key.

# ─── Shared assume-role policy (lambda.amazonaws.com) ────────────────────────

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    sid     = "AllowLambdaAssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# Wallet signer Lambda
# ═══════════════════════════════════════════════════════════════════════════════

resource "aws_iam_role" "signer_lambda" {
  name               = "${var.name_prefix}-signer-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags = {
    Name      = "${var.name_prefix}-signer-lambda-role"
    Component = "signer-lambda"
  }
}

resource "aws_iam_role_policy_attachment" "signer_lambda_basic" {
  role       = aws_iam_role.signer_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Identity-based KMS grant (the key policy's root delegation makes this
# sufficient). Scoped to the dev wallet key ARN — Encrypt/Decrypt only.
data "aws_iam_policy_document" "signer_lambda_kms" {
  statement {
    sid       = "SignerLambdaKMSAccess"
    effect    = "Allow"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
    resources = [aws_kms_key.wallet_signing.arn]
  }
}

resource "aws_iam_role_policy" "signer_lambda_kms" {
  name   = "${var.name_prefix}-signer-lambda-kms-policy"
  role   = aws_iam_role.signer_lambda.id
  policy = data.aws_iam_policy_document.signer_lambda_kms.json
}

resource "aws_lambda_function" "signer" {
  function_name    = "${var.name_prefix}-signer"
  role             = aws_iam_role.signer_lambda.arn
  runtime          = "provided.al2023"
  handler          = "bootstrap"
  architectures    = ["arm64"]
  filename         = var.signer_lambda_zip
  source_code_hash = try(filebase64sha256(var.signer_lambda_zip), null)
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size

  environment {
    variables = {
      KMS_PROVIDER     = "aws"
      KMS_KEY_ID       = aws_kms_key.wallet_signing.key_id
      ALLOW_KEY_IMPORT = var.allow_key_import ? "true" : "false"
    }
  }

  tags = {
    Name      = "${var.name_prefix}-signer"
    Component = "signer-lambda"
  }
}

resource "aws_lambda_function_url" "signer" {
  function_name      = aws_lambda_function.signer.function_name
  authorization_type = "AWS_IAM"
}
