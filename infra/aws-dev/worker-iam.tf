# ═══════════════════════════════════════════════════════════════════════════════
# Worker invoke-only IAM principal (SigV4 caller for the Function URLs)
# ═══════════════════════════════════════════════════════════════════════════════
#
# The Cloudflare Worker (API tier) signs requests to the signer Lambda Function
# URL with SigV4 (aws4fetch). It needs an IAM access key whose ONLY permission is
# lambda:InvokeFunctionUrl on the dev signer Lambda — nothing else.
#
# Authorization requires BOTH sides to allow:
#   1. Identity-based policy on this user (aws_iam_user_policy below).
#   2. Resource-based permission on each function (aws_lambda_permission below).
# `aws_lambda_function_url` only sets the auth type — it adds no resource
# permission — so without (2) the resource-side evaluation has no Allow and the
# Function URL returns 403 even though the identity policy (and the IAM policy
# simulator) say "allowed".
#
# The secret access key is a Terraform output (sensitive). Put it in the
# Worker's secrets (wrangler secret / .dev.vars) — NEVER commit it.

resource "aws_iam_user" "worker_invoker" {
  name = "${var.name_prefix}-worker-invoker"
  tags = {
    Name      = "${var.name_prefix}-worker-invoker"
    Component = "api-worker"
  }
}

resource "aws_iam_access_key" "worker_invoker" {
  user = aws_iam_user.worker_invoker.name
}

data "aws_iam_policy_document" "worker_invoke" {
  statement {
    sid    = "InvokeSignerFunctionUrl"
    effect = "Allow"
    # Function URL IAM auth in practice requires BOTH lambda:InvokeFunctionUrl
    # AND lambda:InvokeFunction — granting only InvokeFunctionUrl returns 403
    # (verified: an identity allowing only InvokeFunctionUrl, even on "*", is
    # denied, while a principal with both — e.g. admin — succeeds). Scoped to
    # exactly the dev signer function.
    actions = ["lambda:InvokeFunctionUrl", "lambda:InvokeFunction"]
    resources = [
      aws_lambda_function.signer.arn,
    ]
  }
}

resource "aws_iam_user_policy" "worker_invoke" {
  name   = "${var.name_prefix}-worker-invoke-policy"
  user   = aws_iam_user.worker_invoker.name
  policy = data.aws_iam_policy_document.worker_invoke.json
}

# ─── Resource-based permission (the other half of the authorization) ─────────
#
# Grants the worker-invoker user InvokeFunctionUrl on each function's AWS_IAM
# Function URL. Scoped to exactly this principal — not account-wide.

resource "aws_lambda_permission" "worker_invoke_signer" {
  statement_id           = "AllowWorkerInvoker"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.signer.function_name
  principal              = aws_iam_user.worker_invoker.arn
  function_url_auth_type = "AWS_IAM"
}
