# infra/aws-dev — Dev/Test signer stack

A **self-contained** Terraform root for the cheap dev/test deployment profile of
the Kryard wallet signer. It is a **DEV profile**: the Lambda reaches KMS over
the **public AWS endpoint with no VPC**, so it is **not suitable for production**
(no network isolation, no private KMS endpoint, no attested-enclave path).

## What it creates

- **One dev wallet-signing KMS key** — a symmetric (`SYMMETRIC_DEFAULT`,
  `ENCRYPT_DECRYPT`) envelope key with rotation enabled and a 7-day deletion
  window. The signer's KMS encryption context binds `environment`, so this dev
  key is intentionally distinct from any prod key.
- **One signer Lambda** (`cmd/signer-lambda`) behind a **Function URL with
  `AWS_IAM` auth**, running **outside any VPC** (KMS over the public endpoint —
  no NAT/NLB/VPC-endpoint cost).
- **A least-privilege Lambda execution role** — `kms:Encrypt`/`kms:Decrypt`/
  `kms:DescribeKey` on the wallet key only, conditioned on the
  `purpose=wallet-signing` encryption context.
- **An invoke-only IAM user + access key** for the Cloudflare Worker to call the
  Function URL with SigV4 (`lambda:InvokeFunctionUrl` only, scoped to this one
  function).

No account IDs, ARNs, key IDs, or URLs are hardcoded — the account is resolved
at apply time via `data.aws_caller_identity`, and everything else is a variable
or a resource reference.

## Build the Lambda zip

The signer build script lives in `../../signer` (relative to this directory):

```bash
# From the repo root:
signer/scripts/build-lambda.sh        # → signer/dist/signer-lambda.zip
```

It produces a single `bootstrap` binary (Go, `CGO_ENABLED=0`,
`GOOS=linux GOARCH=arm64`) zipped for the AWS `provided.al2023` custom runtime on
arm64 — matching the `runtime`/`handler`/`architectures` in `lambda.tf`.

## Deploy

```bash
# 1. Build the Lambda zip (see above).
# 2. Authenticate to AWS (SSO / access keys / profile).
# 3. Apply:
cd infra/aws-dev
cp terraform.tfvars.example terraform.tfvars   # adjust region / name_prefix
terraform init
terraform plan
terraform apply        # signer_lambda_zip defaults to ../../signer/dist/signer-lambda.zip

# 4. Read outputs into the Worker config:
terraform output signer_lambda_function_url
terraform output region
terraform output worker_invoker_access_key_id
terraform output -raw worker_invoker_secret_access_key   # sensitive → Worker secret
```

## Worker wiring

Set on the API Worker (`../../api`): `SIGNER_BASE_URL` (the Function URL),
`SIGNER_AUTH=sigv4`, `AWS_REGION`, and the access-key id/secret as **secrets**
(the Worker uses `sigv4Fetch` — `signerClient.ts`). The secret access key is a
sensitive Terraform output — store it as a Worker secret, **never commit it**.

## Teardown

```bash
terraform destroy
```

The KMS key uses a 7-day deletion window (disposable dev key).
