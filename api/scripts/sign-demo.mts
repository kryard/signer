// sign-demo.mts — exercise the deployed dev signer directly (SigV4 → Function URL).
//
// This calls the signer INTERNAL API the same way the Worker does (aws4fetch
// SigV4 with the invoke-only key from .dev.vars). It bypasses the
// Worker/policy/Postgres — it's a smoke test of the signing core only.
//
// Run:  cd api && npx tsx scripts/sign-demo.mts
import { promises as fs } from "node:fs";
import { AwsClient } from "aws4fetch";

const env: Record<string, string> = {};
for (const l of (await fs.readFile("./.dev.vars", "utf8")).split("\n")) {
  const s = l.trim(); if (!s || s.startsWith("#")) continue;
  const i = s.indexOf("="); if (i > 0) env[s.slice(0, i).trim()] = s.slice(i + 1).trim();
}
const aws = new AwsClient({
  accessKeyId: env.AWS_ACCESS_KEY_ID, secretAccessKey: env.AWS_SECRET_ACCESS_KEY,
  region: env.AWS_REGION || "us-east-1", service: "lambda",
});
const SIGNER = env.SIGNER_BASE_URL.replace(/\/$/, "");

async function post(base: string, path: string, body: unknown) {
  const res = await aws.fetch(base + path, { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json" } });
  const text = await res.text();
  if (!res.ok) throw new Error(`${path} → HTTP ${res.status}: ${text}`);
  return JSON.parse(text);
}
// ── 1. WALLET SIGNER (secp256k1 EVM) ─────────────────────────────────────────
console.log("=== wallet signer: create a fresh key in the signer (KMS-encrypted) ===");
const key = await post(SIGNER, "/internal/keys/create", {
  organizationId: "org-dev-demo", privateKeyId: "pk-demo-1", environment: "dev", name: "demo-key",
});
console.log("  address:   ", key.addresses?.[0]);
console.log("  publicKey: ", key.publicKey?.slice(0, 24) + "…");
console.log("  curve:     ", key.curve, "| kms:", key.kmsProvider, key.kmsKeyId?.slice(0, 8) + "…");

console.log("=== wallet signer: sign a raw payload (keccak256) with that key ===");
// payload = keccak256 will be applied by the signer; we send arbitrary bytes.
const rawSig = await post(SIGNER, "/internal/sign/raw-payload", {
  organizationId: "org-dev-demo", privateKeyId: "pk-demo-1", environment: "dev",
  encryptedPrivateKey: key.encryptedPrivateKey, encryptedDataKey: key.encryptedDataKey,
  kmsKeyId: key.kmsKeyId, kmsProvider: key.kmsProvider, encryptionContext: key.encryptionContext,
  payload: "0x" + Buffer.from("hello kryard dev").toString("hex"),
  hashFunction: "HASH_FUNCTION_KECCAK256",
});
console.log("  r:", rawSig.r, "\n  s:", rawSig.s, "\n  v:", rawSig.v);
console.log("  receipt:", JSON.stringify(rawSig.signerReceipt ?? rawSig.receipt ?? {}).slice(0, 120));

console.log("\n✅ signer responded over SigV4 against the deployed dev Lambda.");
