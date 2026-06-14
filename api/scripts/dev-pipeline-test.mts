// dev-pipeline-test.mts — drive the dashboard's full pipeline against a running
// Worker (default http://localhost:8787). Mirrors src/devDashboard.ts exactly:
// admin bootstrap → P-256 X-Stamp → REAL sign_transaction. Asserts a signature.
//
// Run:  (wrangler dev running)  npx tsx scripts/dev-pipeline-test.mts
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { serializeTransaction } from "viem";

const BASE = process.env.BASE_URL || "http://localhost:8787";
// When the deployed worker gates /admin/dev/* with DEV_ADMIN_TOKEN, send it.
const ADMIN: Record<string, string> = process.env.ADMIN_TOKEN ? { "X-Dev-Admin-Token": process.env.ADMIN_TOKEN } : {};

async function post(path: string, body: unknown, headers: Record<string, string> = {}) {
  const extra = path.startsWith("/admin/") ? ADMIN : {};
  const res = await fetch(BASE + path, { method: "POST", headers: { "content-type": "application/json", ...extra, ...headers }, body: JSON.stringify(body) });
  const text = await res.text();
  if (!res.ok) throw new Error(`${path} → HTTP ${res.status}: ${text}`);
  return JSON.parse(text);
}
async function postRaw(path: string, bodyStr: string, headers: Record<string, string> = {}) {
  const res = await fetch(BASE + path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: bodyStr });
  const text = await res.text();
  if (!res.ok) throw new Error(`${path} → HTTP ${res.status}: ${text}`);
  return JSON.parse(text);
}

const priv = p256.utils.randomPrivateKey();
const pub = bytesToHex(p256.getPublicKey(priv, true));
console.log("1. identity:", pub);

const org = await post("/admin/dev/org", { name: "dev-pipeline-test" });
console.log("2. org:", org.organizationId, "actor:", org.actorId);

const apiKey = await post("/admin/dev/api-key", { organizationId: org.organizationId, actorId: org.actorId, publicKey: pub, scheme: "SIGNATURE_SCHEME_TK_API_P256" });
console.log("3. apiKey:", apiKey.apiKeyId);

const wallet = await post("/admin/dev/wallet", { organizationId: org.organizationId });
console.log("4. wallet:", wallet.address, wallet.privateKeyId);

const chainId = "1", selector = "0x7fea8778", dest = "0x1111111111111111111111111111111111111111";
await post("/admin/dev/policy", { organizationId: org.organizationId, actorId: org.actorId, privateKeyId: wallet.privateKeyId, chainId, methodSelector: selector, destinationAddress: dest, maxNativeValueWei: "0" });
console.log("5. policy seeded (chain", chainId, "selector", selector, "→", dest + ")");

const unsigned = serializeTransaction({ chainId: Number(chainId), nonce: 0, to: dest as `0x${string}`, value: 0n, data: selector as `0x${string}`, maxFeePerGas: 30000000000n, maxPriorityFeePerGas: 1000000000n, gas: 100000n });
const body = { type: "ACTIVITY_TYPE_SIGN_TRANSACTION_V2", timestampMs: String(Date.now()), organizationId: org.organizationId, parameters: { signWith: wallet.privateKeyId, unsignedTransaction: unsigned, type: "TRANSACTION_TYPE_ETHEREUM" } };
const bodyStr = JSON.stringify(body);
const sigDER = p256.sign(sha256(new TextEncoder().encode(bodyStr)), priv).toDERHex();
const stamp = Buffer.from(JSON.stringify({ publicKey: pub, scheme: "SIGNATURE_SCHEME_TK_API_P256", signature: sigDER })).toString("base64url");

const r = await postRaw("/public/v1/submit/sign_transaction", bodyStr, { "X-Stamp": stamp });
const signed = r?.activity?.result?.signTransactionResult?.signedTransaction;
console.log("6. activity status:", r?.activity?.status);
if (!signed) { console.error("❌ no signedTransaction — activity:", JSON.stringify(r?.activity, null, 2)); process.exit(1); }
console.log("\n✅ REAL signed transaction:\n" + signed);
