/**
 * Integration test: signer fault injection (AC-G3 / AC-G4).
 *
 * Drives the sign_transaction path with an INJECTED signerFetch so we can
 * deterministically simulate signer/KMS faults without a live signer:
 *
 *   - 5xx (transient: signer/KMS unavailable, decrypt timeout) → activity PENDING
 *     (retryable), NO plaintext key material persisted anywhere.
 *   - 4xx (hard: malformed request the signer rejects)         → activity FAILED.
 *   - network error (fetch rejects)                            → activity FAILED.
 *   - idempotent recovery: a resubmit of the identical body after a PENDING
 *     returns the SAME activity and does NOT call the signer again (no
 *     double-sign); once the signer is "restored", a fresh submit COMPLETES.
 *
 * This needs Docker (Postgres via testcontainers) but NOT the Go signer — the
 * signer is fully mocked through the fault-injecting fetch. The private key row
 * is seeded directly with dummy ciphertext; the fault fetch intercepts the call
 * before any real decrypt would happen.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { randomUUID } from "node:crypto";
import { createApp } from "../src/app";
import type { SignerFetch } from "../src/signerClient";
import { startTestDb, type TestDb } from "./helpers/pg";
import { seedStamper, stampedRequest } from "./helpers/stamp";
import type { ApiKeyStamper } from "@turnkey/api-key-stamper";

// A fixed EIP-1559 unsigned tx (Sepolia, value 0, no calldata) — the same fixture
// used by signTransaction.int. The signer is mocked, so only its shape matters.
const EIP1559_UNSIGNED_TX =
  "0x02ea83aa36a780843b9aca00843b9aca0082520894000000000000000000000000000000000000dead8080c0";

let tdb: TestDb;
let organizationId: string;
let stamper: ApiKeyStamper;
let privateKeyId: string;

// ---------------------------------------------------------------------------
// Fault-injecting signer fetch
// ---------------------------------------------------------------------------
// `signMode` controls how the mock responds to /internal/sign/transaction.
// `signCalls` counts how many times the SIGN endpoint was hit (parse excluded),
// which is how we prove "no double-sign" on idempotent resubmit.
type SignMode = "ok" | "transient" | "hard" | "network";
let signMode: SignMode = "ok";
let signCalls = 0;

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const PARSE_FIELDS = {
  chainId: "0xaa36a7",
  to: "0x000000000000000000000000000000000000dead",
  value: "0x0",
  nonce: 0,
  gas: 21000,
  data: "0x",
};

const OK_SIGN_RESPONSE = {
  signedTransaction:
    "0x02f86c83aa36a780843b9aca00843b9aca0082520894000000000000000000000000000000000000dead8080c001a0" +
    "1111111111111111111111111111111111111111111111111111111111111111a0" +
    "2222222222222222222222222222222222222222222222222222222222222222",
  fields: PARSE_FIELDS,
  signerReceipt: {
    keyId: "mock-key",
    publicKey: "02".padEnd(66, "0"),
    payloadHash: "ph",
    signatureHash: "sh",
    signerBuildId: "test",
  },
};

const faultFetch: SignerFetch = async (url, _init) => {
  // Parse endpoint always succeeds — the fault under test is the SIGN call.
  if (url.endsWith("/internal/parse/transaction")) {
    return jsonResponse(200, PARSE_FIELDS);
  }

  if (url.endsWith("/internal/sign/transaction")) {
    signCalls += 1;
    switch (signMode) {
      case "transient":
        // 5xx: signer/KMS unavailable → SignerError(isTransient=true) → PENDING.
        return jsonResponse(503, { error: "kms unavailable" });
      case "hard":
        // 4xx: signer rejects the request → SignerError(isTransient=false) → FAILED.
        return jsonResponse(400, { error: "bad request" });
      case "network":
        // fetch rejects (connection refused / DNS) → caught → FAILED.
        throw new Error("ECONNREFUSED");
      case "ok":
      default:
        return jsonResponse(200, OK_SIGN_RESPONSE);
    }
  }

  // Health or anything else.
  return jsonResponse(200, { status: "ok" });
};

let app: ReturnType<typeof createApp>;

beforeAll(async () => {
  tdb = await startTestDb();
  ({ organizationId, stamper } = await seedStamper(tdb.db));

  // Seed a private-key row directly with DUMMY ciphertext. resolveSignWith finds
  // it; the fault fetch intercepts before any real decrypt. No plaintext anywhere.
  privateKeyId = randomUUID();
  await tdb.db
    .insertInto("private_keys")
    .values({
      id: privateKeyId,
      organization_id: organizationId,
      name: "fault-injection-key",
      curve: "CURVE_SECP256K1",
      public_key: "02".padEnd(66, "0"),
      addresses: JSON.stringify(["0x000000000000000000000000000000000000bEEF"]),
      encrypted_private_key: "ZHVtbXktY2lwaGVydGV4dA==", // base64("dummy-ciphertext")
      encrypted_data_key: "ZHVtbXktZGVr", // base64("dummy-dek")
      kms_provider: "local",
      kms_key_id: "mock-key",
      encryption_context: JSON.stringify({
        organization_id: organizationId,
        private_key_id: privateKeyId,
        environment: "test",
        purpose: "wallet-signing",
      }),
    })
    .execute();

  // policyBypassAllowed: true so the seeded key signs without a policy binding —
  // the fault under test is the signer call, not policy.
  app = createApp({
    db: tdb.db,
    signerBaseUrl: "http://signer.invalid",
    policyBypassAllowed: true,
    signerFetch: faultFetch,
  });
});

afterAll(async () => {
  await tdb.stop();
});

beforeEach(() => {
  signMode = "ok";
  signCalls = 0;
});

async function submitSignTx(timestampMs: string) {
  const body = {
    type: "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
    organizationId,
    timestampMs,
    parameters: {
      signWith: privateKeyId,
      unsignedTransaction: EIP1559_UNSIGNED_TX,
      type: "TRANSACTION_TYPE_ETHEREUM",
    },
  };
  const init = await stampedRequest(stamper, body);
  return app.request("/public/v1/submit/sign_transaction", init);
}

/** Read the activity row straight from the DB to assert no plaintext leaked. */
async function activityRow(id: string) {
  return tdb.db.selectFrom("activities").selectAll().where("id", "=", id).executeTakeFirstOrThrow();
}

const BARE_64HEX_RE = /"([0-9a-f]{64})"/i;
function assertNoPlaintextKey(value: unknown): void {
  const str = JSON.stringify(value);
  for (const f of ["privateKeyHex", "rawPrivateKey", "privateKeyMaterial", "plaintext"]) {
    if (str.includes(`"${f}"`)) {
      throw new Error(`forbidden plaintext field "${f}" present: ${str.slice(0, 300)}`);
    }
  }
  // A bare 64-hex string in a sign-tx activity would be suspicious; the dummy
  // ciphertext is base64, not hex, so this should never match.
  expect(BARE_64HEX_RE.test(str.replace(OK_SIGN_RESPONSE.signerReceipt.publicKey, ""))).toBe(false);
}

describe("signer fault injection (G3/G4)", () => {
  it("transient signer/KMS fault (5xx) → activity PENDING, no plaintext cached", async () => {
    signMode = "transient";
    const res = await submitSignTx(String(Date.now()));
    expect(res.status).toBe(200);
    const json = (await res.json()) as { activity: { id: string; status: string; failure: { code: string } | null } };

    expect(json.activity.status).toBe("ACTIVITY_STATUS_PENDING");
    expect(json.activity.failure?.code).toBe("SIGNER_ERROR");
    expect(signCalls).toBe(1);

    // No plaintext private key material in the persisted activity row.
    const row = await activityRow(json.activity.id);
    assertNoPlaintextKey(row.result);
    assertNoPlaintextKey(row.request_body);
  });

  it("hard signer fault (4xx) → activity FAILED", async () => {
    signMode = "hard";
    const res = await submitSignTx(String(Date.now()));
    const json = (await res.json()) as { activity: { status: string; failure: { code: string } | null } };
    expect(json.activity.status).toBe("ACTIVITY_STATUS_FAILED");
    expect(json.activity.failure?.code).toBe("SIGNER_ERROR");
  });

  it("signer network error (fetch rejects) → activity FAILED", async () => {
    signMode = "network";
    const res = await submitSignTx(String(Date.now()));
    const json = (await res.json()) as { activity: { status: string; failure: { code: string } | null } };
    expect(json.activity.status).toBe("ACTIVITY_STATUS_FAILED");
    expect(json.activity.failure?.code).toBe("SIGNER_ERROR");
  });

  it("idempotent recovery: resubmit of a PENDING body returns SAME activity, does NOT re-call signer", async () => {
    signMode = "transient";
    const ts = String(Date.now());

    const first = (await (await submitSignTx(ts)).json()) as { activity: { id: string; status: string } };
    expect(first.activity.status).toBe("ACTIVITY_STATUS_PENDING");
    expect(signCalls).toBe(1);

    // Resubmit the IDENTICAL body (same timestampMs) — idempotency returns the
    // existing PENDING activity WITHOUT invoking the signer a second time.
    const second = (await (await submitSignTx(ts)).json()) as { activity: { id: string; status: string } };
    expect(second.activity.id).toBe(first.activity.id);
    expect(second.activity.status).toBe("ACTIVITY_STATUS_PENDING");
    expect(signCalls).toBe(1); // <-- no double-sign
  });

  it("recovery after restore: signer back up + fresh submit → COMPLETED", async () => {
    // A transient failure first…
    signMode = "transient";
    const failed = (await (await submitSignTx(String(Date.now()))).json()) as { activity: { status: string } };
    expect(failed.activity.status).toBe("ACTIVITY_STATUS_PENDING");

    // …signer restored, NEW timestampMs (a new activity, Turnkey's retry rule).
    signMode = "ok";
    const ok = (await (await submitSignTx(String(Date.now() + 1))).json()) as {
      activity: { id: string; status: string; result: { signTransactionResult?: { signedTransaction: string } } };
    };
    expect(ok.activity.status).toBe("ACTIVITY_STATUS_COMPLETED");
    // Turnkey wire format: signedTransaction is hex WITHOUT 0x.
    expect(ok.activity.result.signTransactionResult?.signedTransaction).not.toMatch(/^0x/);

    const row = await activityRow(ok.activity.id);
    assertNoPlaintextKey(row.result);
  });
});
