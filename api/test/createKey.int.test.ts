/**
 * Integration test: create_private_keys end-to-end.
 *
 * Requires:
 *  - Docker (Postgres container via testcontainers)
 *  - Go toolchain (builds the signer binary once)
 *
 * If Go is absent the signer helper returns null and the suite is skipped.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createApp } from "../src/app";
import { startTestDb, type TestDb } from "./helpers/pg";
import { seedStamper, stampedRequest } from "./helpers/stamp";
import {
  startTestSigner,
  TEST_IMPORT_PRIV_HEX,
  TEST_IMPORT_ADDRESS,
  type TestSigner,
} from "./helpers/signer";
import type { ApiKeyStamper } from "@turnkey/api-key-stamper";

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------
let tdb: TestDb;
let signer: TestSigner | null = null;
let signerWithImport: TestSigner | null = null;
let app: ReturnType<typeof createApp>;
let appWithImport: ReturnType<typeof createApp>;
let organizationId: string;
let stamper: ApiKeyStamper;
let goAvailable = true;

beforeAll(async () => {
  tdb = await startTestDb();
  ({ organizationId, stamper } = await seedStamper(tdb.db));

  // Start two signer instances: one with import disabled, one with it enabled.
  signer = await startTestSigner(false);
  signerWithImport = await startTestSigner(true);

  if (!signer || !signerWithImport) {
    goAvailable = false;
    // Still create the app with a placeholder URL for the import-disabled tests.
    app = createApp({ db: tdb.db, signerBaseUrl: "http://127.0.0.1:1" });
    appWithImport = createApp({ db: tdb.db, signerBaseUrl: "http://127.0.0.1:1" });
    return;
  }

  app = createApp({ db: tdb.db, signerBaseUrl: signer.baseUrl });
  appWithImport = createApp({ db: tdb.db, signerBaseUrl: signerWithImport.baseUrl });
});

afterAll(async () => {
  signer?.stop();
  signerWithImport?.stop();
  await tdb.stop();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function makeCreateKeysBody(extra: Record<string, unknown> = {}) {
  return {
    type: "ACTIVITY_TYPE_CREATE_PRIVATE_KEYS_V2",
    organizationId,
    timestampMs: String(Date.now()),
    parameters: { name: "test-key", curve: "CURVE_SECP256K1", addressFormats: [], ...extra },
  };
}

async function submitTo(
  targetApp: ReturnType<typeof createApp>,
  body: Record<string, unknown>,
) {
  const init = await stampedRequest(stamper, body);
  return targetApp.request("/public/v1/submit/create_private_keys", init);
}

async function query(path: string, body: Record<string, unknown>) {
  const init = await stampedRequest(stamper, body);
  return app.request(`/public/v1/query/${path}`, init);
}

// A 64-hex plaintext private key would appear as a bare JSON string value of
// exactly 64 hex characters (possibly with a "0x" prefix making it 66).
// We exclude the fingerprint field (sha256:<hash>) and base64-encoded fields
// (which use [A-Za-z0-9+/=] and are longer).  The check looks for a JSON string
// whose entire content is 64 lowercase hex chars — i.e. ":<64 hex chars>" in the
// serialised JSON, without any surrounding characters that would indicate a hash
// prefix or longer string.
const BARE_64HEX_RE = /"([0-9a-f]{64})"/i;

function assertNoPlaintextKey(value: unknown): void {
  const str = JSON.stringify(value);
  const match = BARE_64HEX_RE.exec(str);
  if (match) {
    // The fingerprint field carries "sha256:<64 hex>" — that is a 71-char string,
    // not a bare 64-hex value, so it will not be captured here.
    // Encrypted fields are base64 (contain [A-Z+/=]) and are longer than 64 chars.
    throw new Error(
      `Plaintext private key pattern found in response (bare 64-hex string "${match[1].slice(0, 8)}…"): ` +
        str.slice(0, 300),
    );
  }
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------
describe("create_private_keys end-to-end", () => {
  it("skip message when go is absent", () => {
    if (!goAvailable) {
      console.warn(
        "[createKey.int.test] Go toolchain not available — signer integration tests skipped.",
      );
    }
    // Always passes; downstream tests use the goAvailable guard.
    expect(true).toBe(true);
  });

  it("submit → 200 COMPLETED activity with a 0x Ethereum address", async () => {
    if (!goAvailable) return;

    const res = await submitTo(app, makeCreateKeysBody());
    expect(res.status).toBe(200);

    const body = (await res.json()) as {
      activity: {
        status: string;
        result: { createPrivateKeysResult: { privateKeyIds: string[]; addresses: { address: string }[] } };
        failure: unknown;
      };
    };

    expect(body.activity.status).toBe("ACTIVITY_STATUS_COMPLETED");
    expect(body.activity.failure).toBeNull();

    const result = body.activity.result.createPrivateKeysResult;
    expect(result.privateKeyIds).toHaveLength(1);
    expect(result.addresses).toHaveLength(1);
    expect(result.addresses[0].address).toMatch(/^0x[0-9a-fA-F]{40}$/);

    // Critical: no plaintext private key anywhere in the response.
    assertNoPlaintextKey(body);
  });

  it("private_keys row persisted with ciphertext + correct encryption_context", async () => {
    if (!goAvailable) return;

    const res = await submitTo(app, makeCreateKeysBody({ name: "ctx-check-key", timestampMs: String(Date.now()) }));
    expect(res.status).toBe(200);

    const body = (await res.json()) as {
      activity: { result: { createPrivateKeysResult: { privateKeyIds: string[] } } };
    };
    const [privateKeyId] = body.activity.result.createPrivateKeysResult.privateKeyIds;
    expect(privateKeyId).toBeTruthy();

    // Fetch the raw DB row — only storage-layer check; repo API hides ciphertext.
    const row = await tdb.db
      .selectFrom("private_keys")
      .selectAll()
      .where("id", "=", privateKeyId)
      .executeTakeFirst();

    expect(row).not.toBeUndefined();
    expect(row!.encrypted_private_key.length).toBeGreaterThan(0);
    expect(row!.encrypted_data_key.length).toBeGreaterThan(0);
    expect(row!.kms_provider).toBe("local");

    // Verify encryption context contains all required fields.
    const encCtx = row!.encryption_context as Record<string, string>;
    expect(encCtx.organization_id).toBe(organizationId);
    expect(encCtx.private_key_id).toBe(privateKeyId);
    expect(encCtx.purpose).toBe("wallet-signing");
    expect(typeof encCtx.environment).toBe("string");

    // Critical: DB row must not contain a 64-hex plaintext private key anywhere.
    assertNoPlaintextKey(row);
  });

  it("get_private_key returns public metadata without ciphertext", async () => {
    if (!goAvailable) return;

    const submitRes = await submitTo(app, makeCreateKeysBody({ name: "get-pk-test", timestampMs: String(Date.now()) }));
    const submitBody = (await submitRes.json()) as {
      activity: { result: { createPrivateKeysResult: { privateKeyIds: string[] } } };
    };
    const [privateKeyId] = submitBody.activity.result.createPrivateKeysResult.privateKeyIds;

    const res = await query("get_private_key", {
      organizationId,
      privateKeyId,
      timestampMs: String(Date.now()),
    });
    expect(res.status).toBe(200);

    const body = (await res.json()) as {
      privateKey: {
        privateKeyId: string;
        publicKey: string;
        curve: string;
        addresses: unknown;
        createdAt: string;
      };
    };
    expect(body.privateKey.privateKeyId).toBe(privateKeyId);
    expect(body.privateKey.publicKey).toMatch(/^[0-9a-f]{66}$/); // 33-byte compressed
    expect(body.privateKey.curve).toBe("CURVE_SECP256K1");

    // Must not expose ciphertext or plaintext key fields.
    expect((body.privateKey as Record<string, unknown>).encryptedPrivateKey).toBeUndefined();
    expect((body.privateKey as Record<string, unknown>).encryptedDataKey).toBeUndefined();
    assertNoPlaintextKey(body);
  });

  it("list_private_keys returns the created keys for the org", async () => {
    if (!goAvailable) return;

    const res = await query("list_private_keys", {
      organizationId,
      timestampMs: String(Date.now()),
    });
    expect(res.status).toBe(200);

    const body = (await res.json()) as { privateKeys: unknown[] };
    expect(Array.isArray(body.privateKeys)).toBe(true);
    expect(body.privateKeys.length).toBeGreaterThan(0);

    // Every entry must omit ciphertext.
    for (const pk of body.privateKeys) {
      expect((pk as Record<string, unknown>).encryptedPrivateKey).toBeUndefined();
      assertNoPlaintextKey(pk);
    }
  });

  // ---------------------------------------------------------------------------
  // Guarded import path
  // ---------------------------------------------------------------------------
  describe("guarded import path", () => {
    it("import refused when ALLOW_KEY_IMPORT=false → activity FAILED", async () => {
      if (!goAvailable) return;

      const res = await submitTo(
        app,
        makeCreateKeysBody({
          name: "import-blocked",
          timestampMs: String(Date.now()),
          importPrivateKeyHex: TEST_IMPORT_PRIV_HEX,
        }),
      );
      // The signer returns 403; the API surfaces that as a 500 TurnkeyError
      // (signer unavailable) which translates to a FAILED activity.
      // We assert the response is 200 with a non-COMPLETED status OR 5xx.
      if (res.status === 200) {
        const body = (await res.json()) as { activity: { status: string } };
        expect(body.activity.status).not.toBe("ACTIVITY_STATUS_COMPLETED");
      } else {
        expect(res.status).toBeGreaterThanOrEqual(400);
      }
    });

    it("import succeeds when ALLOW_KEY_IMPORT=true → address matches test vector", async () => {
      if (!goAvailable) return;

      const res = await submitTo(
        appWithImport,
        makeCreateKeysBody({
          name: "import-ok",
          timestampMs: String(Date.now()),
          importPrivateKeyHex: TEST_IMPORT_PRIV_HEX,
        }),
      );
      expect(res.status).toBe(200);

      const body = (await res.json()) as {
        activity: {
          status: string;
          result: { createPrivateKeysResult: { addresses: { address: string }[] } };
          failure: unknown;
        };
      };
      expect(body.activity.status).toBe("ACTIVITY_STATUS_COMPLETED");
      expect(body.activity.failure).toBeNull();

      const addr = body.activity.result.createPrivateKeysResult.addresses[0].address;
      // go-ethereum returns EIP-55 checksummed; compare case-insensitively.
      expect(addr.toLowerCase()).toBe(TEST_IMPORT_ADDRESS.toLowerCase());

      assertNoPlaintextKey(body);
    });

    it("import key hex is NOT stored in activities.request_body (CRITICAL-1)", async () => {
      if (!goAvailable) return;

      // Submit an import request with a recognisable private key hex.
      const res = await submitTo(
        appWithImport,
        makeCreateKeysBody({
          name: "import-scrub-check",
          timestampMs: String(Date.now()),
          importPrivateKeyHex: TEST_IMPORT_PRIV_HEX,
        }),
      );
      expect(res.status).toBe(200);

      const body = (await res.json()) as {
        activity: { id: string; status: string };
      };
      expect(body.activity.status).toBe("ACTIVITY_STATUS_COMPLETED");

      // Fetch the raw DB row and assert the 64-hex private key is absent.
      const row = await tdb.db
        .selectFrom("activities")
        .selectAll()
        .where("id", "=", body.activity.id)
        .executeTakeFirst();

      expect(row).not.toBeUndefined();

      // The serialised request_body must not contain the raw private key.
      const storedBody = JSON.stringify(row!.request_body);
      expect(storedBody).not.toContain(TEST_IMPORT_PRIV_HEX);
      // Also confirm no bare 64-hex string is present anywhere in the stored row.
      assertNoPlaintextKey(row!.request_body);
    });
  });
});
