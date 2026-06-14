/**
 * Integration test: create_wallet + create_wallet_accounts end-to-end.
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
import { startTestSigner, type TestSigner } from "./helpers/signer";
import { seedApiKey } from "./helpers/seed";
import { p256 } from "@noble/curves/p256";
import { bytesToHex } from "@noble/hashes/utils";
import { ApiKeyStamper } from "@turnkey/api-key-stamper";
import { SCHEME_P256 } from "../src/stamp";
import type { ApiKeyStamper as ApiKeyStamperType } from "@turnkey/api-key-stamper";

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------
let tdb: TestDb;
let signer: TestSigner | null = null;
let app: ReturnType<typeof createApp>;
let organizationId: string;
let stamper: ApiKeyStamperType;
let goAvailable = true;

// A second org for scoping tests.
let org2Id: string;
let stamper2: ApiKeyStamperType;

beforeAll(async () => {
  tdb = await startTestDb();
  ({ organizationId, stamper } = await seedStamper(tdb.db));

  // Seed a second org with a distinct key pair.
  const priv2 = "0202020202020202020202020202020202020202020202020202020202020202";
  const pub2 = bytesToHex(p256.getPublicKey(priv2, true));
  const { organizationId: o2 } = await seedApiKey(tdb.db, pub2, SCHEME_P256);
  org2Id = o2;
  stamper2 = new ApiKeyStamper({ apiPublicKey: pub2, apiPrivateKey: priv2 });

  signer = await startTestSigner(false);

  if (!signer) {
    goAvailable = false;
    app = createApp({ db: tdb.db, signerBaseUrl: "http://127.0.0.1:1" });
    return;
  }

  app = createApp({ db: tdb.db, signerBaseUrl: signer.baseUrl });
});

afterAll(async () => {
  signer?.stop();
  await tdb.stop();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
async function submit(body: Record<string, unknown>, useStamper: ApiKeyStamperType = stamper) {
  const init = await stampedRequest(useStamper, body);
  const path = body.type === "ACTIVITY_TYPE_CREATE_WALLET"
    ? "create_wallet"
    : "create_wallet_accounts";
  return app.request(`/public/v1/submit/${path}`, init);
}

async function query(path: string, body: Record<string, unknown>, useStamper: ApiKeyStamperType = stamper) {
  const init = await stampedRequest(useStamper, body);
  return app.request(`/public/v1/query/${path}`, init);
}

function makeCreateWalletBody(extra: Record<string, unknown> = {}) {
  return {
    type: "ACTIVITY_TYPE_CREATE_WALLET",
    organizationId,
    timestampMs: String(Date.now()),
    parameters: { walletName: "my-wallet", ...extra },
  };
}

function makeCreateWalletAccountsBody(walletId: string, extra: Record<string, unknown> = {}) {
  return {
    type: "ACTIVITY_TYPE_CREATE_WALLET_ACCOUNTS",
    organizationId,
    timestampMs: String(Date.now()),
    parameters: {
      walletId,
      accounts: [
        { name: "acct-1", curve: "CURVE_SECP256K1", addressFormat: "ADDRESS_FORMAT_ETHEREUM" },
        { name: "acct-2", curve: "CURVE_SECP256K1", addressFormat: "ADDRESS_FORMAT_ETHEREUM" },
      ],
      ...extra,
    },
  };
}

// Plain-text key guard (same pattern as createKey.int.test.ts).
const BARE_64HEX_RE = /"([0-9a-f]{64})"/i;
function assertNoPlaintextKey(value: unknown): void {
  const str = JSON.stringify(value);
  const match = BARE_64HEX_RE.exec(str);
  if (match) {
    throw new Error(
      `Plaintext private key pattern found (bare 64-hex "${match[1].slice(0, 8)}…"): ` +
        str.slice(0, 300),
    );
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe("wallets integration", () => {
  it("skip message when go is absent", () => {
    if (!goAvailable) {
      console.warn("[wallets.int.test] Go toolchain not available — signer tests skipped.");
    }
    expect(true).toBe(true);
  });

  // -------------------------------------------------------------------------
  // create_wallet (no accounts)
  // -------------------------------------------------------------------------
  describe("create_wallet", () => {
    it("→ 200 COMPLETED with a walletId", async () => {
      if (!goAvailable) return;

      const res = await submit(makeCreateWalletBody());
      expect(res.status).toBe(200);

      const body = (await res.json()) as {
        activity: {
          status: string;
          result: { createWalletResult: { walletId: string; addresses: string[] } };
          failure: unknown;
        };
      };

      expect(body.activity.status).toBe("ACTIVITY_STATUS_COMPLETED");
      expect(body.activity.failure).toBeNull();
      const result = body.activity.result.createWalletResult;
      expect(typeof result.walletId).toBe("string");
      expect(result.walletId.length).toBeGreaterThan(0);
    });

    it("wallets row persisted in DB", async () => {
      if (!goAvailable) return;

      const res = await submit(makeCreateWalletBody({ walletName: "db-check-wallet", timestampMs: String(Date.now()) }));
      const body = (await res.json()) as {
        activity: { result: { createWalletResult: { walletId: string } } };
      };
      const walletId = body.activity.result.createWalletResult.walletId;

      const row = await tdb.db
        .selectFrom("wallets")
        .selectAll()
        .where("id", "=", walletId)
        .executeTakeFirst();

      expect(row).not.toBeUndefined();
      expect(row!.name).toBe("db-check-wallet");
      expect(row!.organization_id).toBe(organizationId);
      expect(row!.created_by_activity_id).toBeTruthy();
    });
  });

  // -------------------------------------------------------------------------
  // create_wallet_accounts (N=2)
  // -------------------------------------------------------------------------
  describe("create_wallet_accounts N=2", () => {
    let walletId: string;
    let activityResult: { addresses: string[] };

    beforeAll(async () => {
      if (!goAvailable) return;

      // First create a wallet to attach accounts to.
      const walletRes = await submit(makeCreateWalletBody({ walletName: "acct-wallet", timestampMs: String(Date.now()) }));
      const walletBody = (await walletRes.json()) as {
        activity: { result: { createWalletResult: { walletId: string } } };
      };
      walletId = walletBody.activity.result.createWalletResult.walletId;

      const res = await submit(makeCreateWalletAccountsBody(walletId));
      const body = (await res.json()) as {
        activity: {
          status: string;
          result: { createWalletAccountsResult: { addresses: string[] } };
          failure: unknown;
        };
      };

      expect(body.activity.status).toBe("ACTIVITY_STATUS_COMPLETED");
      activityResult = body.activity.result.createWalletAccountsResult;
    });

    it("returns 2 Ethereum addresses", async () => {
      if (!goAvailable) return;
      expect(activityResult.addresses).toHaveLength(2);
      for (const addr of activityResult.addresses) {
        expect(addr).toMatch(/^0x[0-9a-fA-F]{40}$/);
      }
    });

    it("2 wallet_accounts rows + linked private_keys rows persisted", async () => {
      if (!goAvailable) return;

      const waRows = await tdb.db
        .selectFrom("wallet_accounts")
        .selectAll()
        .where("wallet_id", "=", walletId)
        .execute();

      expect(waRows).toHaveLength(2);

      for (const wa of waRows) {
        expect(wa.organization_id).toBe(organizationId);
        expect(wa.wallet_id).toBe(walletId);
        expect(wa.address).toMatch(/^0x[0-9a-fA-F]{40}$/);

        // Linked private_keys row must exist.
        const pkRow = await tdb.db
          .selectFrom("private_keys")
          .selectAll()
          .where("id", "=", wa.private_key_id)
          .executeTakeFirst();

        expect(pkRow).not.toBeUndefined();
        expect(pkRow!.encrypted_private_key.length).toBeGreaterThan(0);
        // No plaintext key material in the stored row.
        assertNoPlaintextKey(pkRow);
      }
    });

    it("no plaintext key in the activity response", async () => {
      if (!goAvailable) return;
      assertNoPlaintextKey(activityResult);
    });
  });

  // -------------------------------------------------------------------------
  // Idempotency
  // -------------------------------------------------------------------------
  describe("idempotency", () => {
    it("same create_wallet body → same activity id, no extra wallet row", async () => {
      if (!goAvailable) return;

      // Use a current timestamp so auth freshness check passes, then submit SAME body twice.
      const body = makeCreateWalletBody({ walletName: "idem-wallet", timestampMs: String(Date.now()) });
      const r1 = (await (await submit(body)).json()) as { activity: { id: string; result: { createWalletResult: { walletId: string } } } };
      const r2 = (await (await submit(body)).json()) as { activity: { id: string } };

      expect(r2.activity.id).toBe(r1.activity.id);

      // Exactly one wallet row for that walletId.
      const rows = await tdb.db
        .selectFrom("wallets")
        .selectAll()
        .where("id", "=", r1.activity.result.createWalletResult.walletId)
        .execute();
      expect(rows).toHaveLength(1);
    });

    it("same create_wallet_accounts body → same activity id, no extra account/key rows", async () => {
      if (!goAvailable) return;

      // Create a fresh wallet.
      const walletRes = await submit(makeCreateWalletBody({ walletName: "idem-acct-wallet", timestampMs: String(Date.now()) }));
      const walletBody = (await walletRes.json()) as {
        activity: { result: { createWalletResult: { walletId: string } } };
      };
      const wId = walletBody.activity.result.createWalletResult.walletId;

      // Use a current timestamp so auth freshness check passes, then submit SAME body twice.
      const body = {
        type: "ACTIVITY_TYPE_CREATE_WALLET_ACCOUNTS",
        organizationId,
        timestampMs: String(Date.now()),
        parameters: {
          walletId: wId,
          accounts: [{ name: "idem-acct", curve: "CURVE_SECP256K1", addressFormat: "ADDRESS_FORMAT_ETHEREUM" }],
        },
      };

      const a1 = (await (await submit(body)).json()) as { activity: { id: string } };
      const a2 = (await (await submit(body)).json()) as { activity: { id: string } };

      expect(a2.activity.id).toBe(a1.activity.id);

      // Exactly one wallet_accounts row for this wallet.
      const waRows = await tdb.db
        .selectFrom("wallet_accounts")
        .selectAll()
        .where("wallet_id", "=", wId)
        .execute();
      expect(waRows).toHaveLength(1);
    });
  });

  // -------------------------------------------------------------------------
  // Query endpoints
  // -------------------------------------------------------------------------
  describe("query endpoints", () => {
    let walletId: string;
    let walletAccountIds: string[] = [];

    beforeAll(async () => {
      if (!goAvailable) return;

      // Create wallet with inline accounts.
      const res = await submit(
        makeCreateWalletBody({
          walletName: "query-wallet",
          timestampMs: String(Date.now()),
          accounts: [
            { name: "qa-1", curve: "CURVE_SECP256K1", addressFormat: "ADDRESS_FORMAT_ETHEREUM" },
          ],
        }),
      );
      const body = (await res.json()) as {
        activity: { result: { createWalletResult: { walletId: string } } };
      };
      walletId = body.activity.result.createWalletResult.walletId;

      // Collect wallet account ids from DB.
      const waRows = await tdb.db
        .selectFrom("wallet_accounts")
        .select(["id"])
        .where("wallet_id", "=", walletId)
        .execute();
      walletAccountIds = waRows.map((r) => r.id);
    });

    it("get_wallet returns public metadata", async () => {
      if (!goAvailable) return;

      const res = await query("get_wallet", { organizationId, walletId, timestampMs: String(Date.now()) });
      expect(res.status).toBe(200);

      const body = (await res.json()) as {
        wallet: { walletId: string; walletName: string; createdAt: string };
      };
      expect(body.wallet.walletId).toBe(walletId);
      expect(body.wallet.walletName).toBe("query-wallet");
      expect(typeof body.wallet.createdAt).toBe("string");
      assertNoPlaintextKey(body);
    });

    it("list_wallets includes the created wallet", async () => {
      if (!goAvailable) return;

      const res = await query("list_wallets", { organizationId, timestampMs: String(Date.now()) });
      expect(res.status).toBe(200);

      const body = (await res.json()) as { wallets: { walletId: string }[] };
      expect(body.wallets.some((w) => w.walletId === walletId)).toBe(true);
      assertNoPlaintextKey(body);
    });

    it("get_wallet_account returns public metadata", async () => {
      if (!goAvailable) return;
      if (walletAccountIds.length === 0) return;

      const walletAccountId = walletAccountIds[0];
      const res = await query("get_wallet_account", {
        organizationId,
        walletAccountId,
        timestampMs: String(Date.now()),
      });
      expect(res.status).toBe(200);

      const body = (await res.json()) as {
        walletAccount: {
          walletAccountId: string;
          walletId: string;
          curve: string;
          addressFormat: string;
          address: string;
        };
      };
      expect(body.walletAccount.walletAccountId).toBe(walletAccountId);
      expect(body.walletAccount.walletId).toBe(walletId);
      expect(body.walletAccount.address).toMatch(/^0x[0-9a-fA-F]{40}$/);
      // Must not expose ciphertext fields.
      expect((body.walletAccount as Record<string, unknown>).encryptedPrivateKey).toBeUndefined();
      assertNoPlaintextKey(body);
    });

    it("list_wallet_accounts returns accounts for the wallet", async () => {
      if (!goAvailable) return;

      const res = await query("list_wallet_accounts", {
        organizationId,
        walletId,
        timestampMs: String(Date.now()),
      });
      expect(res.status).toBe(200);

      const body = (await res.json()) as { walletAccounts: { walletAccountId: string; address: string }[] };
      expect(body.walletAccounts.length).toBeGreaterThan(0);
      for (const wa of body.walletAccounts) {
        expect(wa.address).toMatch(/^0x[0-9a-fA-F]{40}$/);
        assertNoPlaintextKey(wa);
      }
    });

    it("get_wallet 404 for unknown id", async () => {
      if (!goAvailable) return;

      const res = await query("get_wallet", {
        organizationId,
        walletId: "00000000-0000-0000-0000-000000000000",
        timestampMs: String(Date.now()),
      });
      expect(res.status).toBe(404);
    });
  });

  // -------------------------------------------------------------------------
  // Org scoping
  // -------------------------------------------------------------------------
  describe("org scoping", () => {
    let walletId: string;

    beforeAll(async () => {
      if (!goAvailable) return;

      const res = await submit(
        makeCreateWalletBody({ walletName: "org1-wallet", timestampMs: String(Date.now()) }),
      );
      const body = (await res.json()) as {
        activity: { result: { createWalletResult: { walletId: string } } };
      };
      walletId = body.activity.result.createWalletResult.walletId;
    });

    it("org2's stamp cannot read org1's wallet", async () => {
      if (!goAvailable) return;

      // org2 uses its own organizationId in the body — so auth passes for org2,
      // but it queries for org1's walletId.
      const body = {
        organizationId: org2Id,
        walletId,
        timestampMs: String(Date.now()),
      };
      const init = await stampedRequest(stamper2, body);
      const res = await app.request("/public/v1/query/get_wallet", init);
      // Either 404 (not found in org2's scope) or 400 (invalid request).
      expect([400, 404]).toContain(res.status);
    });
  });

  // -------------------------------------------------------------------------
  // Cross-org attach guard (HIGH security fix)
  // -------------------------------------------------------------------------
  describe("cross-org attach guard", () => {
    it("create_wallet_accounts with a walletId from a different org → FAILED WALLET_NOT_FOUND, no rows created", async () => {
      if (!goAvailable) return;

      // Create a wallet owned by org1 (the default org).
      const walletRes = await submit(
        makeCreateWalletBody({ walletName: "org1-guard-wallet", timestampMs: String(Date.now()) }),
      );
      const walletBody = (await walletRes.json()) as {
        activity: { result: { createWalletResult: { walletId: string } } };
      };
      const org1WalletId = walletBody.activity.result.createWalletResult.walletId;

      // Count wallet_accounts and private_keys before the attack attempt.
      const waBefore = await tdb.db
        .selectFrom("wallet_accounts")
        .select(tdb.db.fn.count<string>("id").as("cnt"))
        .executeTakeFirstOrThrow();
      const pkBefore = await tdb.db
        .selectFrom("private_keys")
        .select(tdb.db.fn.count<string>("id").as("cnt"))
        .executeTakeFirstOrThrow();

      // org2 tries to attach accounts to org1's wallet by supplying org1's walletId
      // but stamping with org2's credentials.
      const attackBody = {
        type: "ACTIVITY_TYPE_CREATE_WALLET_ACCOUNTS",
        organizationId: org2Id,
        timestampMs: String(Date.now()),
        parameters: {
          walletId: org1WalletId,
          accounts: [
            { name: "stolen-acct", curve: "CURVE_SECP256K1", addressFormat: "ADDRESS_FORMAT_ETHEREUM" },
          ],
        },
      };
      const init = await stampedRequest(stamper2, attackBody);
      const res = await app.request("/public/v1/submit/create_wallet_accounts", init);
      expect(res.status).toBe(200);

      const body = (await res.json()) as {
        activity: {
          status: string;
          failure: { code: string; message: string } | null;
        };
      };

      // Activity must be FAILED with WALLET_NOT_FOUND.
      expect(body.activity.status).toBe("ACTIVITY_STATUS_FAILED");
      expect(body.activity.failure).not.toBeNull();
      expect(body.activity.failure!.code).toBe("WALLET_NOT_FOUND");

      // No new wallet_accounts or private_keys rows must have been created.
      const waAfter = await tdb.db
        .selectFrom("wallet_accounts")
        .select(tdb.db.fn.count<string>("id").as("cnt"))
        .executeTakeFirstOrThrow();
      const pkAfter = await tdb.db
        .selectFrom("private_keys")
        .select(tdb.db.fn.count<string>("id").as("cnt"))
        .executeTakeFirstOrThrow();

      expect(Number(waAfter.cnt)).toBe(Number(waBefore.cnt));
      expect(Number(pkAfter.cnt)).toBe(Number(pkBefore.cnt));
    });
  });
});
