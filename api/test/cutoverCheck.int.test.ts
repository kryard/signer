/**
 * Integration test: P9 cutover-readiness check.
 *
 * Tests the runCutoverChecks() function from scripts/cutover-check.ts against:
 *   - A Testcontainers Postgres instance (with migrations applied)
 *   - A running Go signer process (started via the existing signer helper)
 *
 * Test cases:
 *   1. All checks PASS when DB + signer are healthy and policy is seeded.
 *   2. Policy check FAILS when policy_bindings table is empty for the given org.
 *   3. POLICY_BYPASS_ALLOWED=true produces a FAIL for that specific check.
 *   4. Signer health check FAILS when signer is unreachable.
 *   5. ALLOW_KEY_IMPORT=true produces a WARN for that specific check.
 *
 * Requires Docker (Testcontainers) and Go toolchain.
 * If Go is absent the signer-dependent tests are skipped.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { seedStamper } from "./helpers/stamp";
import { startTestDb, type TestDb } from "./helpers/pg";
import { startTestSigner, type TestSigner } from "./helpers/signer";
import { runCutoverChecks, type CheckResult } from "../scripts/cutover-check";

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------
let tdb: TestDb;
let signer: TestSigner | null = null;
let organizationId: string;
let actorId: string;
let goAvailable = true;

beforeAll(async () => {
  tdb = await startTestDb();
  // seedStamper creates an org + actor + api_key, which is the minimum seeding.
  ({ organizationId, actorId } = await seedStamper(tdb.db));

  signer = await startTestSigner(false);
  if (!signer) {
    goAvailable = false;
  }
}, 120_000);

afterAll(async () => {
  signer?.stop();
  await tdb.stop();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function findCheck(results: CheckResult[], nameFragment: string): CheckResult | undefined {
  return results.find((r) => r.name.includes(nameFragment));
}

async function seedPolicyBinding(orgId: string, actId: string): Promise<string> {
  // Insert a minimal private_key row so we can reference it in policy_bindings.
  const { randomUUID } = await import("node:crypto");
  const keyId = randomUUID();

  await tdb.db.insertInto("private_keys").values({
    id: keyId,
    organization_id: orgId,
    name: "cutover-check-test-key",
    curve: "CURVE_SECP256K1",
    public_key: "0".repeat(66),
    addresses: JSON.stringify([]),
    encrypted_private_key: "fake-encrypted",
    encrypted_data_key: "fake-dek",
    kms_provider: "local",
    kms_key_id: "local",
    encryption_context: JSON.stringify({ organization_id: orgId, private_key_id: keyId, purpose: "wallet-signing", environment: "test" }),
    created_by_activity_id: null,
  }).execute();

  await tdb.db.insertInto("policy_bindings").values({
    id: randomUUID(),
    organization_id: orgId,
    actor_id: actId,
    resource_type: "private_key",
    resource_id: keyId,
    allowed_activity_type: "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
  }).execute();

  return keyId;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe("P9 cutover-readiness check", () => {
  it("skip message when Go is absent", () => {
    if (!goAvailable) {
      console.warn("[cutoverCheck.int.test] Go toolchain not available — signer checks skipped.");
    }
    expect(true).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // 1. All checks PASS when DB + signer are seeded and healthy
  // ---------------------------------------------------------------------------
  it("all checks PASS when DB + signer are healthy and policy is seeded", async () => {
    if (!goAvailable) return;

    await seedPolicyBinding(organizationId, actorId);

    const results = await runCutoverChecks({
      databaseUrl: "unused", // we pass db directly
      signerBaseUrl: signer!.baseUrl,
      organizationId,
      policyBypassAllowed: false,
      allowKeyImport: false,
      db: tdb.db,
    });

    // DB reachable
    const dbCheck = findCheck(results, "DB reachable");
    expect(dbCheck?.status).toBe("PASS");

    // Migrations applied
    const migCheck = findCheck(results, "Migrations");
    expect(migCheck?.status).toBe("PASS");

    // Policy fail-closed
    const bypassCheck = findCheck(results, "POLICY_BYPASS_ALLOWED");
    expect(bypassCheck?.status).toBe("PASS");

    const bindingsCheck = findCheck(results, "policy_bindings");
    expect(bindingsCheck?.status).toBe("PASS");

    // Signer health
    const healthCheck = findCheck(results, "Signer /internal/health");
    expect(healthCheck?.status).toBe("PASS");

    // ALLOW_KEY_IMPORT
    const importCheck = findCheck(results, "ALLOW_KEY_IMPORT");
    expect(importCheck?.status).toBe("PASS");

    // No FAIL checks overall
    const fails = results.filter((r) => r.status === "FAIL");
    expect(fails).toHaveLength(0);
  });

  // ---------------------------------------------------------------------------
  // 2. Policy check FAILS when policy_bindings table is empty for the org
  // ---------------------------------------------------------------------------
  it("policy check FAILS when policy_bindings is empty for the given org", async () => {
    if (!goAvailable) return;

    // Use a fresh org with no policy bindings.
    const { randomUUID } = await import("node:crypto");
    const emptyOrg = await tdb.db
      .insertInto("organizations")
      .values({ name: "empty-policy-org" })
      .returning("id")
      .executeTakeFirstOrThrow();

    const emptyActor = await tdb.db
      .insertInto("actors")
      .values({ organization_id: emptyOrg.id, name: "empty-actor" })
      .returning("id")
      .executeTakeFirstOrThrow();

    void randomUUID; // suppress unused import warning
    void emptyActor; // used for consistent state; no bindings inserted

    const results = await runCutoverChecks({
      databaseUrl: "unused",
      signerBaseUrl: signer!.baseUrl,
      organizationId: emptyOrg.id,
      policyBypassAllowed: false,
      allowKeyImport: false,
      db: tdb.db,
    });

    const bindingsCheck = findCheck(results, "policy_bindings");
    expect(bindingsCheck?.status).toBe("FAIL");
    expect(bindingsCheck?.detail).toContain(emptyOrg.id);
  });

  // ---------------------------------------------------------------------------
  // 3. POLICY_BYPASS_ALLOWED=true produces FAIL
  // ---------------------------------------------------------------------------
  it("POLICY_BYPASS_ALLOWED=true produces FAIL for the bypass check", async () => {
    if (!goAvailable) return;

    const results = await runCutoverChecks({
      databaseUrl: "unused",
      signerBaseUrl: signer!.baseUrl,
      organizationId,
      policyBypassAllowed: true, // the flag is on
      allowKeyImport: false,
      db: tdb.db,
    });

    const bypassCheck = findCheck(results, "POLICY_BYPASS_ALLOWED");
    expect(bypassCheck?.status).toBe("FAIL");
    expect(bypassCheck?.detail).toContain("fail-closed");
  });

  // ---------------------------------------------------------------------------
  // 4. Signer health check FAILS when signer is unreachable
  // ---------------------------------------------------------------------------
  it("signer health check FAILS when signer URL is unreachable", async () => {
    // This test does NOT require goAvailable — it just checks the health check
    // against a port that is certainly not listening.
    const results = await runCutoverChecks({
      databaseUrl: "unused",
      signerBaseUrl: "http://127.0.0.1:1",  // nothing listening here
      organizationId,
      policyBypassAllowed: false,
      allowKeyImport: false,
      db: tdb.db,
    });

    const healthCheck = findCheck(results, "Signer /internal/health");
    expect(healthCheck?.status).toBe("FAIL");
  });

  // ---------------------------------------------------------------------------
  // 5. ALLOW_KEY_IMPORT=true produces WARN
  // ---------------------------------------------------------------------------
  it("ALLOW_KEY_IMPORT=true produces WARN", async () => {
    if (!goAvailable) return;

    const results = await runCutoverChecks({
      databaseUrl: "unused",
      signerBaseUrl: signer!.baseUrl,
      organizationId,
      policyBypassAllowed: false,
      allowKeyImport: true, // import window is open
      db: tdb.db,
    });

    const importCheck = findCheck(results, "ALLOW_KEY_IMPORT");
    expect(importCheck?.status).toBe("WARN");
    expect(importCheck?.detail).toContain("guarded import window");
  });

  // ---------------------------------------------------------------------------
  // 6. DB unreachable produces FAIL for DB check (without needing signer)
  // ---------------------------------------------------------------------------
  it("DB unreachable produces FAIL for the DB reachable check", async () => {
    // Create a db pointing at nothing — this will fail on any query.
    const { makeDb } = await import("../src/db");
    const deadDb = makeDb("postgres://invalid:invalid@127.0.0.1:9999/invalid");

    let results: CheckResult[];
    try {
      results = await runCutoverChecks({
        databaseUrl: "unused",
        signerBaseUrl: signer?.baseUrl ?? "http://127.0.0.1:1",
        policyBypassAllowed: false,
        allowKeyImport: false,
        db: deadDb,
      });
    } finally {
      await deadDb.destroy().catch(() => {/* ignore */});
    }

    const dbCheck = findCheck(results, "DB reachable");
    expect(dbCheck?.status).toBe("FAIL");
  });
});
