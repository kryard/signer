/**
 * Integration test: audit hash-chain serialization (migration 007, AC-H2).
 *
 * The load-bearing case is CONCURRENCY: many audit events written at once for
 * one org must still form a single verifiable chain (no fork). Under the old
 * read-latest-then-insert (no lock, created_at tiebreak) this forked; the
 * per-org advisory lock + monotonic seq fix it.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { randomUUID } from "node:crypto";
import { recordAuditEvent, verifyAuditChain } from "../src/audit";
import { startTestDb, type TestDb } from "./helpers/pg";

let tdb: TestDb;
let orgId: string;

beforeAll(async () => {
  tdb = await startTestDb();
  orgId = randomUUID();
  await tdb.db.insertInto("organizations").values({ id: orgId, name: "audit-chain-test" }).execute();
});
afterAll(async () => {
  await tdb.stop();
});

describe("audit hash chain", () => {
  it("sequential writes form a verifiable chain", async () => {
    for (let i = 0; i < 5; i++) {
      await recordAuditEvent(tdb.db, { organizationId: orgId, eventType: "seq_event", metadata: { i } });
    }
    expect(await verifyAuditChain(tdb.db, orgId)).toEqual({ valid: true });
  });

  it("CONCURRENT writes still form a single verifiable chain (no fork)", async () => {
    const org2 = randomUUID();
    await tdb.db.insertInto("organizations").values({ id: org2, name: "audit-conc" }).execute();

    // Fire 25 audit writes for the same org concurrently.
    await Promise.all(
      Array.from({ length: 25 }, (_, i) =>
        recordAuditEvent(tdb.db, { organizationId: org2, eventType: "concurrent", metadata: { i } }),
      ),
    );

    const count = await tdb.db
      .selectFrom("audit_events")
      .select((eb) => eb.fn.countAll().as("c"))
      .where("organization_id", "=", org2)
      .executeTakeFirstOrThrow();
    expect(Number(count.c)).toBe(25);

    // The whole chain must verify (single unforked chain, deterministic order).
    expect(await verifyAuditChain(tdb.db, org2)).toEqual({ valid: true });

    // Exactly one genesis (previous_event_hash NULL) — proves no fork.
    const genesis = await tdb.db
      .selectFrom("audit_events")
      .select((eb) => eb.fn.countAll().as("c"))
      .where("organization_id", "=", org2)
      .where("previous_event_hash", "is", null)
      .executeTakeFirstOrThrow();
    expect(Number(genesis.c)).toBe(1);
  });

  it("a tampered metadata field breaks the chain (detectable)", async () => {
    const org3 = randomUUID();
    await tdb.db.insertInto("organizations").values({ id: org3, name: "audit-tamper" }).execute();
    await recordAuditEvent(tdb.db, { organizationId: org3, eventType: "e1", metadata: { x: 1 } });
    await recordAuditEvent(tdb.db, { organizationId: org3, eventType: "e2", metadata: { x: 2 } });
    expect(await verifyAuditChain(tdb.db, org3)).toEqual({ valid: true });

    // Tamper with the first event's metadata without recomputing its hash.
    const first = await tdb.db
      .selectFrom("audit_events").select(["id"])
      .where("organization_id", "=", org3).orderBy("seq", "asc").limit(1).executeTakeFirstOrThrow();
    await tdb.db.updateTable("audit_events")
      .set({ metadata: JSON.stringify({ x: 999 }) })
      .where("id", "=", first.id).execute();

    const result = await verifyAuditChain(tdb.db, org3);
    expect(result.valid).toBe(false);
  });
});
