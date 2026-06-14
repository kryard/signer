/**
 * P9 — Cutover readiness check.
 *
 * Verifies that a target Postgres DB + signer are ready for production cutover.
 * Exits NONZERO on any failure, printing a checklist of checks.
 *
 * Usage:
 *   DATABASE_URL=postgres://... SIGNER_BASE_URL=http://... pnpm cutover-check
 *
 * Optional environment variables:
 *   POLICY_BYPASS_ALLOWED   — should be unset or "false" in prod; warns if "true"
 *   ALLOW_KEY_IMPORT         — should be unset or "false" in prod; warns if "true"
 *   ORGANIZATION_ID          — if set, verifies policy_bindings exist for that org
 *
 * The check logic is exported as `runCutoverChecks` so it can be imported by tests.
 */

import { makeDb } from "../src/db";
import type { Kysely } from "kysely";
import type { Database } from "../src/db";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CheckResult {
  name: string;
  status: "PASS" | "FAIL" | "WARN";
  detail?: string;
}

export interface CutoverCheckOptions {
  databaseUrl: string;
  signerBaseUrl: string;
  organizationId?: string;
  policyBypassAllowed?: boolean;
  allowKeyImport?: boolean;
  /** Override the DB instance (for testing — skip URL-based makeDb). */
  db?: Kysely<Database>;
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

async function checkDbReachable(db: Kysely<Database>): Promise<CheckResult> {
  try {
    await db.selectFrom("organizations").select("id").limit(1).execute();
    return { name: "DB reachable", status: "PASS" };
  } catch (err) {
    return {
      name: "DB reachable",
      status: "FAIL",
      detail: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Check that migrations 001–005 are all applied.
 * Kysely migrations are tracked in the `kysely_migration` table.
 * We check that all expected migration names are present AND that expected tables exist.
 */
async function checkMigrations(db: Kysely<Database>): Promise<CheckResult> {
  const REQUIRED_MIGRATIONS = [
    "001_activities",
    "002_auth",
    "003_private_keys",
    "004_wallets",
    "005_policy",
  ];

  try {
    // Check kysely migration table
    const rows = await db
      .selectFrom("kysely_migration" as any) // eslint-disable-line @typescript-eslint/no-explicit-any
      .select("name" as any) // eslint-disable-line @typescript-eslint/no-explicit-any
      .execute() as Array<{ name: string }>;

    const applied = new Set(rows.map((r) => r.name));
    const missing = REQUIRED_MIGRATIONS.filter((m) => !applied.has(m));

    if (missing.length > 0) {
      return {
        name: "Migrations 001–005 applied",
        status: "FAIL",
        detail: `Missing: ${missing.join(", ")}`,
      };
    }

    // Also verify expected tables exist by querying them
    const tablesToCheck: Array<keyof Database> = [
      "activities",
      "organizations",
      "actors",
      "api_keys",
      "private_keys",
      "policy_bindings",
      "wallet_policy_rules",
      "wallet_destination_allowlist",
      "policy_decisions",
    ];

    for (const table of tablesToCheck) {
      try {
        await db.selectFrom(table).select("id" as any).limit(0).execute(); // eslint-disable-line @typescript-eslint/no-explicit-any
      } catch (err) {
        return {
          name: "Migrations 001–005 applied",
          status: "FAIL",
          detail: `Table ${table} not found: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    }

    return { name: "Migrations 001–005 applied", status: "PASS" };
  } catch (err) {
    return {
      name: "Migrations 001–005 applied",
      status: "FAIL",
      detail: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Check that the relayer org is fail-closed.
 * If organizationId is provided: assert policy_bindings rows exist for it.
 * Assert POLICY_BYPASS_ALLOWED is not "true".
 */
async function checkPolicyFailClosed(
  db: Kysely<Database>,
  organizationId?: string,
  policyBypassAllowed?: boolean,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];

  // Check POLICY_BYPASS_ALLOWED env
  if (policyBypassAllowed === true) {
    results.push({
      name: "POLICY_BYPASS_ALLOWED is not set",
      status: "FAIL",
      detail: "POLICY_BYPASS_ALLOWED=true means the system is NOT fail-closed. Unset this in production.",
    });
  } else {
    results.push({ name: "POLICY_BYPASS_ALLOWED is not set", status: "PASS" });
  }

  // Check policy_bindings if org provided
  if (organizationId) {
    try {
      const bindings = await db
        .selectFrom("policy_bindings")
        .select("id")
        .where("organization_id", "=", organizationId)
        .execute();

      if (bindings.length === 0) {
        results.push({
          name: "Relayer org has policy_bindings",
          status: "FAIL",
          detail: `Organization ${organizationId} has no policy_bindings — org would be treated as fail-closed but relayer calls would be denied.`,
        });
      } else {
        results.push({
          name: "Relayer org has policy_bindings",
          status: "PASS",
          detail: `${bindings.length} binding(s) found`,
        });
      }
    } catch (err) {
      results.push({
        name: "Relayer org has policy_bindings",
        status: "FAIL",
        detail: err instanceof Error ? err.message : String(err),
      });
    }
  } else {
    results.push({
      name: "Relayer org has policy_bindings",
      status: "WARN",
      detail: "ORGANIZATION_ID not set — skipping policy_bindings check. Set it for a complete readiness check.",
    });
  }

  return results;
}

/**
 * Check the signer is reachable and healthy.
 */
async function checkSignerHealth(signerBaseUrl: string): Promise<CheckResult[]> {
  const results: CheckResult[] = [];

  try {
    const res = await fetch(`${signerBaseUrl}/internal/health`, {
      signal: AbortSignal.timeout(5000),
    });

    if (!res.ok) {
      results.push({
        name: "Signer /internal/health returns ok",
        status: "FAIL",
        detail: `HTTP ${res.status}`,
      });
      return results;
    }

    const body = (await res.json()) as { status?: string; kmsProvider?: string };

    if (body.status !== "ok") {
      results.push({
        name: "Signer /internal/health returns ok",
        status: "FAIL",
        detail: `status=${body.status}`,
      });
    } else {
      results.push({ name: "Signer /internal/health returns ok", status: "PASS" });
    }

    // Warn if kms_provider is not "aws" in prod
    if (body.kmsProvider && body.kmsProvider !== "aws") {
      results.push({
        name: "Signer KMS provider is 'aws'",
        status: "WARN",
        detail: `kmsProvider=${body.kmsProvider} — expected 'aws' in production. 'local' is for dev/test only.`,
      });
    } else if (body.kmsProvider === "aws") {
      results.push({ name: "Signer KMS provider is 'aws'", status: "PASS" });
    } else {
      // Health endpoint may not expose kmsProvider — just skip
      results.push({
        name: "Signer KMS provider is 'aws'",
        status: "WARN",
        detail: "Health response did not include kmsProvider field — cannot verify.",
      });
    }
  } catch (err) {
    results.push({
      name: "Signer /internal/health returns ok",
      status: "FAIL",
      detail: err instanceof Error ? err.message : String(err),
    });
  }

  return results;
}

/**
 * Check ALLOW_KEY_IMPORT is not set in production.
 */
function checkAllowKeyImport(allowKeyImport?: boolean): CheckResult {
  if (allowKeyImport === true) {
    return {
      name: "ALLOW_KEY_IMPORT is not set",
      status: "WARN",
      detail: "ALLOW_KEY_IMPORT=true — the guarded import window is open. Unset this immediately after any one-time key import.",
    };
  }
  return { name: "ALLOW_KEY_IMPORT is not set", status: "PASS" };
}

// ---------------------------------------------------------------------------
// Main exported function
// ---------------------------------------------------------------------------

/**
 * Run all cutover checks and return the results.
 * Does NOT print or exit — callers decide how to handle the results.
 * This function is importable for use in integration tests.
 */
export async function runCutoverChecks(
  opts: CutoverCheckOptions,
): Promise<CheckResult[]> {
  const db = opts.db ?? makeDb(opts.databaseUrl);
  const ownDb = !opts.db; // did we create the db? if so, destroy it after
  const results: CheckResult[] = [];

  try {
    results.push(await checkDbReachable(db));
    results.push(await checkMigrations(db));

    const policyChecks = await checkPolicyFailClosed(db, opts.organizationId, opts.policyBypassAllowed);
    results.push(...policyChecks);

    const signerChecks = await checkSignerHealth(opts.signerBaseUrl);
    results.push(...signerChecks);

    results.push(checkAllowKeyImport(opts.allowKeyImport));
  } finally {
    if (ownDb) {
      await db.destroy();
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// CLI entrypoint
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const databaseUrl = process.env.DATABASE_URL;
  const signerBaseUrl = process.env.SIGNER_BASE_URL;

  if (!databaseUrl) {
    console.error("ERROR: DATABASE_URL is required");
    process.exit(1);
  }
  if (!signerBaseUrl) {
    console.error("ERROR: SIGNER_BASE_URL is required");
    process.exit(1);
  }

  const policyBypassAllowed = process.env.POLICY_BYPASS_ALLOWED === "true";
  const allowKeyImport = process.env.ALLOW_KEY_IMPORT === "true";
  const organizationId = process.env.ORGANIZATION_ID || undefined;

  console.log("=== Kryard P9 Cutover Readiness Check ===");
  console.log(`DATABASE_URL:        ${databaseUrl.replace(/:\/\/[^@]+@/, "://<redacted>@")}`);
  console.log(`SIGNER_BASE_URL:     ${signerBaseUrl}`);
  if (organizationId) console.log(`ORGANIZATION_ID:     ${organizationId}`);
  console.log("");

  let results: CheckResult[];
  try {
    results = await runCutoverChecks({
      databaseUrl,
      signerBaseUrl,
      organizationId,
      policyBypassAllowed,
      allowKeyImport,
    });
  } catch (err) {
    console.error("Unexpected error during checks:", err);
    process.exit(1);
  }

  // Print checklist
  let anyFail = false;
  let anyWarn = false;
  for (const r of results) {
    const icon = r.status === "PASS" ? "✓" : r.status === "FAIL" ? "✗" : "⚠";
    const line = `  [${icon} ${r.status}] ${r.name}${r.detail ? ` — ${r.detail}` : ""}`;
    if (r.status === "FAIL") {
      anyFail = true;
      console.error(line);
    } else if (r.status === "WARN") {
      anyWarn = true;
      console.warn(line);
    } else {
      console.log(line);
    }
  }

  console.log("");
  if (anyFail) {
    console.error("CUTOVER READINESS: FAIL — address the issues above before cutting over.");
    process.exit(1);
  } else if (anyWarn) {
    console.warn("CUTOVER READINESS: WARN — review warnings above; proceeding may be unsafe.");
    process.exit(0); // warnings are non-fatal; the human decides
  } else {
    console.log("CUTOVER READINESS: PASS — all checks green. Safe to proceed with cutover.");
    process.exit(0);
  }
}

// Guard: only run when executed directly as a CLI script, not when imported by tests.
// In ESM with tsx, import.meta.url resolves to the file URL of this module.
// process.argv[1] is the path of the entry script tsx was given.
// We compare them to detect direct execution vs. import.
{
  const { pathToFileURL } = await import("node:url");
  const entryUrl = pathToFileURL(process.argv[1] ?? "").href;
  if (import.meta.url === entryUrl || entryUrl.endsWith("cutover-check.ts")) {
    main().catch((err) => {
      console.error("cutover-check: unexpected error:", err);
      process.exit(1);
    });
  }
}
