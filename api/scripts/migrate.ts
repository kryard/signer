import { promises as fs } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { Migrator, FileMigrationProvider } from "kysely";
import { makeDb } from "../src/db";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));

/**
 * Resolve DATABASE_URL for the migration run.
 *
 * Precedence: the environment wins; otherwise fall back to the `DATABASE_URL`
 * line in `services/api/.dev.vars` (the same file `wrangler dev` reads), so a
 * dev can fill one file and run `pnpm migrate` without a separate export.
 */
async function resolveDatabaseUrl(): Promise<string | undefined> {
  if (process.env.DATABASE_URL) return process.env.DATABASE_URL;

  try {
    const text = await fs.readFile(path.join(SCRIPT_DIR, "../.dev.vars"), "utf8");
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eq = trimmed.indexOf("=");
      if (eq === -1) continue;
      if (trimmed.slice(0, eq).trim() === "DATABASE_URL") {
        return trimmed.slice(eq + 1).trim();
      }
    }
  } catch {
    // .dev.vars absent — handled by the caller's error below.
  }
  return undefined;
}

async function main(): Promise<void> {
  const url = await resolveDatabaseUrl();
  if (!url) {
    throw new Error(
      "DATABASE_URL is required — set it in the environment or in services/api/.dev.vars",
    );
  }
  if (url.includes("__PASTE") || !/^postgres(ql)?:\/\//.test(url)) {
    throw new Error(
      "DATABASE_URL looks like an unfilled placeholder — put your real Neon connection string in services/api/.dev.vars",
    );
  }

  const db = makeDb(url);
  const migrationFolder = path.join(SCRIPT_DIR, "../migrations");
  const migrator = new Migrator({ db, provider: new FileMigrationProvider({ fs, path, migrationFolder }) });

  const { error, results } = await migrator.migrateToLatest();
  for (const r of results ?? []) console.log(`${r.status}: ${r.migrationName}`);
  await db.destroy();
  if (error) {
    console.error(error);
    process.exit(1);
  }
}

main();
