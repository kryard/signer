import { PostgreSqlContainer, type StartedPostgreSqlContainer } from "@testcontainers/postgresql";
import { promises as fs } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { Migrator, FileMigrationProvider, type Kysely } from "kysely";
import { makeDb, type Database } from "../../src/db";

export interface TestDb {
  db: Kysely<Database>;
  stop: () => Promise<void>;
}

/** Start a fresh Postgres container, run migrations, return a Kysely instance. */
export async function startTestDb(): Promise<TestDb> {
  const container: StartedPostgreSqlContainer = await new PostgreSqlContainer("postgres:16-alpine").start();
  const db = makeDb(container.getConnectionUri());
  const migrationFolder = path.join(path.dirname(fileURLToPath(import.meta.url)), "../../migrations");
  const migrator = new Migrator({ db, provider: new FileMigrationProvider({ fs, path, migrationFolder }) });
  const { error } = await migrator.migrateToLatest();
  if (error) throw error;
  return {
    db,
    stop: async () => {
      await db.destroy();
      await container.stop();
    },
  };
}
