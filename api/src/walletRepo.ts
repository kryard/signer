import type { Kysely } from "kysely";
import type { Database } from "./db";

/** Public metadata shape for a wallet — no ciphertext. */
export interface WalletPublicMetadata {
  walletId: string;
  walletName: string;
  createdAt: Date;
}

/** Public metadata shape for a wallet account — no ciphertext. */
export interface WalletAccountPublicMetadata {
  walletAccountId: string;
  walletId: string;
  curve: string;
  addressFormat: string;
  address: string;
  path: string | null;
}

/** Return a single wallet's public metadata, scoped to the caller's org. */
export async function getWallet(
  db: Kysely<Database>,
  organizationId: string,
  walletId: string,
): Promise<WalletPublicMetadata | null> {
  const row = await db
    .selectFrom("wallets")
    .select(["id", "name", "created_at"])
    .where("organization_id", "=", organizationId)
    .where("id", "=", walletId)
    .where("deleted_at", "is", null)
    .executeTakeFirst();

  if (!row) return null;
  return {
    walletId: row.id,
    walletName: row.name,
    createdAt: row.created_at,
  };
}

/** Return all wallets' public metadata for the org, newest first. */
export async function listWallets(
  db: Kysely<Database>,
  organizationId: string,
  limit = 50,
): Promise<WalletPublicMetadata[]> {
  const rows = await db
    .selectFrom("wallets")
    .select(["id", "name", "created_at"])
    .where("organization_id", "=", organizationId)
    .where("deleted_at", "is", null)
    .orderBy("created_at", "desc")
    .limit(limit)
    .execute();

  return rows.map((row) => ({
    walletId: row.id,
    walletName: row.name,
    createdAt: row.created_at,
  }));
}

/** Return a single wallet account's public metadata, scoped to the caller's org. */
export async function getWalletAccount(
  db: Kysely<Database>,
  organizationId: string,
  walletAccountId: string,
): Promise<WalletAccountPublicMetadata | null> {
  const row = await db
    .selectFrom("wallet_accounts")
    .select(["id", "wallet_id", "curve", "address_format", "address", "path"])
    .where("organization_id", "=", organizationId)
    .where("id", "=", walletAccountId)
    .executeTakeFirst();

  if (!row) return null;
  return {
    walletAccountId: row.id,
    walletId: row.wallet_id,
    curve: row.curve,
    addressFormat: row.address_format,
    address: row.address,
    path: row.path ?? null,
  };
}

/** Return all wallet accounts for the given wallet, scoped to the caller's org. */
export async function listWalletAccounts(
  db: Kysely<Database>,
  organizationId: string,
  walletId: string,
  limit = 50,
): Promise<WalletAccountPublicMetadata[]> {
  const rows = await db
    .selectFrom("wallet_accounts")
    .select(["id", "wallet_id", "curve", "address_format", "address", "path"])
    .where("organization_id", "=", organizationId)
    .where("wallet_id", "=", walletId)
    .orderBy("created_at", "desc")
    .limit(limit)
    .execute();

  return rows.map((row) => ({
    walletAccountId: row.id,
    walletId: row.wallet_id,
    curve: row.curve,
    addressFormat: row.address_format,
    address: row.address,
    path: row.path ?? null,
  }));
}
