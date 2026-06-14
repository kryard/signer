import type { Kysely } from "kysely";
import { sql } from "kysely";
import type { Database } from "./db";

/** Full ciphertext row needed by the signer to decrypt and sign.
 *  Callers MUST NOT expose these fields to external API consumers. */
export interface PrivateKeyCiphertextRow {
  id: string;
  publicKey: string;
  curve: string; // CURVE_SECP256K1 | CURVE_ED25519 — selects the signing algorithm
  encryptedPrivateKey: string; // base64
  encryptedDataKey: string;    // base64
  kmsProvider: string;
  kmsKeyId: string;
  encryptionContext: Record<string, string>;
}

/** Public metadata shape returned by query endpoints.
 *  NEVER includes ciphertext (encryptedPrivateKey / encryptedDataKey) or
 *  any plaintext key material. */
export interface PrivateKeyPublicMetadata {
  privateKeyId: string;
  publicKey: string;
  curve: string;
  addresses: unknown; // jsonb — array of address strings
  createdAt: Date;
}

/** Return a single private key's public metadata, scoped to the caller's org. */
export async function getPrivateKey(
  db: Kysely<Database>,
  organizationId: string,
  privateKeyId: string,
): Promise<PrivateKeyPublicMetadata | null> {
  const row = await db
    .selectFrom("private_keys")
    .select(["id", "public_key", "curve", "addresses", "created_at"])
    .where("organization_id", "=", organizationId)
    .where("id", "=", privateKeyId)
    .where("deleted_at", "is", null)
    .executeTakeFirst();

  if (!row) return null;
  return {
    privateKeyId: row.id,
    publicKey: row.public_key,
    curve: row.curve,
    addresses: row.addresses,
    createdAt: row.created_at,
  };
}

/** Return all private keys' public metadata for the org, newest first. */
export async function listPrivateKeys(
  db: Kysely<Database>,
  organizationId: string,
  limit = 50,
): Promise<PrivateKeyPublicMetadata[]> {
  const rows = await db
    .selectFrom("private_keys")
    .select(["id", "public_key", "curve", "addresses", "created_at"])
    .where("organization_id", "=", organizationId)
    .where("deleted_at", "is", null)
    .orderBy("created_at", "desc")
    .limit(limit)
    .execute();

  return rows.map((row) => ({
    privateKeyId: row.id,
    publicKey: row.public_key,
    curve: row.curve,
    addresses: row.addresses,
    createdAt: row.created_at,
  }));
}

/** EIP-55 / ERC-55 Ethereum address pattern: 0x + 40 hex characters (case-insensitive). */
const ETH_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

/**
 * Resolve a `signWith` value (Ethereum address OR private-key UUID) to the full
 * ciphertext row needed by the signer. Returns null if not found.
 *
 * - If `signWith` matches the Ethereum address pattern, look up by address
 *   (the `addresses` jsonb column stores an array of address strings).
 * - Otherwise treat `signWith` as a private-key id.
 *
 * Always scoped to `organizationId` and non-deleted rows.
 */
export async function resolveSignWith(
  db: Kysely<Database>,
  organizationId: string,
  signWith: string,
): Promise<PrivateKeyCiphertextRow | null> {
  let query = db
    .selectFrom("private_keys")
    .select([
      "id",
      "public_key",
      "curve",
      "encrypted_private_key",
      "encrypted_data_key",
      "kms_provider",
      "kms_key_id",
      "encryption_context",
    ])
    .where("organization_id", "=", organizationId)
    .where("deleted_at", "is", null);

  if (ETH_ADDRESS_RE.test(signWith)) {
    // Address lookup: the `addresses` jsonb column stores an array of strings.
    // Use jsonb_path_exists with a like_regex for case-insensitive address match,
    // since go-ethereum stores EIP-55 checksummed addresses but callers may pass
    // lowercase. The jsonpath `like_regex` supports the `flag "i"` flag in PG 12+.
    query = query.where(
      sql<boolean>`jsonb_path_exists(addresses, ${sql.val(`$[*] ? (@ like_regex "^${signWith}$" flag "i")`)}::jsonpath)`,
    );
  } else {
    // Assume private-key UUID.
    query = query.where("id", "=", signWith);
  }

  const row = await query.executeTakeFirst();
  if (!row) return null;

  return {
    id: row.id,
    publicKey: row.public_key,
    curve: row.curve,
    encryptedPrivateKey: row.encrypted_private_key,
    encryptedDataKey: row.encrypted_data_key,
    kmsProvider: row.kms_provider,
    kmsKeyId: row.kms_key_id,
    encryptionContext: row.encryption_context as Record<string, string>,
  };
}
