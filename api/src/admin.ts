/**
 * admin.ts — DEV-ONLY bootstrap endpoints for the dev dashboard.
 *
 * These create the rows that normally come from out-of-band seeding
 * (organizations, actors, api_keys, private_keys, policy_*) so a developer can
 * stand up a working org → key → policy → real sign_transaction flow from the
 * browser. They bypass X-Stamp auth on purpose (they are the bootstrap), so they
 * MUST stay gated behind `devAdminEnabled` (default false) and an optional
 * shared token. Never enable on a publicly reachable deployment.
 */

import type { Kysely } from "kysely";
import type { Database } from "./db";
import { TurnkeyError } from "./errors";
import { createKey, type SignerFetch } from "./signerClient";
import { plainFetch } from "./signerClient";

const SCHEME_P256 = "SIGNATURE_SCHEME_TK_API_P256";
const SIGN_TX_ACTIVITY = "ACTIVITY_TYPE_SIGN_TRANSACTION_V2";

function uuid(): string {
  // crypto.randomUUID is available in the Workers runtime and Node 19+.
  return crypto.randomUUID();
}

// ---------------------------------------------------------------------------
// 1. Organization (+ a default actor)
// ---------------------------------------------------------------------------

export async function createDevOrg(
  db: Kysely<Database>,
  name: string,
): Promise<{ organizationId: string; actorId: string; actorName: string }> {
  const orgName = name?.trim() || "dev-org";
  const org = await db
    .insertInto("organizations")
    .values({ name: orgName })
    .returning("id")
    .executeTakeFirstOrThrow();

  const actorName = "dev-actor";
  const actor = await db
    .insertInto("actors")
    .values({ organization_id: org.id, name: actorName })
    .returning("id")
    .executeTakeFirstOrThrow();

  return { organizationId: org.id, actorId: actor.id, actorName };
}

// ---------------------------------------------------------------------------
// 2. API key (register the dashboard's P-256 stamp public key)
// ---------------------------------------------------------------------------

export async function registerApiKey(
  db: Kysely<Database>,
  input: { organizationId: string; actorId: string; publicKey: string; scheme?: string; name?: string },
): Promise<{ apiKeyId: string }> {
  const { organizationId, actorId, publicKey } = input;
  if (!organizationId || !actorId || !publicKey) {
    throw new TurnkeyError(400, "organizationId, actorId, and publicKey are required");
  }
  // Compressed secp/p256 public keys are 33 bytes = 66 hex chars. Be lenient
  // (accept any non-empty hex) but normalize to lowercase to match the stamp.
  const pk = publicKey.toLowerCase();
  const row = await db
    .insertInto("api_keys")
    .values({
      organization_id: organizationId,
      actor_id: actorId,
      public_key: pk,
      scheme: input.scheme || SCHEME_P256,
      name: input.name || "dev-dashboard-key",
    })
    .returning("id")
    .executeTakeFirstOrThrow();
  return { apiKeyId: row.id };
}

// ---------------------------------------------------------------------------
// 3. Wallet (create the key inside the signer; store ciphertext only)
// ---------------------------------------------------------------------------

export async function createDevWallet(
  db: Kysely<Database>,
  signerBaseUrl: string,
  input: { organizationId: string; name?: string; environment?: string },
  signerFetch: SignerFetch = plainFetch,
): Promise<{ privateKeyId: string; address: string; publicKey: string }> {
  const { organizationId } = input;
  if (!organizationId) throw new TurnkeyError(400, "organizationId is required");

  const privateKeyId = uuid();
  const resp = await createKey(
    signerBaseUrl,
    { organizationId, privateKeyId, environment: input.environment || "dev", name: input.name || "dev-wallet" },
    signerFetch,
  );
  const address = resp.addresses[0] ?? "";

  await db
    .insertInto("private_keys")
    .values({
      id: privateKeyId,
      organization_id: organizationId,
      name: input.name || "dev-wallet",
      curve: resp.curve,
      public_key: resp.publicKey,
      addresses: JSON.stringify(resp.addresses),
      encrypted_private_key: resp.encryptedPrivateKey,
      encrypted_data_key: resp.encryptedDataKey,
      kms_provider: resp.kmsProvider,
      kms_key_id: resp.kmsKeyId,
      encryption_context: JSON.stringify(resp.encryptionContext),
    })
    .execute();

  return { privateKeyId, address, publicKey: resp.publicKey };
}

// ---------------------------------------------------------------------------
// 4. Policy (binding + per-chain rule + destination allowlist)
// ---------------------------------------------------------------------------

export interface SeedPolicyInput {
  organizationId: string;
  actorId: string;
  privateKeyId: string;
  chainId: string; // decimal string, e.g. "1"
  methodSelector: string; // "0x7fea8778"
  destinationAddress: string; // 0x… (allowlisted "to")
  maxNativeValueWei?: string; // default "0"
  allowedActivityType?: string;
}

export async function seedPolicy(db: Kysely<Database>, input: SeedPolicyInput): Promise<{ ok: true }> {
  const { organizationId, actorId, privateKeyId, chainId, methodSelector, destinationAddress } = input;
  if (!organizationId || !actorId || !privateKeyId || !chainId || !methodSelector || !destinationAddress) {
    throw new TurnkeyError(
      400,
      "organizationId, actorId, privateKeyId, chainId, methodSelector, destinationAddress are required",
    );
  }
  const activityType = input.allowedActivityType || SIGN_TX_ACTIVITY;

  await db
    .insertInto("policy_bindings")
    .values({
      organization_id: organizationId,
      actor_id: actorId,
      resource_type: "private_key",
      resource_id: privateKeyId,
      allowed_activity_type: activityType,
    })
    .execute();

  await db
    .insertInto("wallet_policy_rules")
    .values({
      organization_id: organizationId,
      private_key_id: privateKeyId,
      chain_id: chainId,
      allow_raw_payload_signing: false,
      max_native_value_wei: input.maxNativeValueWei || "0",
      method_selector_allowlist: JSON.stringify([methodSelector.toLowerCase()]),
    })
    .execute();

  await db
    .insertInto("wallet_destination_allowlist")
    .values({
      organization_id: organizationId,
      private_key_id: privateKeyId,
      chain_id: chainId,
      address: destinationAddress,
    })
    .execute();

  return { ok: true };
}
