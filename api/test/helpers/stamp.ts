import { p256 } from "@noble/curves/p256";
import { bytesToHex } from "@noble/hashes/utils";
import { ApiKeyStamper } from "@turnkey/api-key-stamper";
import type { Kysely } from "kysely";
import type { Database } from "../../src/db";
import { SCHEME_P256 } from "../../src/stamp";
import { seedApiKey } from "./seed";

export const P256_PRIV = "0101010101010101010101010101010101010101010101010101010101010101";
export const P256_PUB = bytesToHex(p256.getPublicKey(P256_PRIV, true));

/** Seed a P-256 API key and return org/actor ids + a stamper instance. */
export async function seedStamper(db: Kysely<Database>): Promise<{
  organizationId: string;
  actorId: string;
  stamper: ApiKeyStamper;
  pubHex: string;
}> {
  const { organizationId, actorId } = await seedApiKey(db, P256_PUB, SCHEME_P256);
  const stamper = new ApiKeyStamper({ apiPublicKey: P256_PUB, apiPrivateKey: P256_PRIV });
  return { organizationId, actorId, stamper, pubHex: P256_PUB };
}

/** Produce a stamped request init for use with app.request(). */
export async function stampedRequest(
  stamper: ApiKeyStamper,
  body: Record<string, unknown>,
): Promise<{ method: string; headers: Record<string, string>; body: string }> {
  const bodyStr = JSON.stringify(body);
  const { stampHeaderValue } = await stamper.stamp(bodyStr);
  return {
    method: "POST",
    headers: { "content-type": "application/json", "X-Stamp": stampHeaderValue },
    body: bodyStr,
  };
}
