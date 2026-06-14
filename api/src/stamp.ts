import { p256 } from "@noble/curves/p256";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { hexToBytes } from "@noble/hashes/utils";

export const STAMP_HEADER_NAME = "X-Stamp";
export const SCHEME_P256 = "SIGNATURE_SCHEME_TK_API_P256";
export const SCHEME_ED25519 = "SIGNATURE_SCHEME_TK_API_ED25519";

export interface ApiStamp {
  publicKey: string;
  scheme: string;
  signature: string;
}

/** Decode the base64url X-Stamp header value (Buffer is available via nodejs_compat). */
export function decodeStamp(headerValue: string): ApiStamp {
  const json = Buffer.from(headerValue, "base64url").toString("utf8");
  const parsed = JSON.parse(json) as Partial<ApiStamp>;
  if (!parsed.publicKey || !parsed.scheme || !parsed.signature) {
    throw new Error("malformed stamp: missing publicKey/scheme/signature");
  }
  return parsed as ApiStamp;
}

/** Verify the stamp signs `body`. P-256: DER ECDSA over SHA-256(body). Ed25519: over body bytes. */
export function verifyStamp(stamp: ApiStamp, body: string): boolean {
  const msg = new TextEncoder().encode(body);
  try {
    if (stamp.scheme === SCHEME_P256) {
      return p256.verify(hexToBytes(stamp.signature), sha256(msg), hexToBytes(stamp.publicKey));
    }
    if (stamp.scheme === SCHEME_ED25519) {
      return ed25519.verify(hexToBytes(stamp.signature), msg, hexToBytes(stamp.publicKey));
    }
    return false;
  } catch {
    return false;
  }
}
