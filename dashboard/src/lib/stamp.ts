/**
 * stamp.ts — browser-side P-256 identity + Turnkey-style X-Stamp construction.
 *
 * Wire format (must match services/api/src/stamp.ts and the compat harness):
 *   X-Stamp = base64url(JSON({ publicKey, scheme, signature }))
 *   signature = DER-encoded ECDSA-P256 over SHA-256(rawBodyString), hex
 *   publicKey = compressed P-256 public key, hex
 *
 * The signature covers the EXACT raw body string sent on the wire, so callers
 * must POST the same string they stamped (never re-serialize).
 */
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

export const STAMP_HEADER_NAME = "X-Stamp";
export const SCHEME_P256 = "SIGNATURE_SCHEME_TK_API_P256";

export interface StampIdentity {
  /** P-256 private key, hex. Browser-held; never sent to the server. */
  privateKeyHex: string;
  /** Compressed P-256 public key, hex (registered as the API key). */
  publicKeyHex: string;
}

/** Generate a fresh P-256 keypair (compressed public key). */
export function generateIdentity(): StampIdentity {
  const priv = p256.utils.randomPrivateKey();
  return {
    privateKeyHex: bytesToHex(priv),
    publicKeyHex: bytesToHex(p256.getPublicKey(priv, true)),
  };
}

const encoder = new TextEncoder();

function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Build the X-Stamp header value for an exact raw request-body string. */
export function buildStamp(identity: StampIdentity, rawBody: string): string {
  const digest = sha256(encoder.encode(rawBody));
  const signature = p256.sign(digest, hexToBytes(identity.privateKeyHex)).toDERHex();
  const envelope = JSON.stringify({
    publicKey: identity.publicKeyHex,
    scheme: SCHEME_P256,
    signature,
  });
  return toBase64Url(encoder.encode(envelope));
}

/** Verify a stamp against a body (test/debug mirror of the server side). */
export function verifyStamp(headerValue: string, rawBody: string): boolean {
  try {
    const pad = "=".repeat((4 - (headerValue.length % 4)) % 4);
    const json = atob(headerValue.replace(/-/g, "+").replace(/_/g, "/") + pad);
    const parsed = JSON.parse(json) as { publicKey?: string; scheme?: string; signature?: string };
    if (!parsed.publicKey || !parsed.signature || parsed.scheme !== SCHEME_P256) return false;
    const digest = sha256(encoder.encode(rawBody));
    return p256.verify(hexToBytes(parsed.signature), digest, hexToBytes(parsed.publicKey));
  } catch {
    return false;
  }
}

// ── localStorage persistence (the console's signing identity) ────────────────

const IDENTITY_STORAGE_KEY = "kryard.console.identity";

export function loadIdentity(): StampIdentity | null {
  try {
    const raw = localStorage.getItem(IDENTITY_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<StampIdentity>;
    if (!parsed.privateKeyHex || !parsed.publicKeyHex) return null;
    return { privateKeyHex: parsed.privateKeyHex, publicKeyHex: parsed.publicKeyHex };
  } catch {
    return null;
  }
}

export function saveIdentity(identity: StampIdentity): void {
  localStorage.setItem(IDENTITY_STORAGE_KEY, JSON.stringify(identity));
}

export function clearIdentity(): void {
  localStorage.removeItem(IDENTITY_STORAGE_KEY);
}
