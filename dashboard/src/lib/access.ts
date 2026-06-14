/**
 * access.ts — Cloudflare Access identity for the logged-in console user.
 *
 * When the deployed console route sits behind Cloudflare Access, the origin
 * exposes the authenticated identity at /cdn-cgi/access/get-identity
 * (same-origin; NOT proxied through /api). In local dev (no Access) the
 * endpoint doesn't exist — we return null and the Profile/Settings UI shows a
 * friendly "running locally, no auth" state.
 *
 * In explicit local mode (VITE_LOCAL=true) we don't even attempt the fetch:
 * there is no Cloudflare Access in front of a local API, so we degrade
 * immediately to "local, no identity".
 */
import { isLocalMode } from "./client";

export interface AccessIdentity {
  email: string;
  name?: string;
  idpName?: string;
  userUuid?: string;
}

/** Cloudflare Access logout URL for this origin. */
export const ACCESS_LOGOUT_URL = "/cdn-cgi/access/logout";

export async function fetchAccessIdentity(): Promise<AccessIdentity | null> {
  // Zero-auth localhost mode: no Access in front of the app, so skip the probe.
  if (isLocalMode) return null;
  try {
    const res = await fetch("/cdn-cgi/access/get-identity", {
      headers: { accept: "application/json" },
    });
    if (!res.ok) return null;
    const raw = (await res.json()) as Record<string, unknown>;
    const email = typeof raw.email === "string" ? raw.email : "";
    if (!email) return null;
    const idp =
      typeof raw.idp === "object" && raw.idp !== null
        ? (raw.idp as Record<string, unknown>)
        : {};
    return {
      email,
      name: typeof raw.name === "string" ? raw.name : undefined,
      idpName: typeof idp.type === "string" ? idp.type : undefined,
      userUuid: typeof raw.user_uuid === "string" ? raw.user_uuid : undefined,
    };
  } catch {
    return null;
  }
}
