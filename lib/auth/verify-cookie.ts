// lib/auth/verify-cookie.ts
//
// Server helper: resolve the authenticated user id from the Ed25519 session cookie, reusing
// the exact verification the edge proxy performs (signature + expiry + JA3 binding). Used by
// the messenger's SSE/POST routes, which the proxy does not gate (they self-authenticate).

import { cookies, headers } from "next/headers";
import { verifyToken } from "@/lib/auth/session";
import { keyring } from "@/lib/auth/keyring";

export async function authFromCookie(): Promise<string | null> {
  const token = (await cookies()).get("aether_session")?.value;
  if (!token) return null;
  const h = await headers();
  // Mirror the ja3 fallback used at mint time (app/api/auth/srp/verify) and in proxy.ts,
  // so the binding check is consistent behind `next dev` where there's no TLS terminator.
  const ja3 = h.get("x-ja3") ?? `dev-${h.get("user-agent") ?? "unknown"}`;
  const claims = await verifyToken(
    token,
    (kid) => keyring.get(kid)?.publicKey ?? null,
    { ja3 },
  );
  return claims?.sub ?? null;
}
