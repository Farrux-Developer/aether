// proxy.ts  (Next.js 16 — formerly "middleware.ts")
//
// Edge session validation. Runs at the PoP, before the request reaches the origin, on
// every matched path. It:
//   1. reads the session cookie,
//   2. verifies the Ed25519 signature against the public key identified by `kid`
//      (fetched from /api/auth/jwks and cached in-isolate by kid — supports rotation),
//   3. enforces the JA3 TLS-fingerprint binding (session-hijacking guard),
//   4. injects a trusted `x-aether-sub` header for the origin, or 401s.
//
// Ed25519 verify ≈ 60–120 µs; the only network cost is the FIRST jwks fetch per cold
// isolate (then cached), so steady-state added latency is sub-millisecond.

import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { importPublicJwk, verifyToken } from "@/lib/auth/session";

// In-isolate key cache: kid -> CryptoKey. Persists across requests in a warm edge isolate.
const keyCache = new Map<string, CryptoKey>();
let jwksFetchedAt = 0;
const JWKS_TTL_MS = 300_000;

async function resolveKey(kid: string, origin: string): Promise<CryptoKey | null> {
  const cached = keyCache.get(kid);
  if (cached && Date.now() - jwksFetchedAt < JWKS_TTL_MS) return cached;

  // Cache miss or stale → refresh the whole JWKS (one fetch amortized over many requests).
  try {
    const res = await fetch(`${origin}/api/auth/jwks`, { cache: "no-store" });
    if (!res.ok) return keyCache.get(kid) ?? null;
    const jwks = (await res.json()) as { keys: Array<JsonWebKey & { kid: string }> };
    for (const jwk of jwks.keys) {
      const entry = await importPublicJwk(jwk);
      keyCache.set(jwk.kid, entry.publicKey);
    }
    jwksFetchedAt = Date.now();
  } catch {
    return keyCache.get(kid) ?? null; // network blip → fall back to any cached key
  }
  return keyCache.get(kid) ?? null;
}

export async function proxy(req: NextRequest): Promise<Response> {
  const token = req.cookies.get("aether_session")?.value;
  if (!token) {
    return NextResponse.json({ error: "no session" }, { status: 401 });
  }

  // JA3 of the incoming TLS ClientHello. On Cloudflare: req.cf.botManagement.ja3Hash.
  // Behind `next dev` there's no TLS terminator, so mirror the /verify fallback so the
  // binding check is consistent end-to-end.
  const ja3 =
    req.headers.get("x-ja3") ?? `dev-${req.headers.get("user-agent") ?? "unknown"}`;

  const origin = req.nextUrl.origin;
  const claims = await verifyToken(token, (kid) => resolveKey(kid, origin), { ja3 });
  if (!claims) {
    return NextResponse.json({ error: "invalid or hijacked session" }, { status: 401 });
  }

  // Hand a trusted identity to the origin. Strip any client-supplied spoof first.
  const headers = new Headers(req.headers);
  headers.delete("x-aether-sub");
  headers.set("x-aether-sub", claims.sub);
  return NextResponse.next({ request: { headers } });
}

// Only guard protected resources. Critically EXCLUDES /api/auth/* (login + jwks) to avoid
// a validation loop and to let unauthenticated users log in.
export const config = {
  matcher: ["/api/secure/:path*"],
};
