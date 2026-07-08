// app/api/auth/jwks/route.ts
//
// Public JWKS endpoint. The edge proxy (proxy.ts) fetches this, caches keys by `kid`, and
// verifies session tokens WITHOUT contacting the origin per-request. Only public keys are
// exposed here; private keys never leave the signing side (lib/auth/keyring.ts).
//
// This is the join point that makes key rotation transparent: rotate the keyring, and the
// edge picks up the new kid on its next cache refresh while old-kid tokens still validate.

import { NextResponse } from "next/server";
import { keyring } from "@/lib/auth/keyring";

export const runtime = "nodejs";

export async function GET(): Promise<Response> {
  const jwks = await keyring.jwks();
  const res = NextResponse.json(jwks);
  // Short cache: bounds how long a rotated-out key lingers at the edge.
  res.headers.set("cache-control", "public, max-age=300");
  return res;
}
