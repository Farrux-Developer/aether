// app/api/secure/whoami/route.ts
//
// A protected resource. It performs NO auth itself — by the time a request reaches here,
// the edge proxy (proxy.ts) has already validated the session token at the PoP and injected
// a trusted `x-aether-sub` header. If that header is absent, the proxy let it through only
// because it wasn't matched (misconfig) — we defensively reject.

import { NextResponse } from "next/server";
import { headers } from "next/headers";

export const runtime = "nodejs";

export async function GET(): Promise<Response> {
  const sub = (await headers()).get("x-aether-sub");
  if (!sub) return NextResponse.json({ error: "unauthenticated" }, { status: 401 });
  return NextResponse.json({ sub, message: `authenticated as ${sub} (validated at edge)` });
}
