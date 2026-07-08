// app/api/rtc/turn/route.ts
//
// Issues short-lived, HMAC-signed TURN credentials bound to the authenticated user
// (lib/signaling/turn.ts). The client appends these to its ICE server list.
//
// Only active when TURN_HOST is configured (i.e. you actually run coturn from
// services/coturn.conf with a matching static-auth-secret == TURN_SECRET). Otherwise it
// reports { enabled: false } and the client falls back to the public OpenRelay TURN baked
// into lib/rtc/call.ts — so calls still work without any TURN deployment.

import { NextResponse } from "next/server";
import { authFromCookie } from "@/lib/auth/verify-cookie";
import { turnCredential } from "@/lib/signaling/turn";

export const runtime = "nodejs";

export async function GET(): Promise<Response> {
  const sub = await authFromCookie();
  if (!sub) return NextResponse.json({ error: "unauthenticated" }, { status: 401 });

  const host = process.env.TURN_HOST; // e.g. "turn.yourdomain.com:3478"
  if (!host) return NextResponse.json({ enabled: false });

  const secret = process.env.TURN_SECRET ?? "dev-turn-secret";
  const cred = await turnCredential(sub, secret, { host, ttlSeconds: 600 });
  return NextResponse.json({ enabled: true, ...cred });
}
