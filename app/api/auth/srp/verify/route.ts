// app/api/auth/srp/verify/route.ts
//
// SRP login step 2. Client sends {handshakeId, M1}. Server rehydrates the ephemeral state,
// verifies M1 (constant-time), and on success mints a short-lived Ed25519 session token
// bound to the client's JA3 TLS fingerprint, returned as an HttpOnly cookie plus M2 so the
// client can verify the server (mutual auth).

import { NextResponse } from "next/server";
import { SrpServer } from "@/lib/auth/srp";
import { takePending } from "@/lib/auth/store";
import { keyring } from "@/lib/auth/keyring";
import { mintToken } from "@/lib/auth/session";

export const runtime = "nodejs";

const SESSION_TTL_SECONDS = 24 * 60 * 60;

export async function POST(req: Request): Promise<Response> {
  let body: { handshakeId?: string; M1?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "invalid json" }, { status: 400 });
  }
  const { handshakeId, M1 } = body;
  if (!handshakeId || !M1) {
    return NextResponse.json({ error: "handshakeId and M1 required" }, { status: 400 });
  }

  const pending = takePending(handshakeId); // single-use + TTL-checked
  if (!pending) {
    return NextResponse.json({ error: "handshake expired or unknown" }, { status: 401 });
  }

  const srv = SrpServer.restore(pending.snap);
  const result = await srv.verify(pending.I, pending.salt, pending.A, M1);
  if (!result) {
    // Wrong password (or unknown user, which reached here with a dummy verifier): identical
    // 401, no distinguishing detail.
    return NextResponse.json({ error: "authentication failed" }, { status: 401 });
  }

  // In prod the JA3 comes from the CDN (e.g. Cloudflare cf.botManagement.ja3Hash). Behind
  // `next dev` there is no TLS fingerprint, so we fall back to a UA-derived pseudo value —
  // the binding mechanism is exercised end-to-end even without a real TLS terminator.
  const ja3 = req.headers.get("x-ja3") ?? `dev-${req.headers.get("user-agent") ?? "unknown"}`;

  const signer = await keyring.current();
  const token = await mintToken(signer, pending.I, SESSION_TTL_SECONDS, ja3);

  const res = NextResponse.json({ ok: true, M2: result.M2, sub: pending.I });
  res.cookies.set("aether_session", token, {
    httpOnly: true,
    sameSite: "strict",
    secure: true,
    path: "/",
    maxAge: SESSION_TTL_SECONDS,
  });
  return res;
}
