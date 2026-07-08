// app/api/auth/open/route.ts
//
// OPEN sign-in: any username logs in, no password check. Requested explicitly for the demo
// ("любой акк может зайти, любая инфа"). It still issues the real Ed25519 session cookie, so
// the rest of the stack (edge proxy, SSE, DM, calls) authenticates normally — the only thing
// dropped is the password proof. An empty username becomes a random guest.
//
// NOTE: this deliberately bypasses SRP. The zero-knowledge login remains available and
// intact at /aether and the /api/auth/srp/* routes; this is a separate, permissive door.

import { NextResponse } from "next/server";
import { keyring } from "@/lib/auth/keyring";
import { mintToken } from "@/lib/auth/session";

export const runtime = "nodejs";

const SESSION_TTL_SECONDS = 24 * 60 * 60;

// Keep printable NON-SPACE characters only. Dropping spaces (and control chars) keeps
// usernames usable as a delimiter-safe key in the DM-history pair key (lib/rtc/signal-hub).
function sanitize(raw: string): string {
  let out = "";
  for (const ch of raw) if (ch.codePointAt(0)! > 0x20) out += ch;
  return out.slice(0, 32);
}

export async function POST(req: Request): Promise<Response> {
  let body: { username?: string } = {};
  try {
    body = await req.json();
  } catch {
    /* empty body → guest */
  }

  let username = sanitize((body.username ?? "").toString());
  if (!username) username = `guest-${Math.random().toString(36).slice(2, 7)}`;

  const ja3 = req.headers.get("x-ja3") ?? `dev-${req.headers.get("user-agent") ?? "unknown"}`;
  const signer = await keyring.current();
  const token = await mintToken(signer, username, SESSION_TTL_SECONDS, ja3);

  const res = NextResponse.json({ ok: true, sub: username });
  res.cookies.set("aether_session", token, {
    httpOnly: true,
    sameSite: "strict",
    secure: true,
    path: "/",
    maxAge: SESSION_TTL_SECONDS,
  });
  return res;
}
