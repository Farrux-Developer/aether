// app/api/auth/srp/register/route.ts
//
// Registration endpoint. The client computes {salt, verifier} locally (lib/auth/srp.ts
// register()) so the password never touches the network. The server only persists the
// verifier. We validate shape and store it.

import { NextResponse } from "next/server";
import type { Verifier } from "@/lib/auth/srp";
import { putVerifier } from "@/lib/auth/store";

// Force the Node runtime: this touches the in-memory verifier store (a module singleton),
// which the Edge runtime would not share with the rest of the API.
export const runtime = "nodejs";

export async function POST(req: Request): Promise<Response> {
  let body: Partial<Verifier>;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "invalid json" }, { status: 400 });
  }
  const { I, salt, verifier } = body;
  if (!I || !salt || !verifier || !/^[0-9a-f]+$/i.test(salt) || !/^[0-9a-f]+$/i.test(verifier)) {
    return NextResponse.json({ error: "I, salt(hex), verifier(hex) required" }, { status: 400 });
  }
  putVerifier({ I, salt, verifier });
  return NextResponse.json({ ok: true, I });
}
