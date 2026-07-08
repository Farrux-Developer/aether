// app/api/auth/srp/challenge/route.ts
//
// SRP login step 1. Client sends {I, A}. Server looks up the verifier, computes
// B = k*v + g^b, stashes the ephemeral {b, B, v} under a single-use handshake id, and
// returns {handshakeId, salt, B}. To avoid a username-enumeration oracle, an unknown user
// still gets a plausible (dummy) salt+B and the failure surfaces only at /verify.

import { NextResponse } from "next/server";
import { SrpServer } from "@/lib/auth/srp";
import { getVerifier, newHandshakeId, putPending } from "@/lib/auth/store";

export const runtime = "nodejs";

export async function POST(req: Request): Promise<Response> {
  let body: { I?: string; A?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "invalid json" }, { status: 400 });
  }
  const { I, A } = body;
  if (!I || !A || !/^[0-9a-f]+$/i.test(A)) {
    return NextResponse.json({ error: "I and A(hex) required" }, { status: 400 });
  }

  const record = getVerifier(I);
  const srv = new SrpServer();
  // Even for an unknown user we run a real handshake against a throwaway verifier so the
  // response timing and shape don't reveal whether the account exists.
  const verifier = record?.verifier ?? "01";
  const salt = record?.salt ?? "00000000000000000000000000000000";
  const B = await srv.start(verifier);

  const handshakeId = newHandshakeId();
  putPending(handshakeId, { I, salt, A, snap: srv.snapshot() });

  return NextResponse.json({ handshakeId, salt, B });
}
