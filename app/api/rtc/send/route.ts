// app/api/rtc/send/route.ts
//
// Upstream channel for the messenger. The sender's identity comes from the session cookie
// (never trusted from the body), so a client cannot impersonate another `from`. Two kinds:
//   { kind: "chat", text }                      → fan out to everyone
//   { kind: "signal", to, type, data }          → route WebRTC offer/answer/ICE to one peer

import { NextResponse } from "next/server";
import { authFromCookie } from "@/lib/auth/verify-cookie";
import { hub, type RelayMessage } from "@/lib/rtc/signal-hub";

export const runtime = "nodejs";

export async function POST(req: Request): Promise<Response> {
  const from = await authFromCookie();
  if (!from) return NextResponse.json({ error: "unauthenticated" }, { status: 401 });

  let body: {
    kind?: "chat" | "dm" | "signal";
    text?: string;
    to?: string;
    type?: RelayMessage["type"];
    data?: unknown;
  };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "invalid json" }, { status: 400 });
  }

  if (body.kind === "chat") {
    const text = (body.text ?? "").toString().slice(0, 2000);
    if (text.trim()) hub.broadcastChat(from, text);
    return NextResponse.json({ ok: true });
  }

  if (body.kind === "dm") {
    const text = (body.text ?? "").toString().slice(0, 2000);
    if (!body.to) return NextResponse.json({ error: "to required" }, { status: 400 });
    if (text.trim()) hub.sendDM(from, body.to, text);
    return NextResponse.json({ ok: true });
  }

  if (body.kind === "signal") {
    if (!body.to || !body.type) {
      return NextResponse.json({ error: "to and type required" }, { status: 400 });
    }
    hub.route(from, { to: body.to, type: body.type, data: body.data });
    return NextResponse.json({ ok: true });
  }

  return NextResponse.json({ error: "unknown kind" }, { status: 400 });
}
