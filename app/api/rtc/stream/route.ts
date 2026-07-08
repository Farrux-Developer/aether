// app/api/rtc/stream/route.ts
//
// SSE downstream channel. The browser opens ONE EventSource here after login; the server
// pushes presence updates, incoming WebRTC signaling, and chat over it. Authenticated by
// the session cookie (no query-string identity to spoof). Upstream (sending) is POST
// /api/rtc/send. This SSE+POST pair is the whole signaling transport — no extra process,
// no WebSocket dependency, runs under plain `next dev`.

import { authFromCookie } from "@/lib/auth/verify-cookie";
import { hub, type HubClient } from "@/lib/rtc/signal-hub";

export const runtime = "nodejs";
export const dynamic = "force-dynamic"; // never cache/prerender a live stream

const enc = new TextEncoder();

export async function GET(req: Request): Promise<Response> {
  const userId = await authFromCookie();
  if (!userId) return new Response("unauthenticated", { status: 401 });

  let client: HubClient;
  let heartbeat: ReturnType<typeof setInterval>;

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      client = hub.add(userId, controller);
      // Comment-line heartbeat every 15s keeps intermediaries from idling the connection
      // out and lets us notice a dead socket (enqueue throws → cleaned up on abort).
      heartbeat = setInterval(() => {
        try {
          controller.enqueue(enc.encode(": ping\n\n"));
        } catch {
          /* closed */
        }
      }, 15000);

      // Client navigated away / closed tab → abort fires → tear down.
      req.signal.addEventListener("abort", () => {
        clearInterval(heartbeat);
        hub.remove(client);
        try {
          controller.close();
        } catch {
          /* already closed */
        }
      });
    },
    cancel() {
      clearInterval(heartbeat);
      if (client) hub.remove(client);
    },
  });

  return new Response(stream, {
    headers: {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no", // disable proxy buffering so events flush immediately
    },
  });
}
