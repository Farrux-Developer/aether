// services/edge-presence.ts
//
// STANDALONE PROCESS — not part of the Next app. Run with its own deps:
//   npm i uWebSockets.js@uNetworking/uWebSockets.js#v20.51.0 kafkajs
//   node --loader tsx services/edge-presence.ts   (or compile with a services tsconfig)
//
// The edge presence node: holds ~1M WebSockets on uWebSockets.js (native C++ epoll, no
// per-connection JS object — ~2–4 GB RAM for 1M, vs socket.io dying at ~50–100k), and
// delegates all heartbeat coalescing/batching to the pure PresenceAggregator core so the
// logic is unit-tested (see /api/selftest) without a live cluster.
//
// Kernel prerequisites for 1M sockets (else you hit fd/backlog limits, not CPU):
//   fs.file-max=2000000 ; ulimit -n 2000000 ; net.core.somaxconn=65535 ; SO_REUSEPORT

import uWS from "uWebSockets.js";
import { Kafka, CompressionTypes } from "kafkajs";
import { PresenceAggregator, type PresenceDelta } from "../lib/presence/aggregator";

const REGION = process.env.REGION ?? "eu-central";
const PORT = Number(process.env.PORT ?? 9001);
const HEARTBEAT_IDLE = 30; // s; uWS auto-closes silent sockets → auto-offline

const kafka = new Kafka({ clientId: `edge-${REGION}`, brokers: (process.env.KAFKA ?? "localhost:9092").split(",") });
const producer = kafka.producer();

// The sink: one compressed Kafka produce per 3s window. LZ4 compresses presence JSON ~5–8x;
// the RTT is amortized over the whole delta batch, not paid per user.
const aggregator = new PresenceAggregator(REGION, async (batch: PresenceDelta[]) => {
  await producer.send({
    topic: "presence.delta",
    compression: CompressionTypes.LZ4,
    acks: 1, // leader-ack: presence tolerates rare loss (next heartbeat repeats); acks=all
    //          would add a cross-broker RTT for data that lives 3 s — not worth it.
    messages: batch.map((d) => ({ key: d.userId, value: JSON.stringify(d) })),
  });
}, 3000);

interface UserData {
  userId: string;
}

async function main() {
  await producer.connect();
  aggregator.start();

  uWS
    .App()
    .ws<UserData>("/presence", {
      compression: uWS.SHARED_COMPRESSOR, // shared permessage-deflate dictionary → less RAM
      maxPayloadLength: 512, // heartbeats are tiny; clamp abuse
      idleTimeout: HEARTBEAT_IDLE, // no ping in N s → close → offline next flush
      maxBackpressure: 64 * 1024, // don't buffer GBs in-kernel for a stalled client

      upgrade: (res, req, context) => {
        // In prod: validate the Ed25519 session token here (lib/auth/session verifyToken)
        // and pull userId from claims.sub. Demo: read a header.
        const userId = req.getHeader("x-aether-sub") || `anon-${Math.random().toString(36).slice(2)}`;
        res.upgrade<UserData>(
          { userId },
          req.getHeader("sec-websocket-key"),
          req.getHeader("sec-websocket-protocol"),
          req.getHeader("sec-websocket-extensions"),
          context,
        );
      },
      open: (ws) => aggregator.mark(ws.getUserData().userId, "online"),
      message: (ws) => aggregator.mark(ws.getUserData().userId, "online"), // heartbeat = refresh
      close: (ws) => aggregator.mark(ws.getUserData().userId, "offline"),
    })
    .listen(PORT, (ok) => {
      if (ok) console.log(`[edge-presence:${REGION}] listening :${PORT}`);
      else throw new Error(`failed to bind :${PORT}`);
    });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
