// services/signaling-node.ts
//
// STANDALONE PROCESS — global signaling node. Not part of Next (needs a long-lived WS
// server + Redis subscriber connection). Run with:
//   npm i ws ioredis ; node --loader tsx services/signaling-node.ts
//
// Terminates client WebSockets, relays SDP/ICE via the pure SignalingRelay core over a
// Redis Pub/Sub Bus (geo-replicated), and mints ephemeral TURN credentials. A peer on
// another continent is reached because we SUBSCRIBE to its channel; Redis replication
// carries the PUBLISH across regions.

import { WebSocketServer, WebSocket } from "ws";
import Redis from "ioredis";
import { SignalingRelay, type Bus, type SignalMessage } from "../lib/signaling/relay";
import { turnCredential } from "../lib/signaling/turn";

const PORT = Number(process.env.PORT ?? 8080);
const TURN_SECRET = process.env.TURN_SECRET ?? "dev-turn-secret";

// Redis requires a dedicated connection for subscriber mode; a second one publishes.
const redisSub = new Redis(process.env.REDIS_URL ?? "redis://localhost:6379");
const redisPub = new Redis(process.env.REDIS_URL ?? "redis://localhost:6379");
const handlers = new Map<string, (payload: string) => void>();
redisSub.on("message", (channel, payload) => handlers.get(channel)?.(payload));

const bus: Bus = {
  async publish(channel, payload) {
    await redisPub.publish(channel, payload);
  },
  async subscribe(channel, handler) {
    handlers.set(channel, handler);
    await redisSub.subscribe(channel);
  },
  async unsubscribe(channel) {
    handlers.delete(channel);
    await redisSub.unsubscribe(channel);
  },
};

const relay = new SignalingRelay(bus);
const wss = new WebSocketServer({ port: PORT });

wss.on("connection", async (ws: WebSocket, req) => {
  // In prod: verify the Ed25519 session token (from a query param or the upgrade header)
  // with lib/auth/session verifyToken before trusting `userId`.
  const userId = new URL(req.url ?? "/", "http://x").searchParams.get("uid") ?? "anon";

  await relay.attach(userId, (msg: SignalMessage) => {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify({ kind: "signal", msg }));
  });

  // Hand the client fresh, short-TTL TURN credentials for symmetric-NAT fallback.
  ws.send(JSON.stringify({ kind: "turn", cred: await turnCredential(userId, TURN_SECRET) }));

  ws.on("message", async (raw) => {
    try {
      const m = JSON.parse(raw.toString()) as SignalMessage;
      await relay.relay({ ...m, from: userId }); // trust server-side identity, not client claim
    } catch {
      /* drop malformed frames */
    }
  });

  ws.on("close", () => void relay.detach(userId));
});

console.log(`[signaling] ws://0.0.0.0:${PORT} — Redis Pub/Sub relay + ephemeral TURN`);
