# Aether — planetary comms core

Implementation of the four subsystems (auth, presence, SFU media routing, signaling/NAT)
inside this Next.js 16 app. The **pure computer-science cores live in `lib/`** and are
transport-agnostic; the **Next app wires the parts that fit a request/response + edge
model**; the **`services/` folder holds the parts that must run as their own processes**
(1M WebSockets, SRTP over UDP, Redis Pub/Sub, coturn).

Everything in `lib/` is exercised for real by `GET /api/selftest` — **16/16 checks pass**.

## Run it

```bash
npm run dev
# http://localhost:3000/messenger    → the app: login, presence, chat, audio/video calls
# http://localhost:3000/aether       → auth internals demo (watch SRP run, no password on the wire)
# http://localhost:3000/api/selftest → runs every algorithm, returns pass/fail JSON (16/16)
```

### The messenger (Telegram-style)

`/messenger` is a working client: type a username + password and **Join** (a new username
self-registers via SRP; an existing one logs in). You then get:

- **global presence** — everyone online, live (SSE, pushed on connect/disconnect);
- **global chat** — broadcast to all;
- **audio (📞) / video (🎥) calls** — click a user in the sidebar. Media is **peer-to-peer
  WebRTC**; only SDP/ICE signaling passes through the server. Open a second browser (or
  profile), log in as a different user, and call between them.

Signaling transport is **SSE downstream (`/api/rtc/stream`) + POST upstream (`/api/rtc/send`)**,
both authenticated by the Ed25519 session cookie — so no second server process and no extra
dependency is needed to run it. To scale past one node, swap the in-memory `lib/rtc/signal-hub.ts`
for the Redis Pub/Sub `Bus` in `lib/signaling/relay.ts`; the client protocol is unchanged.
For symmetric NAT, add TURN creds (`lib/signaling/turn.ts`) to the ICE server list in
`lib/rtc/call.ts`.

The demo needs **no external infra** — session keys are generated in-process. The
`services/` need Kafka/Redis/coturn (see `.env.local.example`).

## What maps to what

| Task | Core (`lib/`, tested) | Next wiring | Standalone (`services/`) |
|------|----------------------|-------------|--------------------------|
| 1 · SRP-6a ZKP | `auth/srp.ts` | `api/auth/srp/{register,challenge,verify}` + `/aether` UI | — |
| 1 · Sessions + rotation + JA3 | `auth/session.ts`, `auth/keyring.ts` | `proxy.ts` (edge), `api/auth/jwks` | KMS/HSM + CDN KV in prod |
| 1 · WebAuthn/Passkeys | *(integration point — see below)* | add `api/auth/webauthn/*` | — |
| 2 · Presence CRDT | `presence/crdt.ts` (LWW + HLC) | `api/selftest` proves convergence | materializer per region |
| 2 · Edge aggregation | `presence/aggregator.ts` | — | `edge-presence.ts` (uWS + Kafka) |
| 3 · SFU / Simulcast / GCC | `sfu/rtp.ts`, `sfu/gcc.ts`, `sfu/layer-selector.ts` | — | `sfu-forwarder.ts` (werift + UDP) |
| 4 · Signaling / Trickle ICE / TURN | `signaling/relay.ts`, `signaling/turn.ts` | — | `signaling-node.ts` (ws + Redis), `coturn.conf` |

## Auth data flow (Task 1, fully working)

```
BROWSER (lib/auth/srp.ts runs here — Web Crypto)         SERVER (Node route handlers)
  register(I,P) → {salt, v=g^x}  ── POST /register ─────▶ store verifier (never sees P)
  SrpClient.start() → A          ── POST /challenge ────▶ B = k*v+g^b ; stash {b,B,v} (60s TTL)
  process(P,salt,B) → M1, K      ── POST /verify ───────▶ verify M1 (constant-time)
                                                          → mint Ed25519 token, bind H(JA3)
  verifyServer(M2)  ◀───────────── {M2} + Set-Cookie ────┘  (mutual auth)

  GET /api/secure/* ─▶ proxy.ts @ edge: fetch JWKS by kid (cached), Ed25519 verify (~80µs),
                        check exp + JA3 binding → inject x-aether-sub → origin
```

Password and `x` never cross the network. A DB leak yields only `v` (offline-brute bounded
by password entropy). A stolen cookie fails on a different TLS stack (JA3 mismatch).

### WebAuthn (Task 1.2) — integration point

Left as a documented hook rather than a half-baked impl: add `api/auth/webauthn/register`
and `.../login` using `@simplewebauthn/server` (`npm i @simplewebauthn/server`). Verify the
assertion, enforce `userVerification: "required"` and `signCount` monotonicity (clone
detection), then mint the **same** Ed25519 session token via `lib/auth/session.mintToken` —
so WebAuthn and SRP converge on one session format and one edge validator (`proxy.ts`).

## Honest boundaries

- **JA3 binding** ties a session to a TLS *stack* fingerprint, not a unique device — it's a
  layer atop short TTL + rotation, not an identity. For cryptographic proof-of-possession,
  add DPoP (RFC 9449); the token layer is structured to accept an extra bound claim.
- **GCC** here is a faithful trendline/overuse detector + AIMD loop, not the full
  multi-loop libwebrtc estimator (Kalman + probing). Correct in behavior, not line-for-line.
- **SFU** does simulcast layer selection (RID-based). SVC (temporal/spatial drop inside one
  SSRC) needs codec-specific payload-descriptor parsing (VP9 PD / AV1 OBU) — noted in code.
- `services/` are **reference processes**: real code against real libs (uWebSockets.js,
  kafkajs, ws, ioredis, werift, coturn), excluded from the Next TS build; they need their
  own deps + tsconfig.

## Breaking changes honored (Next 16)

- Middleware is now **`proxy.ts`** at the project root (named `proxy` export) — not
  `middleware.ts`.
- Route handlers are `app/api/**/route.ts` with per-method exports; `runtime = "nodejs"`
  pins the handlers that use the in-memory singleton stores.
- Edge runtime exposes `SubtleCrypto` incl. **Ed25519** but no Node APIs — which is exactly
  why the crypto core is built on Web Crypto + BigInt (isomorphic browser/node/edge).
