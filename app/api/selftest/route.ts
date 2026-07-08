// app/api/selftest/route.ts
//
// Runs the pure-CS cores end-to-end IN PROCESS and reports pass/fail. This is the
// verifiable proof that the algorithms actually work — open /api/selftest in the browser
// (or curl it) after `next dev`. Each check asserts a concrete invariant.

import { NextResponse } from "next/server";
import { register, SrpClient, SrpServer } from "@/lib/auth/srp";
import {
  generateKeyPair,
  mintToken,
  verifyToken,
} from "@/lib/auth/session";
import { PresenceStore, hlcNow, type PresenceValue } from "@/lib/presence/crdt";
import { PresenceAggregator, type PresenceDelta } from "@/lib/presence/aggregator";
import { buildRtp, parseRtp } from "@/lib/sfu/rtp";
import { DelayBasedBwe } from "@/lib/sfu/gcc";
import { SubscriptionSelector, type Layer } from "@/lib/sfu/layer-selector";
import { SignalingRelay, candidatePriority, type Bus, type SignalMessage } from "@/lib/signaling/relay";

export const runtime = "nodejs";

type Check = { name: string; pass: boolean; detail: string };

async function srpCheck(): Promise<Check[]> {
  const I = "alice@aether.app";
  const P = "correct horse battery staple";
  const cred = await register(I, P);

  // Happy path: client and server must derive the SAME session key, and both proofs verify.
  const client = new SrpClient();
  const A = await client.start();
  const server = new SrpServer();
  const B = await server.start(cred.verifier);
  const { M1, K: clientK } = await client.process(I, P, cred.salt, B);
  const srvResult = await server.verify(I, cred.salt, A, M1);
  const serverOk = srvResult !== null;
  const keysMatch =
    serverOk &&
    (await (async () => {
      // Re-derive server K by inspecting equality via M2 round-trip instead of exposing K.
      return client.verifyServer(srvResult!.M2, M1, clientK);
    })());

  // Wrong password must fail.
  const client2 = new SrpClient();
  const A2 = await client2.start();
  const server2 = new SrpServer();
  const B2 = await server2.start(cred.verifier);
  const bad = await client2.process(I, "wrong password", cred.salt, B2);
  const rejected = (await server2.verify(I, cred.salt, A2, bad.M1)) === null;

  return [
    { name: "SRP: mutual auth (M1 accepted, M2 verified, keys agree)", pass: keysMatch, detail: keysMatch ? "shared K established" : "FAILED" },
    { name: "SRP: wrong password rejected", pass: rejected, detail: rejected ? "verify() returned null" : "FAILED — accepted bad proof" },
  ];
}

async function sessionCheck(): Promise<Check[]> {
  const signer = await generateKeyPair("kid-test");
  const token = await mintToken(signer, "bob", 3600, "771,4865-4866,0-23,29-23");
  const resolve = (kid: string) => (kid === "kid-test" ? signer.publicKey : null);

  const okSameJa3 = (await verifyToken(token, resolve, { ja3: "771,4865-4866,0-23,29-23" })) !== null;
  const rejDiffJa3 = (await verifyToken(token, resolve, { ja3: "999,0000" })) === null;
  // Deterministically flip one byte of the signature (first char → a guaranteed-different
  // value) so the tamper can never coincidentally reproduce the original signature.
  const parts = token.split(".");
  const flipped = (parts[2][0] === "A" ? "B" : "A") + parts[2].slice(1);
  const tampered = `${parts[0]}.${parts[1]}.${flipped}`;
  const rejTampered = (await verifyToken(tampered, resolve, { ja3: "771,4865-4866,0-23,29-23" })) === null;
  const expired = await mintToken(signer, "bob", -1, undefined);
  const rejExpired = (await verifyToken(expired, resolve)) === null;

  return [
    { name: "Session: valid token + matching JA3 accepted", pass: okSameJa3, detail: okSameJa3 ? "ok" : "FAILED" },
    { name: "Session: mismatched JA3 rejected (hijack guard)", pass: rejDiffJa3, detail: rejDiffJa3 ? "rejected" : "FAILED" },
    { name: "Session: tampered signature rejected", pass: rejTampered, detail: rejTampered ? "rejected" : "FAILED" },
    { name: "Session: expired token rejected", pass: rejExpired, detail: rejExpired ? "rejected" : "FAILED" },
  ];
}

function crdtCheck(): Check[] {
  // Two regions merge the SAME two deltas in OPPOSITE order → must converge identically.
  const mk = (status: "online" | "offline", node: string, wall: number): PresenceValue => ({
    status,
    ts: { wall, count: 0, node },
    region: node,
  });
  const a = mk("online", "syd", 1000);
  const b = mk("offline", "fra", 2000);

  const r1 = new PresenceStore();
  r1.merge("u", a);
  r1.merge("u", b);
  const r2 = new PresenceStore();
  r2.merge("u", b);
  r2.merge("u", a);
  const converged = r1.status("u") === r2.status("u") && r1.status("u") === "offline";

  // Idempotency: applying the same delta twice changes nothing after the first win.
  const r3 = new PresenceStore();
  const first = r3.merge("u", a);
  const second = r3.merge("u", a);
  const idempotent = first === true && second === false;

  // HLC monotonicity under equal wall-clock.
  const t1 = hlcNow("n");
  const t2 = hlcNow("n", { wall: t1.wall, count: t1.count, node: "n" });
  const hlcMono = t2.wall === t1.wall ? t2.count === t1.count + 1 : t2.wall > t1.wall;

  return [
    { name: "CRDT: commutative merge converges (order-independent)", pass: converged, detail: `both → ${r1.status("u")}` },
    { name: "CRDT: merge idempotent", pass: idempotent, detail: idempotent ? "second merge no-op" : "FAILED" },
    { name: "CRDT: HLC monotonic under equal wall-clock", pass: hlcMono, detail: `count ${t1.count}→${t2.count}` },
  ];
}

async function presenceBatchCheck(): Promise<Check[]> {
  let flushes = 0;
  let lastBatch: PresenceDelta[] = [];
  const agg = new PresenceAggregator("eu", async (batch) => {
    flushes++;
    lastBatch = batch;
  }, 10_000);
  // 1000 heartbeats from the same user collapse to ONE delta.
  for (let i = 0; i < 1000; i++) agg.mark("user1", "online");
  agg.mark("user2", "away");
  const coalesced = agg.size() === 2;
  await agg.flush();
  const oneRecordPerUser = flushes === 1 && lastBatch.length === 2;
  return [
    { name: "Presence: heartbeats coalesce per user (1000→1)", pass: coalesced, detail: `dirty set size = ${2}` },
    { name: "Presence: flush emits one record per changed user", pass: oneRecordPerUser, detail: `batch size = ${lastBatch.length}` },
  ];
}

function rtpCheck(): Check[] {
  const payload = new Uint8Array([1, 2, 3, 4, 5]);
  const pkt = buildRtp({ marker: true, payloadType: 96, sequenceNumber: 40000, timestamp: 123456789, ssrc: 0xdeadbeef }, payload);
  const h = parseRtp(pkt);
  const ok =
    h.version === 2 &&
    h.marker === true &&
    h.payloadType === 96 &&
    h.sequenceNumber === 40000 &&
    h.timestamp === 123456789 &&
    h.ssrc === 0xdeadbeef &&
    h.payloadOffset === 12;
  return [{ name: "RTP: header round-trips (build → parse)", pass: ok, detail: ok ? `pt=${h.payloadType} seq=${h.sequenceNumber} ssrc=0x${h.ssrc.toString(16)}` : "FAILED" }];
}

function gccLayerCheck(): Check[] {
  // Rising delay gradient must drive the estimator into "decrease".
  const bwe = new DelayBasedBwe(2_000_000);
  let now = 0;
  for (let i = 0; i < 40; i++) {
    bwe.onDelaySample(20, (now += 30)); // sustained positive gradient = queue building
    bwe.update(0.0);
  }
  const backedOff = bwe.getState() === "decrease" && bwe.getBitrate() < 2_000_000;

  // Layer selection tracks the budget: high budget → 1080p, tiny budget → 360p.
  const layers: Layer[] = [
    { rid: "l", ssrc: 3, targetBitrate: 250_000 },
    { rid: "m", ssrc: 2, targetBitrate: 1_000_000 },
    { rid: "h", ssrc: 1, targetBitrate: 2_500_000 },
  ];
  const sel = new SubscriptionSelector(layers);
  const hi = sel.pick(4_000_000, 0).rid; // plenty → h
  const kf = sel.needsKeyframe(); // switching to a new layer requests a keyframe
  const lo = sel.pick(300_000, 100_000).rid; // starved → l (downgrade not gated)
  const selects = hi === "h" && lo === "l" && kf === 1;

  return [
    { name: "GCC: rising delay gradient → decrease state + lower bitrate", pass: backedOff, detail: `state=${bwe.getState()} rate=${Math.round(bwe.getBitrate())}` },
    { name: "GCC/SFU: layer tracks bandwidth (4Mbps→h, 300kbps→l) + keyframe on switch", pass: selects, detail: `hi=${hi} lo=${lo} kfSsrc=${kf}` },
  ];
}

async function signalingCheck(): Promise<Check[]> {
  // In-memory bus mimicking Redis Pub/Sub for the relay unit test.
  const subs = new Map<string, ((p: string) => void)[]>();
  const bus: Bus = {
    async publish(ch, p) { (subs.get(ch) ?? []).forEach((h) => h(p)); },
    async subscribe(ch, h) { (subs.get(ch) ?? subs.set(ch, []).get(ch)!).push(h); },
    async unsubscribe(ch) { subs.delete(ch); },
  };
  const relay = new SignalingRelay(bus);
  let delivered: SignalMessage | null = null;
  await relay.attach("carol", (m) => (delivered = m));
  // Dave (on a "different node", only the bus is shared) sends an offer to Carol.
  await relay.relay({ from: "dave", to: "carol", type: "offer", data: "v=0...", seq: 1 });
  const routed = delivered !== null && (delivered as SignalMessage).from === "dave";

  // ICE priority ordering: host > srflx > relay (try direct before TURN).
  const order =
    candidatePriority("host") > candidatePriority("srflx") &&
    candidatePriority("srflx") > candidatePriority("relay");

  return [
    { name: "Signaling: offer routed to peer via pub/sub bus", pass: routed, detail: routed ? "delivered to carol" : "FAILED" },
    { name: "Signaling: ICE priority host > srflx > relay", pass: order, detail: order ? "direct-first" : "FAILED" },
  ];
}

export async function GET(): Promise<Response> {
  const t0 = performance.now();
  const checks: Check[] = [
    ...(await srpCheck()),
    ...(await sessionCheck()),
    ...crdtCheck(),
    ...(await presenceBatchCheck()),
    ...rtpCheck(),
    ...gccLayerCheck(),
    ...(await signalingCheck()),
  ];
  const passed = checks.filter((c) => c.pass).length;
  return NextResponse.json({
    ok: passed === checks.length,
    passed,
    total: checks.length,
    elapsedMs: Math.round((performance.now() - t0) * 100) / 100,
    checks,
  });
}
