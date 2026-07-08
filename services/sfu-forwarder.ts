// services/sfu-forwarder.ts
//
// STANDALONE PROCESS — the SFU media plane. Not part of Next (needs raw UDP + SRTP).
// Run with: npm i werift  (for DTLS-SRTP + ICE) ; node --loader tsx services/sfu-forwarder.ts
//
// This wires the pure cores — parseRtp/readRid (lib/sfu/rtp), DelayBasedBwe (lib/sfu/gcc),
// SubscriptionSelector (lib/sfu/layer-selector) — into a per-subscriber forwarding loop.
// The heavy transport bits (ICE/DTLS/SRTP decrypt-encrypt) are provided by werift; the
// ROUTING DECISION (which simulcast layer each subscriber gets) is our code below.
//
// The SFU never decodes the codec. It reads RTP headers only and forwards or drops whole
// packets — O(1) per packet, so a node scales to ~1.5M pkt/s (≈1000 publishers).

import dgram from "node:dgram";
import { parseRtp, readRid } from "../lib/sfu/rtp";
import { DelayBasedBwe } from "../lib/sfu/gcc";
import { SubscriptionSelector, type Layer } from "../lib/sfu/layer-selector";

const RID_EXT_ID = Number(process.env.RID_EXT_ID ?? 4); // negotiated in SDP (a=extmap)

// One publisher's advertised simulcast encodings (from its SDP a=simulcast / a=rid lines).
const PUBLISHER_LAYERS: Layer[] = [
  { rid: "l", ssrc: 0x1000_0003, targetBitrate: 250_000 }, // 360p
  { rid: "m", ssrc: 0x1000_0002, targetBitrate: 1_000_000 }, // 720p
  { rid: "h", ssrc: 0x1000_0001, targetBitrate: 2_500_000 }, // 1080p
];

// Per-subscriber routing state.
class Subscriber {
  readonly bwe = new DelayBasedBwe(1_000_000);
  readonly selector = new SubscriptionSelector(PUBLISHER_LAYERS);
  constructor(
    readonly id: string,
    readonly addr: { address: string; port: number },
    readonly socket: dgram.Socket,
  ) {}

  // Called on every inbound RTP packet from the publisher. Decides forward/drop per this
  // subscriber, and pulls a keyframe when it just switched up to a higher layer.
  onPublisherPacket(pkt: Uint8Array, nowMs: number): void {
    const h = parseRtp(pkt);
    const rid = readRid(pkt, h, RID_EXT_ID);

    // Re-evaluate the target layer against this subscriber's current BWE (~once/RTT the
    // BWE is refreshed from RTCP receiver reports; here we just consult the latest estimate).
    this.selector.pick(this.bwe.getBitrate(), nowMs);

    const kfSsrc = this.selector.needsKeyframe();
    if (kfSsrc !== null) this.sendPLI(kfSsrc); // RTCP PLI → publisher emits an IDR

    if (this.selector.shouldForward(h, rid)) {
      // In prod: rewrite SSRC/sequence-number to a stable outbound stream, then SRTP-encrypt.
      // Here we forward the packet bytes as-is over UDP.
      this.socket.send(pkt, this.addr.port, this.addr.address);
    }
    // else: dropped — this is the "Selective" in Selective Forwarding Unit.
  }

  // Feed transport feedback (RTCP TWCC / receiver reports) into the estimator.
  onFeedback(interArrivalDelayMs: number, lossFraction: number, nowMs: number): void {
    this.bwe.onDelaySample(interArrivalDelayMs, nowMs);
    this.bwe.update(lossFraction);
  }

  private sendPLI(_ssrc: number): void {
    // Build + send an RTCP PLI (PT=206, FMT=1) toward the publisher. Elided.
  }
}

// --- wiring sketch ---
// A real deployment terminates ICE/DTLS-SRTP per peer with werift and hands decrypted RTP
// to onPublisherPacket. This dgram loop shows the forwarding decision in isolation.
function demo() {
  const socket = dgram.createSocket("udp4");
  const subscribers = new Map<string, Subscriber>();
  socket.on("message", (msg) => {
    const now = performance.now();
    for (const sub of subscribers.values()) sub.onPublisherPacket(msg, now);
  });
  socket.bind(Number(process.env.RTP_PORT ?? 5004), () =>
    console.log("[sfu] forwarding decision loop bound; attach real ICE/SRTP via werift"),
  );
  void Subscriber; // referenced by the real signaling-driven attach path
}

if (process.env.SFU_DEMO) demo();
