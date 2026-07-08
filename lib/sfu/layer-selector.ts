// lib/sfu/layer-selector.ts
//
// Per-(publisher, subscriber) simulcast layer selection. Given a subscriber's estimated
// available bandwidth (from lib/sfu/gcc.ts) and loss, decide WHICH of the publisher's 3
// encodings (h=1080p / m=720p / l=360p) to forward. This is the "Selective" in SFU:
// packets of non-chosen layers are dropped, not forwarded. O(1) per decision / per packet.

import type { RtpHeader } from "@/lib/sfu/rtp";

export interface Layer {
  rid: string;
  ssrc: number;
  targetBitrate: number; // nominal encoder bitrate for this layer, bps
}

export class SubscriptionSelector {
  private current: Layer | null = null;
  private lastSwitch = 0;
  private pendingKeyframeFor: number | null = null; // ssrc awaiting a keyframe after switch
  private readonly layers: Layer[];

  // Anti-flap: once we pick a layer, don't upgrade for HYSTERESIS_MS. Downgrades are NOT
  // gated (see pick) — we drop quality instantly to protect the call, but climb cautiously.
  private readonly HYSTERESIS_MS = 2000;

  constructor(layers: Layer[]) {
    this.layers = [...layers].sort((a, b) => a.targetBitrate - b.targetBitrate);
  }

  // Choose a layer for the current bandwidth budget. Returns the selected layer; if the
  // selection changed to a higher layer, a keyframe must be pulled (see needsKeyframe).
  pick(availBps: number, nowMs: number): Layer {
    const budget = availBps * 0.85; // 15% headroom: BWE is an estimate, not a guarantee
    let target = this.layers[0];
    for (const l of this.layers) if (l.targetBitrate <= budget) target = l;

    const goingUp = this.current !== null && target.targetBitrate > this.current.targetBitrate;
    if (this.current && goingUp && nowMs - this.lastSwitch < this.HYSTERESIS_MS) {
      return this.current; // hold: too soon to upgrade, avoids ping-pong at the boundary
    }
    if (!this.current || target.rid !== this.current.rid) {
      this.current = target;
      this.lastSwitch = nowMs;
      // A new layer's stream does not start on a keyframe → decoder shows garbage until
      // one arrives. Flag that we must send RTCP PLI/FIR to the publisher for this SSRC.
      this.pendingKeyframeFor = target.ssrc;
    }
    return this.current;
  }

  // The forwarding predicate. Called on EVERY packet — must be O(1) and branch-cheap.
  // A correct SFU also waits for the previous layer's marker (end-of-frame) before it
  // stops forwarding it, so it never cuts a frame in half; that boundary logic lives in
  // the forwarder and consults `current`.
  shouldForward(h: RtpHeader, packetRid: string | null): boolean {
    if (!this.current) return false;
    return packetRid === this.current.rid && h.version === 2;
  }

  // Returns the SSRC that needs a keyframe (once), or null. The forwarder calls this after
  // pick() and, if non-null, emits an RTCP PLI toward the publisher.
  needsKeyframe(): number | null {
    const s = this.pendingKeyframeFor;
    this.pendingKeyframeFor = null;
    return s;
  }

  currentLayer(): Layer | null {
    return this.current;
  }
}
