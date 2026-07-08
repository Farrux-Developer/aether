// lib/sfu/gcc.ts
//
// GCC — Google Congestion Control, delay-based bandwidth estimation (the "trendline"
// variant used in modern libwebrtc). Estimates the send rate a subscriber's path can
// sustain, per RTT.
//
// Why delay-based, not loss-based: a pure loss-based controller reacts only AFTER the
// bottleneck queue overflows and drops packets — too late, and it oscillates. GCC watches
// the ONE-WAY DELAY GRADIENT: as a bottleneck buffer fills, inter-packet arrival spacing
// grows before any loss occurs. Detecting that rising trend lets us back off tens of ms
// earlier, keeping latency low (critical for the <50 ms ping target).
//
// Signal:   d(i) = (arrival_i - arrival_{i-1}) - (send_i - send_{i-1})
// A persistently positive, growing d => queue building => overuse => decrease.
// Threshold gamma is ADAPTIVE so a merely jittery (not congested) path isn't throttled.

export type BweState = "hold" | "increase" | "decrease";

export class DelayBasedBwe {
  private trend = 0; // smoothed delay-gradient estimate
  private threshold = 12.5; // gamma, ms — adaptive overuse threshold
  private state: BweState = "hold";
  private bitrate: number;
  private lastAdapt = 0;

  // Threshold adaptation rates from libwebrtc: move gamma slowly toward |trend|,
  // faster up (kUp) than down (kDown), so brief spikes don't permanently desensitize.
  private readonly kUp = 0.0087;
  private readonly kDown = 0.039;

  constructor(startBitrate = 300_000) {
    // Conservative TCP-friendly start; ramps multiplicatively once the path proves stable.
    this.bitrate = startBitrate;
  }

  // Feed one inter-arrival delay gradient sample (ms). O(1).
  onDelaySample(interArrivalDelayMs: number, nowMs: number): void {
    // Exponential smoothing suppresses single-packet jitter before the detector sees it.
    this.trend = 0.9 * this.trend + 0.1 * interArrivalDelayMs;

    if (this.trend > this.threshold) this.state = "decrease"; // queue growing → overuse
    else if (this.trend < -this.threshold) this.state = "increase"; // draining → headroom
    else this.state = "hold";

    // Adapt gamma toward the observed |trend| (Kalman-like, rate depends on regime).
    const dt = this.lastAdapt === 0 ? 0 : Math.min(nowMs - this.lastAdapt, 100);
    const k = Math.abs(this.trend) < this.threshold ? this.kDown : this.kUp;
    this.threshold += k * (Math.abs(this.trend) - this.threshold) * dt;
    this.threshold = Math.max(6, Math.min(600, this.threshold));
    this.lastAdapt = nowMs;
  }

  // Recompute the target bitrate, ~once per RTT. Combines the delay-based FSM with a
  // loss-based safety floor (the second GCC loop): heavy loss cuts rate even if delay is
  // nominally fine (handles sudden bursty loss the delay filter would lag on).
  update(lossFraction: number): number {
    switch (this.state) {
      case "increase":
        this.bitrate *= 1.08; // multiplicative increase, ~8%/RTT (AIMD-ish)
        break;
      case "decrease":
        this.bitrate *= 0.85; // multiplicative decrease toward measured throughput, beta=0.85
        break;
    }
    if (lossFraction > 0.1) this.bitrate *= 1 - 0.5 * lossFraction; // >10% loss → cut hard
    else if (lossFraction < 0.02) this.bitrate *= 1.05; // <2% loss → probe upward
    this.bitrate = Math.max(50_000, Math.min(8_000_000, this.bitrate)); // clamp 50 kbps..8 Mbps
    return this.bitrate;
  }

  getState(): BweState {
    return this.state;
  }
  getBitrate(): number {
    return this.bitrate;
  }
}
