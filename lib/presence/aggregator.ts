// lib/presence/aggregator.ts
//
// Transport-agnostic heartbeat aggregator + batcher (the hot-path core of the edge
// presence node). The uWebSockets.js wrapper that actually holds ~1M sockets lives in
// services/edge-presence.ts and delegates to this — keeping the pure logic testable
// without a live socket cluster.
//
// The economy: heartbeats arrive tens of thousands/sec, but downstream (Kafka -> CRDT)
// only cares about the SET of statuses that CHANGED within a window. We coalesce by
// userId (idempotent: 1000 beats from one user in a window collapse to one record),
// then flush a single compressed batch every `flushMs`. Per-heartbeat work is O(1) with
// zero allocation in steady state; per-flush work is O(delta), never O(connections).

export type PresenceStatus = "online" | "away" | "offline";

export interface PresenceDelta {
  userId: string;
  status: PresenceStatus;
  ts: number; // wall-clock ms at the edge; HLC is assigned by the materializer
  region: string;
}

export type FlushSink = (batch: PresenceDelta[]) => Promise<void>;

export class PresenceAggregator {
  private dirty = new Map<string, PresenceDelta>();
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly region: string,
    private readonly sink: FlushSink,
    private readonly flushMs = 3000,
  ) {}

  // Record/refresh a user's status. O(1). Idempotent within a flush window.
  mark(userId: string, status: PresenceStatus): void {
    this.dirty.set(userId, { userId, status, ts: Date.now(), region: this.region });
  }

  start(): void {
    if (this.timer) return;
    // setInterval, not per-event flush: this is the backpressure valve that stops a
    // reconnect storm (e.g. a mobile tower handoff bouncing 100k sockets) from turning
    // into 100k Kafka writes. Amortized cost is bounded by window size, not fan-in rate.
    this.timer = setInterval(() => void this.flush(), this.flushMs);
    // Do not keep the event loop alive solely for this timer (Node-only; no-op elsewhere).
    (this.timer as unknown as { unref?: () => void }).unref?.();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  size(): number {
    return this.dirty.size;
  }

  // Swap-and-reset: the hot path is never blocked while I/O is in flight. On sink failure
  // we merge the batch back so no status is lost — the next window retries.
  async flush(): Promise<void> {
    if (this.dirty.size === 0) return;
    const batch = this.dirty;
    this.dirty = new Map();
    try {
      await this.sink([...batch.values()]);
    } catch {
      for (const [k, v] of batch) if (!this.dirty.has(k)) this.dirty.set(k, v);
    }
  }
}
