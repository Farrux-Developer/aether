// lib/presence/crdt.ts
//
// LWW-Register keyed by a Hybrid Logical Clock (HLC), for Active-Active geo-replication
// of presence ("who is online, globally").
//
// Why a CRDT and not consensus: forcing Raft/Paxos across Sydney<->Frankfurt adds a
// cross-ocean RTT (~150 ms) to every status flip. A CRDT merge is a join over a
// semilattice — commutative, associative, idempotent — so regions converge with NO
// coordination and tolerate out-of-order / duplicate delivery from Kafka.
//
// Why HLC and not wall-clock: pure wall-clock LWW breaks when a region's clock is skewed
// ahead — its stale "offline" can permanently mask a fresh "online". HLC keeps physical
// time monotone AND adds a logical counter to break ties causally (Kulkarni et al.).

export type PresenceStatus = "online" | "away" | "offline";

// HLC timestamp: (physical ms, logical counter, node id for total order).
export interface Hlc {
  wall: number;
  count: number;
  node: string;
}

export function hlcNow(node: string, last?: Hlc): Hlc {
  const wall = Date.now();
  if (last && last.wall >= wall) {
    // Physical clock didn't advance past last event → bump logical counter.
    return { wall: last.wall, count: last.count + 1, node };
  }
  return { wall, count: 0, node };
}

// Total order on HLC: wall, then count, then node id (deterministic tie-break so all
// replicas pick the SAME winner regardless of merge order).
export function hlcCompare(a: Hlc, b: Hlc): number {
  if (a.wall !== b.wall) return a.wall - b.wall;
  if (a.count !== b.count) return a.count - b.count;
  return a.node < b.node ? -1 : a.node > b.node ? 1 : 0;
}

export interface PresenceValue {
  status: PresenceStatus;
  ts: Hlc;
  region: string;
}

// The LWW register for one user. merge() is the semilattice join: pure, side-effect free,
// O(1). Applying the same delta twice, or in any order, yields the same state.
export class PresenceRegister {
  private value: PresenceValue | null = null;

  get(): PresenceValue | null {
    return this.value;
  }

  // Returns true if the incoming value won (state changed) — used to gate fan-out pushes.
  merge(incoming: PresenceValue): boolean {
    if (!this.value || hlcCompare(incoming.ts, this.value.ts) > 0) {
      this.value = incoming;
      return true;
    }
    return false;
  }
}

// A sharded map of registers — one materialized view per region, fed by the Kafka
// "presence.delta" topic. Lookups and merges are O(1) amortized.
export class PresenceStore {
  private users = new Map<string, PresenceRegister>();

  merge(userId: string, value: PresenceValue): boolean {
    let reg = this.users.get(userId);
    if (!reg) this.users.set(userId, (reg = new PresenceRegister()));
    return reg.merge(value);
  }

  status(userId: string): PresenceStatus {
    return this.users.get(userId)?.get()?.status ?? "offline";
  }

  snapshot(): Record<string, PresenceValue> {
    const out: Record<string, PresenceValue> = {};
    for (const [id, reg] of this.users) {
      const v = reg.get();
      if (v) out[id] = v;
    }
    return out;
  }
}
