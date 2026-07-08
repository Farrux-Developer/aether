// lib/auth/store.ts
//
// DEV/demo in-memory stores. Two things need to persist across HTTP round-trips:
//   1. verifiers — {I, salt, v} written at registration, read at login (prod: Postgres).
//   2. pending SRP handshakes — the server's ephemeral {b, B, v} between /challenge and
//      /verify, with a short TTL (prod: Redis with EXPIRE, so any PoP can complete it).
//
// A short TTL on handshakes is a security property, not just cleanup: it bounds the window
// for replay/guessing against a captured B.

import type { Verifier } from "@/lib/auth/srp";

interface Pending {
  I: string;
  salt: string;
  A: string;
  snap: { b: string; B: string; v: string };
  expires: number;
}

interface Stores {
  verifiers: Map<string, Verifier>;
  pending: Map<string, Pending>;
}

const g = globalThis as unknown as { __aetherStores?: Stores };
const stores: Stores =
  g.__aetherStores ??
  (g.__aetherStores = { verifiers: new Map(), pending: new Map() });

const HANDSHAKE_TTL_MS = 60_000;

export function putVerifier(v: Verifier): void {
  stores.verifiers.set(v.I, v);
}
export function getVerifier(I: string): Verifier | null {
  return stores.verifiers.get(I) ?? null;
}

export function putPending(id: string, p: Omit<Pending, "expires">): void {
  stores.pending.set(id, { ...p, expires: Date.now() + HANDSHAKE_TTL_MS });
}

// Read-and-delete: a handshake id is single-use (prevents verify replay).
export function takePending(id: string): Pending | null {
  const p = stores.pending.get(id);
  if (!p) return null;
  stores.pending.delete(id);
  if (p.expires < Date.now()) return null; // expired → treat as absent
  return p;
}

export function newHandshakeId(): string {
  return `hs_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}
