// lib/signaling/turn.ts
//
// Ephemeral TURN credentials (coturn "REST API" scheme, draft-uberti-behave-turn-rest).
// Instead of static long-term credentials sitting in a DB, the username encodes an expiry
// and the password is an HMAC over it keyed by a shared secret. coturn recomputes the same
// HMAC to authorize — no per-user secret storage, credentials auto-expire.
//
// TURN is required for SYMMETRIC NAT: such a NAT maps a new external port per destination,
// so the port STUN observed for the server is useless for the peer. A TURN relay sidesteps
// this by being a fixed public rendezvous both sides can reach.
//
// HMAC-SHA1 here matches coturn's expected algorithm (not a security downgrade — it's a MAC
// over non-secret, short-lived data, and interop is fixed by coturn).

export interface TurnCredential {
  username: string;
  credential: string;
  ttl: number;
  urls: string[];
}

export async function turnCredential(
  userId: string,
  secret: string,
  opts: { ttlSeconds?: number; host?: string } = {},
): Promise<TurnCredential> {
  const ttl = opts.ttlSeconds ?? 600;
  const host = opts.host ?? "turn.aether.app:3478";
  const username = `${Math.floor(Date.now() / 1000) + ttl}:${userId}`;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret) as BufferSource,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const mac = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(username) as BufferSource),
  );
  // coturn expects standard base64 for the credential.
  const credential = btoa(String.fromCharCode(...mac));

  return {
    username,
    credential,
    ttl,
    // UDP first (lowest TTFF); TCP/TLS TURN is a fallback for networks that block UDP.
    urls: [`turn:${host}?transport=udp`, `turn:${host}?transport=tcp`],
  };
}
