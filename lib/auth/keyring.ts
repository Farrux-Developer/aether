// lib/auth/keyring.ts
//
// In-process signing keyring with rotation + overlap (Node/route-handler side).
//
// Rotation model: a "current" key signs new tokens; on rotate() a fresh kid becomes
// current, but previous keys are retained until their tokens can no longer be valid
// (retain window >= max token TTL). The edge (proxy.ts) resolves by kid via the public
// JWKS endpoint, so a rotation never invalidates in-flight sessions.
//
// This singleton is a DEV/demo store. In production the private keys live in a KMS/HSM
// and the public JWKS is served from Cloudflare KV / a CDN cache. See services/README.md.

import { exportPublicJwk, generateKeyPair, type KeyEntry } from "@/lib/auth/session";

const RETAIN_MS = 26 * 60 * 60 * 1000; // > token TTL (24h) + skew, so overlap is safe

class Keyring {
  private keys = new Map<string, KeyEntry>();
  private currentKid: string | null = null;
  private initializing: Promise<void> | null = null;

  private async ensure(): Promise<void> {
    if (this.currentKid) return;
    if (!this.initializing) this.initializing = this.rotate().then(() => undefined);
    await this.initializing;
  }

  async current(): Promise<KeyEntry> {
    await this.ensure();
    return this.keys.get(this.currentKid!)!;
  }

  // Create a new current key and prune keys older than the retain window.
  async rotate(): Promise<KeyEntry> {
    const kid = `k_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    const entry = await generateKeyPair(kid);
    this.keys.set(kid, entry);
    this.currentKid = kid;
    const cutoff = Date.now() - RETAIN_MS;
    for (const [k, v] of this.keys) if (v.createdAt < cutoff) this.keys.delete(k);
    return entry;
  }

  get(kid: string): KeyEntry | null {
    return this.keys.get(kid) ?? null;
  }

  // Public JWKS document (never exposes private material) for the edge to fetch + cache.
  async jwks(): Promise<{ keys: Array<JsonWebKey & { kid: string }> }> {
    await this.ensure();
    const keys = await Promise.all([...this.keys.values()].map(exportPublicJwk));
    return { keys };
  }
}

// Module-singleton. During `next dev` all route handlers share this one Node instance.
const g = globalThis as unknown as { __aetherKeyring?: Keyring };
export const keyring: Keyring = g.__aetherKeyring ?? (g.__aetherKeyring = new Keyring());
