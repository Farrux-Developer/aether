// lib/crypto/bytes.ts
//
// Isomorphic byte / BigInt / hash primitives.
//
// Everything here touches ONLY Web Crypto (`crypto.subtle`, `crypto.getRandomValues`)
// and native BigInt — never Node's `crypto` module. That is deliberate: the exact same
// code path runs in the browser, in Node.js, and in the Next.js Edge runtime. This is
// what makes the SRP handshake (lib/auth/srp.ts) truly zero-knowledge — the identical
// hashing/modexp routine executes client-side, so the password never has to leave the
// device even to be "prepared" for the server.

export function hexToBigInt(hex: string): bigint {
  return BigInt("0x" + hex.replace(/\s+/g, ""));
}

export function bigIntToHex(x: bigint): string {
  let h = x.toString(16);
  if (h.length % 2) h = "0" + h;
  return h;
}

export function bytesToBigInt(b: Uint8Array): bigint {
  // Big-endian decode. O(n) over byte length (n = 256 for a 2048-bit group).
  let x = 0n;
  for (const byte of b) x = (x << 8n) | BigInt(byte);
  return x;
}

// Fixed-length big-endian encoding.
// RFC 5054 §2.6 mandates PADding A, B, g to byte-length(N) BEFORE hashing; skip it and
// client & server derive different u/k/M1 on ~1/256 of handshakes (leading-zero case) —
// the classic SRP interop bug. Always pad.
export function bigIntToBytes(x: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let i = length - 1;
  while (x > 0n && i >= 0) {
    out[i--] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

export function concat(...arrs: Uint8Array[]): Uint8Array {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arrs) {
    out.set(a, o);
    o += a.length;
  }
  return out;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function fromUtf8(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

export function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  // SHA-256 ~ a few µs for small inputs; hardware-accelerated in V8/BoringSSL.
  const d = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return new Uint8Array(d);
}

// modPow: square-and-multiply. O(log2(exp)) modular multiplications; each mulmod over
// k=32 limbs (2048-bit) is O(k^2). Net: a 2048-bit modexp is ~1–3 ms in V8 BigInt.
// This is the dominant server cost of one SRP login, so it belongs off the main API loop.
export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let r = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) r = (r * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return r;
}

// Constant-time comparison for proof bytes (M1/M2). A byte-by-byte early-return `===`
// would leak, via timing, how many leading bytes matched — enough to forge a proof
// server-side over many attempts. This runs in time independent of the mismatch position.
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b); // CSPRNG; max 65536 bytes/call (we use ≤32)
  return b;
}

// --- base64url (JWT-style token segments), no padding ---
export function b64urlEncode(b: Uint8Array): string {
  let s = "";
  for (const byte of b) s += String.fromCharCode(byte);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(s: string): Uint8Array {
  const norm = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(norm);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
