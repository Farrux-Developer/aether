// lib/auth/session.ts
//
// Stateless session tokens signed with Ed25519 (EdDSA over Curve25519).
//
// Why Ed25519 and not RSA/HS256:
//   - verify ≈ 60–120 µs on commodity edge CPU (vs ~1–2 ms for RSA-2048 verify),
//     which matters when this runs on EVERY request at the PoP before the origin;
//   - signatures are deterministic and the algorithm is constant-time by construction
//     (no secret-dependent branches) → no timing side channel;
//   - 64-byte signatures, 32-byte keys — cheap to ship in a cookie/header.
//
// Token layout is JWT-ish but minimal:  b64url(header) "." b64url(claims) "." b64url(sig)
// The heavy PAKE/WebAuthn ceremony (lib/auth/srp.ts) happens ONCE per session; this token
// is the cheap per-request bearer that the edge proxy (proxy.ts) validates without ever
// touching the origin or a database.

import {
  b64urlDecode,
  b64urlEncode,
  bytesToHex,
  fromUtf8,
  sha256,
  utf8,
} from "@/lib/crypto/bytes";

export interface SessionClaims {
  sub: string; // user id
  iat: number; // issued-at (unix seconds)
  exp: number; // expiry (unix seconds) — keep SHORT; rotation covers longevity
  j3?: string; // sha256(JA3) TLS-fingerprint binding, hex
}

export interface KeyEntry {
  kid: string;
  publicKey: CryptoKey;
  privateKey?: CryptoKey; // present only on the signing side
  createdAt: number;
}

export async function generateKeyPair(kid: string): Promise<KeyEntry> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  return { kid, publicKey: kp.publicKey, privateKey: kp.privateKey, createdAt: Date.now() };
}

export async function exportPublicJwk(entry: KeyEntry): Promise<JsonWebKey & { kid: string }> {
  const jwk = (await crypto.subtle.exportKey("jwk", entry.publicKey)) as JsonWebKey;
  return { ...jwk, kid: entry.kid };
}

export async function importPublicJwk(jwk: JsonWebKey & { kid: string }): Promise<KeyEntry> {
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "Ed25519" },
    true,
    ["verify"],
  );
  return { kid: jwk.kid, publicKey, createdAt: Date.now() };
}

export async function ja3Hash(ja3: string): Promise<string> {
  return bytesToHex(await sha256(utf8(ja3)));
}

// Mint a signed token. `bindJa3` is the raw JA3 string of the client's TLS ClientHello;
// we store H(JA3) so a stolen token replayed from a different TLS stack fails validation.
export async function mintToken(
  signer: KeyEntry,
  sub: string,
  ttlSeconds: number,
  bindJa3?: string,
): Promise<string> {
  if (!signer.privateKey) throw new Error("mintToken: signer has no private key");
  const now = Math.floor(Date.now() / 1000);
  const claims: SessionClaims = {
    sub,
    iat: now,
    exp: now + ttlSeconds,
    ...(bindJa3 ? { j3: await ja3Hash(bindJa3) } : {}),
  };
  const header = { alg: "EdDSA", typ: "AET", kid: signer.kid };
  const h = b64urlEncode(utf8(JSON.stringify(header)));
  const p = b64urlEncode(utf8(JSON.stringify(claims)));
  const sig = new Uint8Array(
    await crypto.subtle.sign("Ed25519", signer.privateKey, utf8(`${h}.${p}`) as BufferSource),
  );
  return `${h}.${p}.${b64urlEncode(sig)}`;
}

export interface VerifyOptions {
  ja3?: string; // present JA3 of the incoming connection to enforce binding
  now?: number; // override clock (tests)
}

// Verify a token against a keyring resolver (kid -> public key, supports rotation).
// Returns claims on success or null on any failure (bad sig, unknown kid, expired,
// fingerprint mismatch). Never throws on attacker-controlled input.
export async function verifyToken(
  token: string,
  resolveKey: (kid: string) => Promise<CryptoKey | null> | CryptoKey | null,
  opts: VerifyOptions = {},
): Promise<SessionClaims | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;

  let header: { kid?: string; alg?: string };
  try {
    header = JSON.parse(fromUtf8(b64urlDecode(h)));
  } catch {
    return null;
  }
  if (header.alg !== "EdDSA" || !header.kid) return null;

  const key = await resolveKey(header.kid);
  if (!key) return null; // unknown/rotated-out kid

  let ok = false;
  try {
    ok = await crypto.subtle.verify(
      "Ed25519",
      key,
      b64urlDecode(s) as BufferSource,
      utf8(`${h}.${p}`) as BufferSource,
    );
  } catch {
    return null;
  }
  if (!ok) return null;

  let claims: SessionClaims;
  try {
    claims = JSON.parse(fromUtf8(b64urlDecode(p)));
  } catch {
    return null;
  }

  const now = opts.now ?? Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== "number" || claims.exp < now) return null;

  // Session-hijacking guard: token is bound to the TLS fingerprint it was minted for.
  // Different browser/OS/proxy => different JA3 => rejection. (See caveats in README:
  // JA3 is a stack fingerprint, an extra layer atop short TTL + rotation, not an identity.)
  if (claims.j3) {
    if (!opts.ja3) return null; // token demands a fingerprint we weren't given
    if ((await ja3Hash(opts.ja3)) !== claims.j3) return null;
  }
  return claims;
}
