// lib/auth/srp.ts
//
// SRP-6a (RFC 5054) — augmented PAKE / zero-knowledge password proof.
//
// The server stores ONLY the verifier v = g^x mod N (x derived from salt+password).
// The password, and even x, never travel the wire — not in plaintext, not hashed.
// Client and server each independently derive the same premaster secret S and session
// key K; a passive observer sees only A, B, salt, from which recovering S is equivalent
// to solving Diffie-Hellman + discrete log over a 2048-bit safe-prime group.
//
// Protocol (all arithmetic mod N):
//   register: x = H(salt | H(I ":" P)),  v = g^x                          -> store {I, salt, v}
//   login:
//     C -> S:  A = g^a                    (a ephemeral, 256-bit)
//     S -> C:  salt, B = k*v + g^b        (b ephemeral; k = H(N | PAD(g)))
//     both:    u = H(PAD(A) | PAD(B))
//     C:       S = (B - k*g^x)^(a + u*x),  K = H(S)
//     S:       S = (A * v^u)^b,            K = H(S)
//     C -> S:  M1 = H(H(N) XOR H(g), H(I), salt, A, B, K)   (server verifies)
//     S -> C:  M2 = H(A, M1, K)                             (client verifies)

import {
  bigIntToBytes,
  bigIntToHex,
  bytesToBigInt,
  bytesToHex,
  concat,
  hexToBigInt,
  hexToBytes,
  modPow,
  randomBytes,
  sha256,
  timingSafeEqual,
  utf8,
} from "@/lib/crypto/bytes";

// RFC 5054, Appendix A — 2048-bit group. N is a safe prime (N = 2q+1, q prime), so the
// order-q subgroup is prime → no small-subgroup confinement attacks. g = 2 is a generator.
export const N = hexToBigInt(
  "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4" +
    "A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60" +
    "95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF" +
    "747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907" +
    "8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861" +
    "60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB" +
    "FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
);
export const g = 2n;

// Byte length of the group (256 for 2048-bit). Used for RFC 5054 PADding.
const NLEN = Math.ceil(bigIntToHex(N).length / 2);
const pad = (x: bigint) => bigIntToBytes(x, NLEN);

async function H(...parts: Uint8Array[]): Promise<bigint> {
  return bytesToBigInt(await sha256(concat(...parts)));
}

// k = H(N | PAD(g)) — the SRP-6a multiplier that closed the SRP-3 "two-for-one" guess:
// without it a malicious server could probe two password candidates per handshake.
let _k: bigint | null = null;
async function getK(): Promise<bigint> {
  if (_k === null) _k = await H(pad(N), pad(g));
  return _k;
}

// x = H(salt | H(I ":" P)). The inner H(I:P) binds identity to password so the same
// password under two usernames yields different verifiers.
async function computeX(salt: Uint8Array, I: string, P: string): Promise<bigint> {
  const inner = await sha256(utf8(`${I}:${P}`));
  return bytesToBigInt(await sha256(concat(salt, inner)));
}

async function computeM1(
  I: string,
  salt: Uint8Array,
  A: bigint,
  B: bigint,
  K: Uint8Array,
): Promise<Uint8Array> {
  const hN = await sha256(pad(N));
  const hg = await sha256(pad(g));
  const hI = await sha256(utf8(I));
  const xor = new Uint8Array(hN.length);
  for (let i = 0; i < xor.length; i++) xor[i] = hN[i] ^ hg[i];
  return sha256(concat(xor, hI, salt, pad(A), pad(B), K));
}

export interface Verifier {
  I: string;
  salt: string; // hex
  verifier: string; // hex, = g^x mod N
}

// REGISTRATION — runs CLIENT-SIDE. The output {salt, verifier} is what gets POSTed and
// stored; the server never receives P. A DB leak yields only v, which costs an offline
// brute-force bounded by password entropy + salt — never a direct login.
export async function register(I: string, P: string): Promise<Verifier> {
  const salt = randomBytes(16);
  const x = await computeX(salt, I, P);
  const v = modPow(g, x, N); // v = g^x, ~1–3 ms
  return { I, salt: bytesToHex(salt), verifier: bigIntToHex(v) };
}

export class SrpClient {
  private a!: bigint;
  A!: bigint;

  // Generate ephemeral a and public A = g^a. Abort/retry if A ≡ 0 (mod N).
  async start(): Promise<string> {
    do {
      this.a = bytesToBigInt(randomBytes(32)); // 256-bit ephemeral
      this.A = modPow(g, this.a, N);
    } while (this.A % N === 0n);
    return bigIntToHex(this.A);
  }

  // Consume server's (salt, B) plus the user's password to derive proof M1 and key K.
  async process(
    I: string,
    P: string,
    saltHex: string,
    Bhex: string,
  ): Promise<{ M1: string; K: Uint8Array }> {
    const B = hexToBigInt(Bhex);
    // Abort if B ≡ 0 (mod N): a malicious/broken server value that would collapse S.
    if (B % N === 0n) throw new Error("SRP abort: B ≡ 0 (mod N)");
    const salt = hexToBytes(saltHex);
    const k = await getK();
    const u = await H(pad(this.A), pad(B));
    if (u === 0n) throw new Error("SRP abort: u == 0");
    const x = await computeX(salt, I, P);

    // S = (B - k*g^x)^(a + u*x) mod N. Keep the base in [0, N) after subtraction.
    let base = (B - ((k * modPow(g, x, N)) % N)) % N;
    if (base < 0n) base += N;
    const S = modPow(base, this.a + u * x, N);

    const K = await sha256(pad(S));
    const M1 = await computeM1(I, salt, this.A, B, K);
    return { M1: bytesToHex(M1), K };
  }

  // Verify the server's proof M2 = H(A, M1, K). Mutual auth: proves the server actually
  // knew v (not just relayed our A) — defeats a MITM that lacks the verifier.
  async verifyServer(M2hex: string, M1hex: string, K: Uint8Array): Promise<boolean> {
    const expected = await sha256(concat(pad(this.A), hexToBytes(M1hex), K));
    return timingSafeEqual(expected, hexToBytes(M2hex));
  }
}

export class SrpServer {
  private b!: bigint;
  private v!: bigint;
  B!: bigint;

  // Given the stored verifier, produce B = k*v + g^b. Retry if B ≡ 0 (mod N).
  async start(verifierHex: string): Promise<string> {
    this.v = hexToBigInt(verifierHex);
    const k = await getK();
    do {
      this.b = bytesToBigInt(randomBytes(32));
      this.B = (k * this.v + modPow(g, this.b, N)) % N;
    } while (this.B % N === 0n);
    return bigIntToHex(this.B);
  }

  // Verify client's M1. Returns {M2, K} on success, or null on bad proof (wrong password).
  async verify(
    I: string,
    saltHex: string,
    Ahex: string,
    clientM1Hex: string,
  ): Promise<{ M2: string; K: Uint8Array } | null> {
    const A = hexToBigInt(Ahex);
    // CRITICAL: abort if A ≡ 0 (mod N). Otherwise S = 0 and any attacker logs in with
    // no password knowledge — the canonical SRP implementation footgun.
    if (A % N === 0n) throw new Error("SRP abort: A ≡ 0 (mod N)");
    const salt = hexToBytes(saltHex);
    const u = await H(pad(A), pad(this.B));

    const S = modPow((A * modPow(this.v, u, N)) % N, this.b, N); // S = (A * v^u)^b
    const K = await sha256(pad(S));

    const expectedM1 = await computeM1(I, salt, A, this.B, K);
    // Constant-time compare — do not short-circuit on first mismatched byte.
    if (!timingSafeEqual(expectedM1, hexToBytes(clientM1Hex))) return null;

    const M2 = await sha256(concat(pad(A), expectedM1, K)); // M2 = H(A, M1, K)
    return { M2: bytesToHex(M2), K };
  }

  // Serialize the per-handshake secret state so it can live in a short-TTL session store
  // between the two HTTP round-trips (challenge -> verify). b and B expire in ~60s.
  snapshot(): { b: string; B: string; v: string } {
    return { b: bigIntToHex(this.b), B: bigIntToHex(this.B), v: bigIntToHex(this.v) };
  }
  static restore(s: { b: string; B: string; v: string }): SrpServer {
    const srv = new SrpServer();
    // Private access is legal here — same class, static method.
    srv.b = hexToBigInt(s.b);
    srv.v = hexToBigInt(s.v);
    srv.B = hexToBigInt(s.B);
    return srv;
  }
}
