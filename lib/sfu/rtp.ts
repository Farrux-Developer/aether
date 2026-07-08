// lib/sfu/rtp.ts
//
// Zero-copy RTP header parsing (RFC 3550) + RID extraction (RFC 8852 / 8285).
//
// This is the SFU's absolute hot path: at 1080p30 a single publisher emits ~1000–1500
// packets/sec; 1000 publishers on a node = ~1.5M pkt/s. So: NO allocations, NO slices —
// read fields directly out of the buffer by offset. Every function here is O(1) (the RID
// TLV scan is O(#extensions), typically 1–3). The SFU never decodes the codec payload;
// it forwards or drops whole packets based on these headers alone.

export interface RtpHeader {
  version: number;
  padding: boolean;
  marker: boolean; // end-of-frame marker → safe boundary to switch layers
  payloadType: number;
  sequenceNumber: number;
  timestamp: number;
  ssrc: number;
  csrcCount: number;
  hasExtension: boolean;
  extOffset: number; // byte offset of the extension block, or -1
  payloadOffset: number; // byte offset where media payload begins
}

export function parseRtp(b: Uint8Array): RtpHeader {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const b0 = b[0];
  const b1 = b[1];
  const version = b0 >> 6; // MUST be 2
  const padding = (b0 & 0x20) !== 0;
  const hasExtension = (b0 & 0x10) !== 0;
  const csrcCount = b0 & 0x0f;
  const marker = (b1 & 0x80) !== 0;
  const payloadType = b1 & 0x7f;
  const sequenceNumber = view.getUint16(2, false);
  const timestamp = view.getUint32(4, false);
  const ssrc = view.getUint32(8, false);

  let off = 12 + csrcCount * 4; // fixed header + CSRC list
  let extOffset = -1;
  if (hasExtension) {
    extOffset = off;
    const words = view.getUint16(off + 2, false); // extension length in 32-bit words
    off += 4 + words * 4;
  }
  return {
    version,
    padding,
    marker,
    payloadType,
    sequenceNumber,
    timestamp,
    ssrc,
    csrcCount,
    hasExtension,
    extOffset,
    payloadOffset: off,
  };
}

// Read the RID (restriction identifier, e.g. "h" | "m" | "l") from a one-byte RTP header
// extension (RFC 8285 profile 0xBEDE). RID is how a simulcast publisher labels which of
// its 3 encodings a packet belongs to, without the SFU decoding anything.
export function readRid(b: Uint8Array, h: RtpHeader, ridExtId: number): string | null {
  if (!h.hasExtension || h.extOffset < 0) return null;
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const profile = view.getUint16(h.extOffset, false);
  if (profile !== 0xbede) return null; // only one-byte form handled here
  let p = h.extOffset + 4;
  const end = h.payloadOffset;
  while (p < end) {
    const idlen = b[p];
    if (idlen === 0) {
      p++;
      continue;
    } // padding byte
    const id = idlen >> 4;
    const len = (idlen & 0x0f) + 1;
    if (id === 15) break; // reserved terminator
    if (id === ridExtId) {
      let s = "";
      for (let i = 0; i < len; i++) s += String.fromCharCode(b[p + 1 + i]);
      return s;
    }
    p += 1 + len;
  }
  return null;
}

// Minimal RTP packet builder — used by the selftest to round-trip parse, and by the SFU
// to rewrite SSRC/sequence when switching simulcast layers for a subscriber.
export function buildRtp(
  h: Pick<RtpHeader, "marker" | "payloadType" | "sequenceNumber" | "timestamp" | "ssrc">,
  payload: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(12 + payload.length);
  const view = new DataView(out.buffer);
  out[0] = 0x80; // v=2, no padding/ext/csrc
  out[1] = (h.marker ? 0x80 : 0) | (h.payloadType & 0x7f);
  view.setUint16(2, h.sequenceNumber & 0xffff, false);
  view.setUint32(4, h.timestamp >>> 0, false);
  view.setUint32(8, h.ssrc >>> 0, false);
  out.set(payload, 12);
  return out;
}
