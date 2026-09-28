// G.711 µ-law (PCMU, PT 0) and A-law (PCMA, PT 8): 8 kHz, one byte per sample.
//
// The gateway normally relays G.711 bytes untouched. When the browser leg and the Asterisk leg
// end up on different laws, each byte is mapped through a 256-entry table (decode to linear,
// re-encode). Port of the Sun Microsystems reference implementation (g711.c).
import type { CodecName } from '../sip/sdp.ts';

const SEG_UEND = [0x3f, 0x7f, 0xff, 0x1ff, 0x3ff, 0x7ff, 0xfff, 0x1fff];
const SEG_AEND = [0x1f, 0x3f, 0x7f, 0xff, 0x1ff, 0x3ff, 0x7ff, 0xfff];

const segment = (val: number, table: number[]): number => {
  for (let i = 0; i < table.length; i++) if (val <= table[i]) return i;
  return table.length;
};

export function linearToUlaw(pcm: number): number {
  let val = pcm >> 2;
  let mask = 0xff;
  if (val < 0) {
    val = -val;
    mask = 0x7f;
  }
  if (val > 8159) val = 8159;
  val += 0x21; // bias
  const seg = segment(val, SEG_UEND);
  if (seg >= 8) return 0x7f ^ mask;
  return ((seg << 4) | ((val >> (seg + 1)) & 0x0f)) ^ mask;
}

export function ulawToLinear(u: number): number {
  u = ~u & 0xff;
  let t = ((u & 0x0f) << 3) + 0x84;
  t <<= (u & 0x70) >> 4;
  return u & 0x80 ? 0x84 - t : t - 0x84;
}

export function linearToAlaw(pcm: number): number {
  let val = pcm >> 3;
  let mask = 0xd5;
  if (val < 0) {
    mask = 0x55;
    val = -val - 1;
  }
  const seg = segment(val, SEG_AEND);
  if (seg >= 8) return 0x7f ^ mask;
  const aval = (seg << 4) | ((seg < 2 ? val >> 1 : val >> seg) & 0x0f);
  return aval ^ mask;
}

export function alawToLinear(a: number): number {
  a ^= 0x55;
  let t = (a & 0x0f) << 4;
  const seg = (a & 0x70) >> 4;
  if (seg === 0) t += 8;
  else if (seg === 1) t += 0x108;
  else t = (t + 0x108) << (seg - 1);
  return a & 0x80 ? t : -t;
}

const ULAW_TO_ALAW = Uint8Array.from({ length: 256 }, (_, i) => linearToAlaw(ulawToLinear(i)));
const ALAW_TO_ULAW = Uint8Array.from({ length: 256 }, (_, i) => linearToUlaw(alawToLinear(i)));

/** Byte value of digital silence for each law. */
export const SILENCE: Record<CodecName, number> = { PCMU: 0xff, PCMA: 0xd5 };

/** Convert a G.711 payload between laws. Returns the input unchanged when they match. */
export function transcode(payload: Buffer, from: CodecName, to: CodecName): Buffer {
  if (from === to) return payload;
  const table = from === 'PCMU' ? ULAW_TO_ALAW : ALAW_TO_ULAW;
  const out = Buffer.allocUnsafe(payload.length);
  for (let i = 0; i < payload.length; i++) out[i] = table[payload[i]];
  return out;
}
