// Minimal RTP (RFC 3550) packet helpers and a timeline mapper for relaying.
import crypto from 'node:crypto';

export interface RtpInfo {
  pt: number;
  marker: boolean;
  seq: number;
  timestamp: number;
  ssrc: number;
  payload: Buffer;
}

/** Parse an RTP packet. Returns null for RTCP, STUN or junk. */
export function parseRtp(pkt: Buffer): RtpInfo | null {
  if (pkt.length < 12 || (pkt[0] & 0xc0) !== 0x80) return null;
  const pt = pkt[1] & 0x7f;
  if (pt >= 72 && pt <= 76) return null; // RTCP multiplexed on the same port

  let offset = 12 + 4 * (pkt[0] & 0x0f); // CSRC list
  if (pkt[0] & 0x10) {
    if (pkt.length < offset + 4) return null;
    offset += 4 + 4 * pkt.readUInt16BE(offset + 2); // header extension
  }
  let end = pkt.length;
  if (pkt[0] & 0x20) end -= pkt[pkt.length - 1]; // padding
  if (end < offset) return null;

  return {
    pt,
    marker: Boolean(pkt[1] & 0x80),
    seq: pkt.readUInt16BE(2),
    timestamp: pkt.readUInt32BE(4),
    ssrc: pkt.readUInt32BE(8),
    payload: pkt.subarray(offset, end),
  };
}

export function buildRtp({ pt, marker, seq, timestamp, ssrc, payload }: RtpInfo): Buffer {
  const h = Buffer.alloc(12);
  h[0] = 0x80; // V=2, no padding, no extension, no CSRC
  h[1] = (marker ? 0x80 : 0) | (pt & 0x7f);
  h.writeUInt16BE(seq & 0xffff, 2);
  h.writeUInt32BE(timestamp >>> 0, 4);
  h.writeUInt32BE(ssrc >>> 0, 8);
  return Buffer.concat([h, payload]);
}

export const randomUint32 = (): number => crypto.randomBytes(4).readUInt32BE();

/**
 * Maps packets from a source stream (whose SSRC, sequence numbers and timestamps may jump when
 * the far end restarts or the PBX re-bridges the call) onto one continuous outgoing stream.
 *
 * Within one source SSRC the timestamp gaps are preserved, so silence suppression and packet
 * loss keep their timing. Out-of-order and duplicate packets are dropped (G.711 at 20 ms has
 * nothing to gain from reordering in a relay).
 */
export class RtpTimeline {
  seq = randomUint32() & 0xffff;
  timestamp = randomUint32();
  private srcSsrc: number | null = null;
  private srcSeq = 0;
  private srcTimestamp = 0;
  private started = false;

  /**
   * Returns the outgoing { seq, timestamp, marker } for a source packet, or null to drop it.
   * `samples` is the packet's duration in clock ticks (for G.711: the payload length).
   */
  map(src: { ssrc: number; seq: number; timestamp: number; marker: boolean }, samples: number): { seq: number; timestamp: number; marker: boolean } | null {
    let marker = src.marker;
    if (this.srcSsrc !== src.ssrc || !this.started) {
      // New source: continue our timeline one frame after the last packet.
      if (this.started) this.timestamp = (this.timestamp + samples) >>> 0;
      marker = true;
    } else {
      const seqDelta = (src.seq - this.srcSeq) & 0xffff;
      if (seqDelta === 0 || seqDelta > 0x8000) return null; // duplicate or late
      let tsDelta = (src.timestamp - this.srcTimestamp) >>> 0;
      // A jump of more than 10 s (or backwards) is a source reset, not a real gap.
      if (tsDelta === 0 || tsDelta > 80000) tsDelta = samples;
      this.timestamp = (this.timestamp + tsDelta) >>> 0;
    }
    this.started = true;
    this.srcSsrc = src.ssrc;
    this.srcSeq = src.seq;
    this.srcTimestamp = src.timestamp;
    this.seq = (this.seq + 1) & 0xffff;
    return { seq: this.seq, timestamp: this.timestamp, marker };
  }

  /** Allocate the next sequence number without moving the timeline (RFC 4733 DTMF packets). */
  nextSeq(): number {
    this.seq = (this.seq + 1) & 0xffff;
    return this.seq;
  }
}
