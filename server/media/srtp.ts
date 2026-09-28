// SRTP (RFC 3711) with the AES_CM_128_HMAC_SHA1_80 profile, keyed by SDES (RFC 4568).
//
// Each direction has its own master key (16 bytes) + master salt (14 bytes), exchanged as
// `a=crypto:<tag> AES_CM_128_HMAC_SHA1_80 inline:<base64 of key||salt>` in the SDP. That SDP
// travels inside SIP, which is why SIP must run over TLS: over plain UDP anyone on the path
// could read the keys.
//
//   protect:   RTP header | AES-128-CTR(payload) | HMAC-SHA1(header|ciphertext|ROC)[0..10]
//   unprotect: verify the 80-bit tag, then decrypt
//
// No MKI, key derivation rate 0 (session keys derived once), RTCP is not used (SRTCP packets
// are dropped by the caller). One context per direction; the receiving side tracks the
// rollover counter (ROC) per SSRC as in RFC 3711 Appendix A.
import crypto from 'node:crypto';

export const SRTP_SUITE = 'AES_CM_128_HMAC_SHA1_80';
export const MASTER_KEY_LEN = 16;
export const MASTER_SALT_LEN = 14;
const AUTH_KEY_LEN = 20;
const TAG_LEN = 10;

/** AES-CM PRF from RFC 3711 §4.3.1: derive `length` bytes for `label` (key derivation rate 0). */
export function deriveKey(masterKey: Buffer, masterSalt: Buffer, label: number, length: number): Buffer {
  const iv = Buffer.alloc(16);
  masterSalt.copy(iv, 0, 0, MASTER_SALT_LEN);
  iv[7] ^= label; // key_id = label || r (r = 0), right-aligned in the 112-bit salt
  const cipher = crypto.createCipheriv('aes-128-ecb', masterKey, null);
  cipher.setAutoPadding(false);
  const out = Buffer.alloc(Math.ceil(length / 16) * 16);
  for (let block = 0; block * 16 < length; block++) {
    iv.writeUInt16BE(block, 14); // x * 2^16 + counter
    cipher.update(iv).copy(out, block * 16);
  }
  return out.subarray(0, length);
}

export interface SessionKeys {
  cipherKey: Buffer;
  authKey: Buffer;
  salt: Buffer;
}

export function deriveSessionKeys(master: Buffer): SessionKeys {
  if (master.length !== MASTER_KEY_LEN + MASTER_SALT_LEN) throw new Error(`SRTP master key+salt must be 30 bytes, got ${master.length}`);
  const key = master.subarray(0, MASTER_KEY_LEN);
  const salt = master.subarray(MASTER_KEY_LEN);
  return {
    cipherKey: deriveKey(key, salt, 0, MASTER_KEY_LEN),
    authKey: deriveKey(key, salt, 1, AUTH_KEY_LEN),
    salt: deriveKey(key, salt, 2, MASTER_SALT_LEN),
  };
}

/** Offset of the payload: fixed header, CSRCs and the header extension. */
function headerLength(pkt: Buffer): number {
  let len = 12 + 4 * (pkt[0] & 0x0f);
  if (pkt[0] & 0x10) {
    if (pkt.length < len + 4) return -1;
    len += 4 + 4 * pkt.readUInt16BE(len + 2);
  }
  return len <= pkt.length ? len : -1;
}

/** Packet index = ROC * 2^16 + SEQ (48 bits). Applies the AES-CM keystream in place. */
function applyKeystream(keys: SessionKeys, ssrc: number, index: number, data: Buffer): Buffer {
  // IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)
  const iv = Buffer.alloc(16);
  keys.salt.copy(iv, 0);
  iv.writeUInt32BE((iv.readUInt32BE(4) ^ ssrc) >>> 0, 4);
  const hi = Math.floor(index / 0x100000000);
  const lo = index >>> 0;
  iv.writeUInt16BE(iv.readUInt16BE(8) ^ hi, 8);
  iv.writeUInt32BE((iv.readUInt32BE(10) ^ lo) >>> 0, 10);
  const cipher = crypto.createCipheriv('aes-128-ctr', keys.cipherKey, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function authTag(keys: SessionKeys, authenticated: Buffer, roc: number): Buffer {
  const rocBuf = Buffer.alloc(4);
  rocBuf.writeUInt32BE(roc >>> 0);
  return crypto.createHmac('sha1', keys.authKey).update(authenticated).update(rocBuf).digest().subarray(0, TAG_LEN);
}

/** Generate a fresh base64 master key||salt for an `a=crypto` line. */
export function generateMasterKey(): string {
  return crypto.randomBytes(MASTER_KEY_LEN + MASTER_SALT_LEN).toString('base64');
}

/** One direction of an SRTP session. */
export class SrtpContext {
  private readonly keys: SessionKeys;
  // sending side: one stream (our SSRC)
  private sendRoc = 0;
  private lastSendSeq: number | null = null;
  // receiving side: ROC tracking per SSRC
  private readonly recv = new Map<number, { roc: number; seq: number }>();

  /** `masterKeyB64` is the `inline:` value of an a=crypto line (key || salt, base64). */
  constructor(masterKeyB64: string) {
    this.keys = deriveSessionKeys(Buffer.from(masterKeyB64, 'base64'));
  }

  /** Encrypt + authenticate one RTP packet. */
  protect(rtp: Buffer): Buffer {
    const hlen = headerLength(rtp);
    if (hlen < 0) throw new Error('Malformed RTP packet');
    const seq = rtp.readUInt16BE(2);
    const ssrc = rtp.readUInt32BE(8);
    // Our sequence numbers only move forward; a smaller one means it wrapped.
    if (this.lastSendSeq !== null && seq < this.lastSendSeq && this.lastSendSeq - seq > 0x8000) this.sendRoc = (this.sendRoc + 1) >>> 0;
    this.lastSendSeq = seq;
    const index = this.sendRoc * 0x10000 + seq;
    const encrypted = Buffer.concat([rtp.subarray(0, hlen), applyKeystream(this.keys, ssrc, index, rtp.subarray(hlen))]);
    return Buffer.concat([encrypted, authTag(this.keys, encrypted, this.sendRoc)]);
  }

  /** Verify + decrypt one SRTP packet. Returns null if it fails authentication. */
  unprotect(srtp: Buffer): Buffer | null {
    if (srtp.length < 12 + TAG_LEN) return null;
    const body = srtp.subarray(0, srtp.length - TAG_LEN);
    const tag = srtp.subarray(srtp.length - TAG_LEN);
    const hlen = headerLength(body);
    if (hlen < 0) return null;
    const seq = body.readUInt16BE(2);
    const ssrc = body.readUInt32BE(8);

    // Estimate the ROC this packet was sent with (RFC 3711 Appendix A).
    const state = this.recv.get(ssrc);
    let roc = 0;
    if (state) {
      roc = state.roc;
      if (state.seq < 0x8000) {
        if (seq - state.seq > 0x8000) roc = state.roc - 1;
      } else if (state.seq - 0x8000 > seq) {
        roc = state.roc + 1;
      }
      if (roc < 0) return null;
    }

    if (!crypto.timingSafeEqual(authTag(this.keys, body, roc), tag)) return null;

    // Only authenticated packets move the receive state forward.
    if (!state || roc > state.roc || (roc === state.roc && seq > state.seq)) this.recv.set(ssrc, { roc, seq });
    const index = roc * 0x10000 + seq;
    return Buffer.concat([body.subarray(0, hlen), applyKeystream(this.keys, ssrc, index, body.subarray(hlen))]);
  }
}
