// SDP offer/answer (RFC 4566 / RFC 3264) for the single audio stream towards Asterisk: plain
// RTP (RTP/AVP) or SDES-keyed SRTP (RTP/SAVP + a=crypto, RFC 4568).
// Only G.711 is offered: the gateway relays G.711 payloads between Asterisk and the browser
// without decoding them (see media/g711.ts for the µ-law <-> A-law fallback).

import { MASTER_KEY_LEN, MASTER_SALT_LEN, SRTP_SUITE } from '../media/srtp.ts';

export type CodecName = 'PCMU' | 'PCMA';
export type Direction = 'sendrecv' | 'sendonly' | 'recvonly' | 'inactive';

export const CODECS: Record<CodecName, { name: CodecName; pt: number; clockRate: number }> = {
  PCMU: { name: 'PCMU', pt: 0, clockRate: 8000 },
  PCMA: { name: 'PCMA', pt: 8, clockRate: 8000 },
};
export const DTMF_PT = 101;

export const isCodecName = (s: string): s is CodecName => s === 'PCMU' || s === 'PCMA';

const STATIC_PT: Record<number, { name: string; clockRate: number }> = {
  0: { name: 'PCMU', clockRate: 8000 },
  8: { name: 'PCMA', clockRate: 8000 },
};

export interface BuildSdpInput {
  ip: string;
  port: number;
  sessionId: number;
  version: number;
  /** Codecs in preference order, with the payload type to advertise. */
  codecs: Array<{ name: CodecName; pt: number }>;
  dtmfPt?: number | null;
  direction?: Direction;
  /** SDES key for SRTP (our sending key), or null/undefined for plain RTP. */
  crypto?: { tag: number; keyB64: string } | null;
}

export function buildSdp({ ip, port, sessionId, version, codecs, dtmfPt = DTMF_PT, direction = 'sendrecv', crypto = null }: BuildSdpInput): string {
  const pts = [...codecs.map((c) => c.pt), ...(dtmfPt != null ? [dtmfPt] : [])];
  const lines = [
    'v=0',
    `o=- ${sessionId} ${version} IN IP4 ${ip}`,
    's=ArzenGateway',
    `c=IN IP4 ${ip}`,
    't=0 0',
    `m=audio ${port} ${crypto ? 'RTP/SAVP' : 'RTP/AVP'} ${pts.join(' ')}`,
  ];
  for (const c of codecs) lines.push(`a=rtpmap:${c.pt} ${c.name}/8000`);
  if (dtmfPt != null) lines.push(`a=rtpmap:${dtmfPt} telephone-event/8000`, `a=fmtp:${dtmfPt} 0-16`);
  lines.push('a=ptime:20');
  if (crypto) lines.push(`a=crypto:${crypto.tag} ${SRTP_SUITE} inline:${crypto.keyB64}`);
  lines.push(`a=${direction}`);
  return `${lines.join('\r\n')}\r\n`;
}

export interface CryptoLine {
  tag: number;
  suite: string;
  /** base64 master key || salt */
  keyB64: string;
  /** Lifetime / MKI suffix after the key ('|2^31|1:4'), '' when absent. */
  keyParams: string;
  /** Session parameters after the key-params (e.g. UNENCRYPTED_SRTP). */
  sessionParams: string[];
}

export interface RemoteMedia {
  ip: string;
  port: number;
  proto: string;
  formats: number[];
  rtpmap: Record<number, { name: string; clockRate: number; channels: number }>;
  direction: Direction;
  /** True for RTP/SAVP (SRTP required). */
  secure: boolean;
  crypto: CryptoLine[];
}

const DIRECTIONS = new Set<string>(['sendrecv', 'sendonly', 'recvonly', 'inactive']);

/** Parse the first m=audio section of an SDP body. Returns null when there is none. */
export function parseSdp(text = ''): RemoteMedia | null {
  if (!text.trim()) return null;
  let sessionIp: string | null = null;
  let sessionDirection: Direction = 'sendrecv';
  let media: (Omit<RemoteMedia, 'ip' | 'direction' | 'secure'> & { ip: string | null; direction: Direction | null }) | null = null;

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    const type = line[0];
    const value = line.slice(2);
    if (type === 'm') {
      if (media) break; // only the first audio stream matters
      const [kind, port, proto, ...fmts] = value.split(/\s+/);
      if (kind !== 'audio') continue;
      media = { port: Number(port), proto, formats: fmts.map(Number), rtpmap: {}, crypto: [], ip: null, direction: null };
    } else if (type === 'c') {
      const ip = value.split(/\s+/)[2];
      if (media) media.ip = ip;
      else sessionIp = ip;
    } else if (type === 'a') {
      const [attr, ...rest] = value.split(':');
      const arg = rest.join(':');
      if (DIRECTIONS.has(attr)) {
        if (media) media.direction = attr as Direction;
        else sessionDirection = attr as Direction;
      } else if (media && attr === 'crypto') {
        // a=crypto:<tag> <suite> inline:<key||salt>[|lifetime][|MKI:len] [session params]
        const m = /^(\d+)\s+(\S+)\s+inline:([^|\s]+)(\S*)\s*(.*)$/.exec(arg);
        if (m) media.crypto.push({ tag: Number(m[1]), suite: m[2], keyB64: m[3], keyParams: m[4], sessionParams: m[5].split(/\s+/).filter(Boolean) });
      } else if (media && attr === 'rtpmap') {
        const m = /^(\d+)\s+([^/]+)\/(\d+)(?:\/(\d+))?/.exec(arg);
        if (m) media.rtpmap[Number(m[1])] = { name: m[2], clockRate: Number(m[3]), channels: m[4] ? Number(m[4]) : 1 };
      }
    }
  }
  if (!media) return null;
  const ip = media.ip ?? sessionIp;
  if (!ip) return null;
  return { ...media, ip, direction: media.direction ?? sessionDirection, secure: /SAVP/i.test(media.proto) };
}

export interface Negotiated {
  codec: { name: CodecName; pt: number };
  dtmfPt: number | null;
}

/**
 * Choose the codec for a call, returning the REMOTE payload numbers.
 *   preferred:   our codec names in preference order
 *   remoteOrder: true when `remote` is an answer (the answerer already chose, so honour its order)
 */
export function negotiate(remote: RemoteMedia, preferred: CodecName[], { remoteOrder = false } = {}): Negotiated | null {
  const offered = remote.formats
    .map((pt) => {
      const map = remote.rtpmap[pt] ?? STATIC_PT[pt];
      return map ? { pt, name: map.name, clockRate: map.clockRate } : null;
    })
    .filter((o): o is { pt: number; name: string; clockRate: number } => o !== null);

  const ours = (name: string): CodecName | undefined => preferred.find((p) => p.toLowerCase() === name.toLowerCase());
  let codec: Negotiated['codec'] | null = null;
  if (remoteOrder) {
    const hit = offered.find((o) => o.clockRate === 8000 && ours(o.name));
    if (hit) codec = { name: ours(hit.name)!, pt: hit.pt };
  } else {
    for (const name of preferred) {
      const hit = offered.find((o) => o.name.toLowerCase() === name.toLowerCase() && o.clockRate === 8000);
      if (hit) {
        codec = { name, pt: hit.pt };
        break;
      }
    }
  }
  if (!codec) return null;

  const dtmf = offered.find((o) => o.name.toLowerCase() === 'telephone-event' && o.clockRate === 8000);
  return { codec, dtmfPt: dtmf ? dtmf.pt : null };
}

/**
 * Pick the a=crypto line we can use: AES_CM_128_HMAC_SHA1_80, a 30-byte key, no MKI and no
 * session parameters (UNENCRYPTED_SRTP and friends would weaken or change the profile).
 */
export function pickCrypto(remote: RemoteMedia): CryptoLine | null {
  return (
    remote.crypto.find((c) => {
      if (c.suite !== SRTP_SUITE || c.sessionParams.length) return false;
      if (c.keyParams.split('|').some((p) => p.includes(':'))) return false; // MKI
      return Buffer.from(c.keyB64, 'base64').length === MASTER_KEY_LEN + MASTER_SALT_LEN;
    }) ?? null
  );
}
