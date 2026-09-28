// A tiny scripted "Asterisk" on 127.0.0.1 for tests: real sockets for SIP (UDP or TLS) and RTP.
// It digest-challenges REGISTER and initial INVITEs, answers calls with a configurable codec,
// and records every SIP message and RTP packet it receives.
//
// With `srtp: true` its SDP is RTP/SAVP with an a=crypto key, and its media is SRTP done by
// werift's SrtpSession: an implementation independent of server/media/srtp.ts, so the tests
// prove interoperability rather than agreement with ourselves.
import dgram from 'node:dgram';
import fs from 'node:fs';
import path from 'node:path';
import tls from 'node:tls';
import { ProtectionProfileAes128CmHmacSha1_80, RtpHeader, SrtpSession } from 'werift';
import { buildMessage, buildResponse, getHeader, getHeaders, parseMessage, type ResponseOptions, type SipMessage } from '../server/sip/message.ts';
import { buildAuthorization, parseChallenge } from '../server/sip/digest.ts';
import { parseSdp, pickCrypto } from '../server/sip/sdp.ts';
import { SipStreamParser } from '../server/sip/transport.ts';
import { generateMasterKey } from '../server/media/srtp.ts';
import { parseRtp, type RtpInfo } from '../server/media/rtp.ts';

export const PASSWORD = 's3cret';
const NONCE = 'abc123';
const FIXTURES = path.join(import.meta.dirname, 'fixtures');
export const PBX_CERT = path.join(FIXTURES, 'pbx-cert.pem');
const PBX_KEY = path.join(FIXTURES, 'pbx-key.pem');

/** A received SIP message plus a way to answer it on the connection it came in on. */
export type PbxMessage = SipMessage & { send: (text: string) => void };

export interface FakePbxOptions {
  transport?: 'udp' | 'tls';
  srtp?: boolean;
}

export interface FakePbx {
  port: number;
  rtpPort: number;
  requests: PbxMessage[];
  /** Decrypted (if SRTP) RTP packets received from the gateway. */
  rtpPackets: RtpInfo[];
  /** Raw datagrams as they arrived on the wire. */
  rawRtp: Buffer[];
  /** SRTP packets that failed authentication. */
  badSrtp: number;
  /** TLS connections accepted so far. */
  connections: number;
  lastRtpFrom?: dgram.RemoteInfo;
  /** The PBX's own SRTP key (what it puts in a=crypto). */
  srtpKey: string;
  answerCodec: { pt: number; name: string };
  answerDelay: number;
  /** Media port to advertise in SDP instead of the real one (simulates a misconfigured externip / NAT). */
  sdpRtpPort?: number;
  /** The gateway's RTP port, from its SDP. */
  gatewayRtpPort?: number;
  waitFor(pred: (m: PbxMessage) => boolean): Promise<PbxMessage>;
  waitForRtp(pred: (p: RtpInfo) => boolean): Promise<RtpInfo>;
  sdp(dir?: string): string;
  sendRtp(payload: Buffer, pt: number, seq: number, timestamp: number): void;
  reply(req: PbxMessage, status: number, reason: string, opts?: ResponseOptions): void;
  /** Send a request to the gateway (UDP: to `port`; TLS: over the latest connection). */
  sendRequest(text: string, port: number): void;
  /** TLS: drop every connection (simulates a PBX restart / network blip). */
  dropConnections(): void;
  close(): void;
}

export async function startFakePbx({ transport = 'udp', srtp = false }: FakePbxOptions = {}): Promise<FakePbx> {
  const rtp = dgram.createSocket('udp4');
  await new Promise<void>((r) => rtp.bind(0, '127.0.0.1', r));
  let waiters: Array<{ pred: (m: PbxMessage) => boolean; resolve: (m: PbxMessage) => void }> = [];
  let rtpWaiters: Array<{ pred: (p: RtpInfo) => boolean; resolve: (p: RtpInfo) => void }> = [];
  let session: SrtpSession | null = null;
  let sessionRemoteKey = '';
  const tlsSockets = new Set<tls.TLSSocket>();
  let lastTls: tls.TLSSocket | null = null;

  const checkAuth = (req: SipMessage): boolean => {
    const c = parseChallenge(getHeader(req, 'authorization'));
    if (!c) return false;
    const expected = buildAuthorization({ challenge: { realm: 'asterisk', nonce: NONCE }, method: req.method, uri: c.uri, username: '1001', password: PASSWORD }).response;
    return c.response === expected;
  };

  /** Key the SRTP session with the gateway's a=crypto from any SDP it sends us. */
  const learnGatewayKey = (msg: SipMessage): void => {
    if (!srtp || !msg.body) return;
    const remote = parseSdp(msg.body);
    const line = remote && pickCrypto(remote);
    if (!line || line.keyB64 === sessionRemoteKey) return;
    sessionRemoteKey = line.keyB64;
    const local = Buffer.from(pbx.srtpKey, 'base64');
    const theirs = Buffer.from(line.keyB64, 'base64');
    session = new SrtpSession({
      profile: ProtectionProfileAes128CmHmacSha1_80,
      keys: {
        localMasterKey: local.subarray(0, 16),
        localMasterSalt: local.subarray(16),
        remoteMasterKey: theirs.subarray(0, 16),
        remoteMasterSalt: theirs.subarray(16),
      },
    });
  };

  const pbx: FakePbx = {
    port: 0,
    rtpPort: rtp.address().port,
    requests: [],
    rtpPackets: [],
    rawRtp: [],
    badSrtp: 0,
    connections: 0,
    srtpKey: generateMasterKey(),
    answerCodec: { pt: 8, name: 'PCMA' },
    answerDelay: 50,
    waitFor: (pred) =>
      new Promise((resolve) => {
        const hit = pbx.requests.find(pred);
        if (hit) resolve(hit);
        else waiters.push({ pred, resolve });
      }),
    waitForRtp: (pred) =>
      new Promise((resolve) => {
        const hit = pbx.rtpPackets.find(pred);
        if (hit) resolve(hit);
        else rtpWaiters.push({ pred, resolve });
      }),
    sdp: (dir = 'sendrecv') =>
      [
        'v=0', 'o=- 1 1 IN IP4 127.0.0.1', 's=Asterisk', 'c=IN IP4 127.0.0.1', 't=0 0',
        `m=audio ${pbx.sdpRtpPort ?? pbx.rtpPort} ${srtp ? 'RTP/SAVP' : 'RTP/AVP'} ${pbx.answerCodec.pt} 101`,
        `a=rtpmap:${pbx.answerCodec.pt} ${pbx.answerCodec.name}/8000`,
        'a=rtpmap:101 telephone-event/8000',
        // Like Asterisk: an 80-bit and a 32-bit tag suite; the gateway must pick the _80 one.
        ...(srtp ? [`a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:${pbx.srtpKey}`, `a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:${generateMasterKey()}`] : []),
        `a=${dir}`, '',
      ].join('\r\n'),
    sendRtp: (payload, pt, seq, timestamp) => {
      const to = pbx.lastRtpFrom ?? (pbx.gatewayRtpPort ? { port: pbx.gatewayRtpPort } : null);
      if (!to) throw new Error('No RTP from the gateway yet: unknown port');
      let packet: Buffer;
      if (srtp) {
        if (!session) throw new Error('No SRTP session: the gateway has not sent its key');
        packet = session.encrypt(payload, new RtpHeader({ payloadType: pt, sequenceNumber: seq, timestamp, ssrc: 0x01020304 }));
      } else {
        const h = Buffer.from([0x80, pt, (seq >> 8) & 0xff, seq & 0xff, 0, 0, 0, 0, 1, 2, 3, 4]);
        h.writeUInt32BE(timestamp, 4);
        packet = Buffer.concat([h, payload]);
      }
      rtp.send(packet, to.port, '127.0.0.1');
    },
    reply: (req, status, reason, opts) => req.send(buildResponse(req, status, reason, opts)),
    sendRequest: (text, port) => {
      if (transport === 'tls') lastTls?.write(text);
      else udp?.send(text, port, '127.0.0.1');
    },
    dropConnections: () => {
      for (const s of tlsSockets) s.destroy();
    },
    close: () => {
      udp?.close();
      for (const s of tlsSockets) s.destroy();
      tlsServer?.close();
      rtp.close();
    },
  };

  const onSip = (buf: Buffer, send: (text: string) => void): void => {
    const parsed = parseMessage(buf);
    if (!parsed) return;
    const msg: PbxMessage = Object.assign(parsed, { send });
    pbx.requests.push(msg);
    learnGatewayKey(msg);
    const media = msg.body ? parseSdp(msg.body) : null;
    if (media) pbx.gatewayRtpPort = media.port;
    if (msg.isRequest) {
      const initialInvite = msg.method === 'INVITE' && !/tag=/.test(getHeader(msg, 'to') ?? '');
      if ((msg.method === 'REGISTER' || initialInvite) && !checkAuth(msg)) {
        pbx.reply(msg, 401, 'Unauthorized', { toTag: 'pbxtag', extraHeaders: [['WWW-Authenticate', `Digest realm="asterisk", nonce="${NONCE}", algorithm=MD5`]] });
      } else if (msg.method === 'REGISTER') {
        pbx.reply(msg, 200, 'OK', { toTag: 'regtag', extraHeaders: [['Contact', getHeaders(msg, 'contact')[0]], ['Expires', '120']] });
      } else if (msg.method === 'INVITE') {
        pbx.reply(msg, 100, 'Trying');
        pbx.reply(msg, 180, 'Ringing', { toTag: 'calltag' });
        setTimeout(
          () => pbx.reply(msg, 200, 'OK', { toTag: 'calltag', extraHeaders: [['Contact', `<sip:pbx@127.0.0.1:${pbx.port}>`], ['Content-Type', 'application/sdp']], body: pbx.sdp() }),
          pbx.answerDelay,
        );
      } else if (msg.method === 'BYE' || msg.method === 'CANCEL') {
        pbx.reply(msg, 200, 'OK');
      }
    }
    waiters = waiters.filter((w) => (w.pred(msg) ? (w.resolve(msg), false) : true));
  };

  let udp: dgram.Socket | null = null;
  let tlsServer: tls.Server | null = null;
  if (transport === 'udp') {
    const sock = dgram.createSocket('udp4');
    await new Promise<void>((r) => sock.bind(0, '127.0.0.1', r));
    sock.on('message', (buf, rinfo) => onSip(buf, (text) => sock.send(text, rinfo.port, rinfo.address)));
    udp = sock;
    pbx.port = sock.address().port;
  } else {
    const server = tls.createServer({ key: fs.readFileSync(PBX_KEY), cert: fs.readFileSync(PBX_CERT) }, (socket) => {
      pbx.connections++;
      tlsSockets.add(socket);
      lastTls = socket;
      const parser = new SipStreamParser();
      socket.on('data', (chunk: Buffer) => {
        for (const m of parser.push(chunk)) onSip(m, (text) => socket.write(text));
      });
      socket.on('error', () => {});
      socket.on('close', () => tlsSockets.delete(socket));
    });
    server.on('tlsClientError', () => {}); // clients that reject our certificate
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    tlsServer = server;
    pbx.port = (server.address() as { port: number }).port;
  }

  rtp.on('message', (buf, rinfo) => {
    pbx.rawRtp.push(buf);
    pbx.lastRtpFrom = rinfo;
    let plain: Buffer = buf;
    if (srtp) {
      if (!session) return;
      try {
        plain = session.decrypt(buf);
      } catch {
        pbx.badSrtp++;
        return;
      }
    }
    const pkt = parseRtp(plain);
    if (!pkt) return;
    pbx.rtpPackets.push(pkt);
    rtpWaiters = rtpWaiters.filter((w) => (w.pred(pkt) ? (w.resolve(pkt), false) : true));
  });

  return pbx;
}

/** An inbound INVITE from the PBX towards the UA at `uaPort`. */
export function inboundInvite(pbx: FakePbx, uaPort: number, callId: string, transport: 'UDP' | 'TLS' = 'UDP'): string {
  return buildMessage({
    startLine: `INVITE sip:1001@127.0.0.1:${uaPort} SIP/2.0`,
    headers: [
      ['Via', `SIP/2.0/${transport} 127.0.0.1:${pbx.port};branch=z9hG4bK${callId};rport`],
      ['From', `"Front Desk" <sip:1002@127.0.0.1>;tag=from${callId}`],
      ['To', '<sip:1001@127.0.0.1>'],
      ['Call-ID', callId],
      ['CSeq', '102 INVITE'],
      ['Contact', `<sip:1002@127.0.0.1:${pbx.port}>`],
      ['Content-Type', 'application/sdp'],
    ],
    body: pbx.sdp(),
  });
}
