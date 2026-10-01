// End-to-end harness: fake Asterisk (fakePbx.ts) <-> real SipUA + MediaGateway <-> a werift peer
// playing the browser over the real WebSocket signalling.
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { WebSocket, WebSocketServer } from 'ws';
import { MediaStreamTrack, RTCPeerConnection, RTCRtpCodecParameters, RtpHeader, RtpPacket } from 'werift';
import { MediaGateway } from '../server/MediaGateway.ts';
import { SipUA, type SipAccount } from '../server/sip/SipUA.ts';
import type { ClientMessage, GatewayStatus, LiveCall, ServerMessage } from '../shared/protocol.ts';
import type { Supervisor } from '../server/ami/Supervisor.ts';
import { PASSWORD, PBX_CERT, startFakePbx, type FakePbx } from './fakePbx.ts';

export const until = <T>(p: Promise<T>, ms: number, what: string): Promise<T> =>
  Promise.race([p, new Promise<T>((_, reject) => setTimeout(() => reject(new Error(`timeout waiting for ${what}`)), ms))]);

/** SipAccount for a UA talking to `pbx` (TLS trusts the fixture certificate). */
export function accountFor(pbx: FakePbx, { transport = 'udp', srtp = false, password = PASSWORD }: { transport?: 'udp' | 'tls'; srtp?: boolean; password?: string } = {}): SipAccount {
  return {
    server: '127.0.0.1', serverPort: pbx.port, transport, srtp, extension: '1001', password,
    tls: { rejectUnauthorized: true, caFile: PBX_CERT },
    localPort: 0, localIp: '127.0.0.1', codecs: ['PCMA', 'PCMU'], rtpPortMin: 30000, rtpPortMax: 40000,
  };
}

export interface Harness {
  pbx: FakePbx;
  ua: SipUA;
  gw: MediaGateway;
  send(msg: ClientMessage): void;
  waitStatus(pred: (s: GatewayStatus) => boolean, what: string): Promise<GatewayStatus>;
  /** Packets the "browser" received from the gateway. */
  received: RtpPacket[];
  waitReceived(pred: (p: RtpPacket) => boolean, what: string): Promise<RtpPacket>;
  sendFromBrowser(payload: Buffer, seq: number): void;
  /** Latest live calls board, and every error message, sent to the browser. */
  liveCalls: LiveCall[];
  errors: string[];
  waitLiveCalls(pred: (calls: LiveCall[]) => boolean, what: string): Promise<LiveCall[]>;
  waitError(pred: (message: string) => boolean, what: string): Promise<string>;
  close(): Promise<void>;
}

export interface HarnessOptions {
  connectBrowser?: boolean;
  /** Transport / SRTP of both the fake PBX and the UA. */
  transport?: 'udp' | 'tls';
  srtp?: boolean;
  /** Override the UA's SRTP setting (to test mismatches with the PBX). */
  uaSrtp?: boolean;
  supervisor?: Supervisor;
}

export async function setup({ connectBrowser = true, transport = 'udp', srtp = false, uaSrtp = srtp, supervisor }: HarnessOptions = {}): Promise<Harness> {
  const pbx = await startFakePbx({ transport, srtp });
  const ua = new SipUA();
  const registered = new Promise<void>((resolve) => ua.on('registration', (r) => r.state === 'registered' && resolve()));
  await ua.start(accountFor(pbx, { transport, srtp: uaSrtp }));
  await until(registered, 5000, 'registration');

  const gw = new MediaGateway(ua, { extension: '1001', pbx: `127.0.0.1:${pbx.port}`, transport, encryption: uaSrtp, codecs: ['PCMA', 'PCMU'], supervisor });
  const server = http.createServer();
  const wss = new WebSocketServer({ server, path: '/ws' });
  wss.on('connection', (ws) => gw.handleSocket(ws));
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));

  let browser: RTCPeerConnection | null = null;
  let ws: WebSocket | null = null;
  const received: RtpPacket[] = [];
  let recvWaiters: Array<{ pred: (p: RtpPacket) => boolean; resolve: (p: RtpPacket) => void }> = [];
  let statusWaiters: Array<{ pred: (s: GatewayStatus) => boolean; resolve: (s: GatewayStatus) => void }> = [];
  let lastStatus: GatewayStatus | null = null;
  let callWaiters: Array<{ pred: (c: LiveCall[]) => boolean; resolve: (c: LiveCall[]) => void }> = [];
  let errorWaiters: Array<{ pred: (m: string) => boolean; resolve: (m: string) => void }> = [];
  const btrack = new MediaStreamTrack({ kind: 'audio' });

  const h: Harness = {
    pbx, ua, gw, received,
    liveCalls: [],
    errors: [],
    waitLiveCalls: (pred, what) =>
      until(
        new Promise((resolve) => {
          if (pred(h.liveCalls)) resolve(h.liveCalls);
          else callWaiters.push({ pred, resolve });
        }),
        5000,
        what,
      ),
    waitError: (pred, what) =>
      until(
        new Promise((resolve) => {
          const hit = h.errors.find(pred);
          if (hit) resolve(hit);
          else errorWaiters.push({ pred, resolve });
        }),
        5000,
        what,
      ),
    send: (msg) => ws!.send(JSON.stringify(msg)),
    waitStatus: (pred, what) =>
      until(
        new Promise((resolve) => {
          if (lastStatus && pred(lastStatus)) resolve(lastStatus);
          else statusWaiters.push({ pred, resolve });
        }),
        5000,
        what,
      ),
    waitReceived: (pred, what) =>
      until(
        new Promise((resolve) => {
          const hit = received.find(pred);
          if (hit) resolve(hit);
          else recvWaiters.push({ pred, resolve });
        }),
        5000,
        what,
      ),
    sendFromBrowser: (payload, seq) => btrack.writeRtp(new RtpPacket(new RtpHeader({ payloadType: 8, sequenceNumber: seq, timestamp: seq * 160 }), payload)),
    close: async () => {
      ws?.close();
      await browser?.close();
      await gw.close();
      await ua.stop();
      wss.close();
      server.close();
      pbx.close();
    },
  };

  if (!connectBrowser) return h;

  ws = new WebSocket(`ws://127.0.0.1:${(server.address() as AddressInfo).port}/ws`);
  const answer = new Promise<string>((resolve) => {
    ws!.on('message', (data) => {
      const msg = JSON.parse(data.toString()) as ServerMessage;
      if (msg.type === 'answer') resolve(msg.sdp);
      if (msg.type === 'liveCalls') {
        h.liveCalls = msg.calls;
        callWaiters = callWaiters.filter((w) => (w.pred(msg.calls) ? (w.resolve(msg.calls), false) : true));
      }
      if (msg.type === 'error') {
        h.errors.push(msg.message);
        errorWaiters = errorWaiters.filter((w) => (w.pred(msg.message) ? (w.resolve(msg.message), false) : true));
      }
      if (msg.type === 'status') {
        lastStatus = msg.status;
        statusWaiters = statusWaiters.filter((w) => (w.pred(msg.status) ? (w.resolve(msg.status), false) : true));
      }
    });
  });
  await new Promise((r) => ws!.once('open', r));
  h.send({ type: 'join' });

  // Offer like Chrome does: Opus first, G.711 as well.
  browser = new RTCPeerConnection({
    iceServers: [],
    codecs: {
      audio: [
        new RTCRtpCodecParameters({ mimeType: 'audio/opus', clockRate: 48000, channels: 2, payloadType: 111 }),
        new RTCRtpCodecParameters({ mimeType: 'audio/PCMU', clockRate: 8000, channels: 1, payloadType: 0 }),
        new RTCRtpCodecParameters({ mimeType: 'audio/PCMA', clockRate: 8000, channels: 1, payloadType: 8 }),
      ],
    },
  });
  browser.addTransceiver(btrack, { direction: 'sendrecv' });
  browser.onTrack.subscribe((t) =>
    t.onReceiveRtp.subscribe((p) => {
      received.push(p);
      recvWaiters = recvWaiters.filter((w) => (w.pred(p) ? (w.resolve(p), false) : true));
    }),
  );
  await browser.setLocalDescription(await browser.createOffer());
  h.send({ type: 'offer', sdp: browser.localDescription!.sdp });
  const sdp = await until(answer, 10000, 'SDP answer');
  assert.match(sdp, /m=audio \d+ UDP\/TLS\/RTP\/SAVPF 8\r\n/, 'gateway answers with PCMA only');
  await browser.setRemoteDescription({ type: 'answer', sdp });
  await h.waitStatus((s) => s.peer === 'connected', 'WebRTC connected');
  return h;
}
