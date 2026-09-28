// End-to-end: a werift peer plays the browser (WebSocket signalling + WebRTC), the real
// MediaGateway + SipUA sit in the middle, and a scripted fake Asterisk answers on 127.0.0.1.
// Checks audio in both directions byte-for-byte, transcoding, mute, DTMF, hangup, inbound calls.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SipUA } from '../server/sip/SipUA.ts';
import dgram from 'node:dgram';
import { transcode } from '../server/media/g711.ts';
import { RtpEndpoint } from '../server/media/RtpEndpoint.ts';
import { buildRtp } from '../server/media/rtp.ts';
import { inboundInvite, startFakePbx } from './fakePbx.ts';
import { accountFor, setup, until } from './harness.ts';

test('outbound call: browser <-> gateway <-> PBX audio both ways, mute, DTMF, hangup', { timeout: 30000 }, async () => {
  const h = await setup();
  try {
    h.send({ type: 'dial', number: '0300 1234567' });
    const active = await h.waitStatus((s) => s.call.state === 'active', 'call active');
    assert.equal(active.call.codec, 'PCMA');
    assert.equal(active.call.browserCodec, 'PCMA');
    const invite = await h.pbx.waitFor((m) => m.method === 'INVITE' && /Authorization/i.test([...m.headers.keys()].join()));
    assert.equal(invite.uri, `sip:03001234567@127.0.0.1:${h.pbx.port}`);
    assert.match(invite.body, /m=audio \d+ RTP\/AVP 8 0 101/, 'browser law offered first');

    // Browser -> PBX: payload bytes arrive untouched as plain RTP, PT 8.
    const frame = Buffer.alloc(160, 0x2a);
    for (let i = 1; i <= 5; i++) h.sendFromBrowser(frame, i);
    const up = await until(h.pbx.waitForRtp((p) => p.payload[0] === 0x2a), 5000, 'browser audio at PBX');
    assert.equal(up.pt, 8);
    assert.deepEqual(up.payload, frame);

    // PBX -> browser.
    const down = Buffer.alloc(160, 0x77);
    for (let i = 1; i <= 5; i++) h.pbx.sendRtp(down, 8, 100 + i, 5000 + i * 160);
    const got = await h.waitReceived((p) => p.payload[0] === 0x77, 'PBX audio in browser');
    assert.equal(got.header.payloadType, 8);
    assert.deepEqual(got.payload, down);

    // Mute: the gateway sends A-law silence instead of the mic.
    h.send({ type: 'mute', muted: true });
    await h.waitStatus((s) => s.call.muted === true, 'muted');
    for (let i = 6; i <= 10; i++) h.sendFromBrowser(Buffer.alloc(160, 0x33), i);
    await until(h.pbx.waitForRtp((p) => p.pt === 8 && p.payload.every((b) => b === 0xd5)), 5000, 'silence while muted');
    assert.ok(!h.pbx.rtpPackets.some((p) => p.payload[0] === 0x33), 'muted audio never reaches the PBX');
    h.send({ type: 'mute', muted: false });

    // DTMF over RFC 4733.
    h.send({ type: 'dtmf', digit: '5' });
    const dtmf = await until(h.pbx.waitForRtp((p) => p.pt === 101), 5000, 'DTMF');
    assert.equal(dtmf.payload[0], 5);

    h.send({ type: 'hangup' });
    await h.waitStatus((s) => s.call.state === 'idle', 'idle after hangup');
    const bye = await until(h.pbx.waitFor((m) => m.method === 'BYE'), 5000, 'BYE');
    assert.equal(bye.uri, `sip:pbx@127.0.0.1:${h.pbx.port}`, 'BYE goes to the Contact of the 200 OK');
  } finally {
    await h.close();
  }
});

test('PBX answers with PCMU: gateway transcodes to the browser leg PCMA', { timeout: 30000 }, async () => {
  const h = await setup();
  h.pbx.answerCodec = { pt: 0, name: 'PCMU' };
  try {
    h.send({ type: 'dial', number: '1002' });
    const active = await h.waitStatus((s) => s.call.state === 'active', 'call active');
    assert.equal(active.call.codec, 'PCMU');

    const alaw = Buffer.alloc(160, 0x2a);
    for (let i = 1; i <= 5; i++) h.sendFromBrowser(alaw, i);
    const up = await until(h.pbx.waitForRtp((p) => p.pt === 0), 5000, 'PCMU at PBX');
    assert.deepEqual(up.payload, transcode(alaw, 'PCMA', 'PCMU'));

    const ulaw = Buffer.alloc(160, 0x77);
    for (let i = 1; i <= 5; i++) h.pbx.sendRtp(ulaw, 0, 100 + i, 5000 + i * 160);
    const expected = transcode(ulaw, 'PCMU', 'PCMA');
    const got = await h.waitReceived((p) => p.payload[0] === expected[0], 'transcoded audio in browser');
    assert.equal(got.header.payloadType, 8);
    assert.deepEqual(got.payload, expected);
    h.send({ type: 'hangup' });
    await h.waitStatus((s) => s.call.state === 'idle', 'idle');
  } finally {
    await h.close();
  }
});

test('inbound call: ringing in the browser, accept, remote BYE', { timeout: 30000 }, async () => {
  const h = await setup();
  try {
    h.pbx.sendRequest(inboundInvite(h.pbx, h.ua.localPort, 'in1'), h.ua.localPort);
    const ringing = await h.waitStatus((s) => s.call.state === 'incoming', 'incoming');
    assert.equal(ringing.call.number, '1002');
    assert.equal(ringing.call.display, 'Front Desk');
    await until(h.pbx.waitFor((m) => m.status === 180), 5000, '180 Ringing');

    h.send({ type: 'accept' });
    const ok = await until(h.pbx.waitFor((m) => m.status === 200 && m.body.includes('m=audio')), 5000, '200 OK');
    assert.match(ok.body, /RTP\/AVP 8 101/);
    await h.waitStatus((s) => s.call.state === 'active', 'active');

    h.sendFromBrowser(Buffer.alloc(160, 0x2b), 1);
    h.sendFromBrowser(Buffer.alloc(160, 0x2b), 2);
    await until(h.pbx.waitForRtp((p) => p.payload[0] === 0x2b), 5000, 'audio at PBX');

    const bye = [
      `BYE sip:1001@127.0.0.1:${h.ua.localPort} SIP/2.0`,
      `Via: SIP/2.0/UDP 127.0.0.1:${h.pbx.port};branch=z9hG4bKbye1`,
      'From: "Front Desk" <sip:1002@127.0.0.1>;tag=fromin1',
      `To: ${ok.headers.get('to')![0]}`,
      'Call-ID: in1',
      'CSeq: 103 BYE',
      'Content-Length: 0',
      '',
      '',
    ].join('\r\n');
    h.pbx.sendRequest(bye, h.ua.localPort);
    const idle = await h.waitStatus((s) => s.call.state === 'idle', 'idle');
    assert.equal(idle.call.reason, 'The other party hung up.');
  } finally {
    await h.close();
  }
});

test('inbound call with no browser connected is rejected with 480', { timeout: 15000 }, async () => {
  const h = await setup({ connectBrowser: false });
  try {
    h.pbx.sendRequest(inboundInvite(h.pbx, h.ua.localPort, 'in2'), h.ua.localPort);
    await until(h.pbx.waitFor((m) => m.status === 480), 5000, '480');
  } finally {
    await h.close();
  }
});

test('wrong secret: registration fails after one authenticated attempt, no retry (fail2ban)', { timeout: 15000 }, async () => {
  const pbx = await startFakePbx();
  const ua = new SipUA();
  try {
    const result = new Promise<{ state: string; error?: string }>((resolve) =>
      ua.on('registration', (r) => (r.state === 'registered' || r.state === 'failed') && resolve(r)),
    );
    await ua.start(accountFor(pbx, { password: 'nope' }));
    const r = await until(result, 5000, 'registration result');
    assert.equal(r.state, 'failed');
    assert.match(r.error ?? '', /Authentication failed/);
    await new Promise((res) => setTimeout(res, 500));
    assert.equal(pbx.requests.filter((m) => m.method === 'REGISTER').length, 2);
  } finally {
    await ua.stop();
    pbx.close();
  }
});

test('one-way audio fix: PBX media arrives from another address than its SDP says, gateway latches (symmetric RTP)', { timeout: 30000 }, async () => {
  const h = await setup();
  // Like an Issabel with a wrong externip/localnet: the SDP points somewhere the PBX doesn't listen.
  const blackhole = dgram.createSocket('udp4');
  await new Promise<void>((r) => blackhole.bind(0, '127.0.0.1', r));
  let lost = 0;
  blackhole.on('message', () => lost++);
  h.pbx.sdpRtpPort = blackhole.address().port;
  try {
    h.send({ type: 'dial', number: '1002' });
    await h.waitStatus((s) => s.call.state === 'active', 'active');
    h.sendFromBrowser(Buffer.alloc(160, 0x11), 1);
    await new Promise((r) => setTimeout(r, 200));
    assert.ok(lost > 0, 'before latching, our audio goes to the SDP address (and is lost)');
    assert.equal(h.pbx.rtpPackets.length, 0);

    // The PBX's audio reaches us from its real port...
    for (let i = 1; i <= 3; i++) h.pbx.sendRtp(Buffer.alloc(160, 0x77), 8, i, i * 160);
    await h.waitReceived((p) => p.payload[0] === 0x77, 'PBX audio in browser');
    // ...so the browser's audio now goes back there and the other party hears us.
    for (let i = 2; i <= 6; i++) h.sendFromBrowser(Buffer.alloc(160, 0x22), i);
    await until(h.pbx.waitForRtp((p) => p.payload[0] === 0x22), 5000, 'browser audio at the real PBX port');
    assert.equal(h.ua.mediaStats!.sendTo, `127.0.0.1:${h.pbx.rtpPort}`);
    assert.equal(h.ua.mediaStats!.sdpTarget, `127.0.0.1:${blackhole.address().port}`);
    h.send({ type: 'hangup' });
  } finally {
    blackhole.close();
    await h.close();
  }
});

test('symmetric RTP never latches onto (or plays) packets from an unknown host', async () => {
  const ep = new RtpEndpoint();
  const port = await ep.open(30000, 40000);
  const played: number[] = [];
  ep.on('audio', (p) => played.push(p.seq));
  const stranger = dgram.createSocket('udp4');
  try {
    ep.configure({ remoteIp: '10.255.255.1', remotePort: 4000, codec: 'PCMA', pt: 8, dtmfPt: null, sendEnabled: true, latchHosts: ['10.255.255.2'] });
    stranger.send(buildRtp({ pt: 8, marker: false, seq: 1, timestamp: 0, ssrc: 1, payload: Buffer.alloc(160) }), port, '127.0.0.1');
    await new Promise((r) => setTimeout(r, 150));
    assert.equal(ep.stats.ignored, 1);
    assert.equal(ep.latched, null);
    assert.deepEqual(ep.sendTo, { address: '10.255.255.1', port: 4000 });
    assert.deepEqual(played, []);

    ep.configure({ remoteIp: '10.255.255.1', remotePort: 4000, codec: 'PCMA', pt: 8, dtmfPt: null, sendEnabled: true, latchHosts: ['127.0.0.1'] });
    stranger.send(buildRtp({ pt: 8, marker: false, seq: 2, timestamp: 160, ssrc: 1, payload: Buffer.alloc(160) }), port, '127.0.0.1');
    await new Promise((r) => setTimeout(r, 150));
    assert.equal(ep.sendTo?.address, '127.0.0.1', 'the PBX host may move the media port');
    assert.deepEqual(played, [2]);
  } finally {
    stranger.close();
    ep.close();
  }
});
