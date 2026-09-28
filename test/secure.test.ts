// Encrypted mode: SRTP engine, SDES in SDP, SIP stream framing, SIP over TLS (trust, host
// name, reconnect) and full TLS + SRTP calls through the gateway.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ProtectionProfileAes128CmHmacSha1_80, RtpHeader, SrtpSession } from 'werift';
import { deriveSessionKeys, generateMasterKey, SrtpContext } from '../server/media/srtp.ts';
import { buildRtp } from '../server/media/rtp.ts';
import { buildSdp, parseSdp, pickCrypto } from '../server/sip/sdp.ts';
import { getHeader } from '../server/sip/message.ts';
import { SipStreamParser } from '../server/sip/transport.ts';
import { SipUA, type RegistrationInfo } from '../server/sip/SipUA.ts';
import { inboundInvite, startFakePbx } from './fakePbx.ts';
import { accountFor, setup, until } from './harness.ts';

// ---------------------------------------------------------------------------------------------
// SRTP engine

test('srtp: key derivation matches RFC 3711 Appendix B.3', () => {
  const master = Buffer.from('E1F97A0D3E018BE0D64FA32C06DE4139' + '0EC675AD498AFEEBB6960B3AABE6', 'hex');
  const k = deriveSessionKeys(master);
  assert.equal(k.cipherKey.toString('hex'), 'c61e7a93744f39ee10734afe3ff7a087');
  assert.equal(k.salt.toString('hex'), '30cbbc08863d8c85d49db34a9ae1');
  assert.equal(k.authKey.toString('hex'), 'cebe321f6ff7716b6fd4ab49af256a156d38baa4');
});

test('srtp: interoperates with werift in both directions across a sequence-number wrap (ROC)', () => {
  const ours = generateMasterKey();
  const theirs = generateMasterKey();
  const o = Buffer.from(ours, 'base64');
  const t = Buffer.from(theirs, 'base64');
  const werift = new SrtpSession({
    profile: ProtectionProfileAes128CmHmacSha1_80,
    keys: { localMasterKey: t.subarray(0, 16), localMasterSalt: t.subarray(16), remoteMasterKey: o.subarray(0, 16), remoteMasterSalt: o.subarray(16) },
  });
  const tx = new SrtpContext(ours);
  const rx = new SrtpContext(theirs);
  for (let i = 0; i < 1200; i++) {
    const seq = (65000 + i) & 0xffff; // wraps after 536 packets
    const plain = buildRtp({ pt: 8, marker: false, seq, timestamp: i * 160, ssrc: 0xabcdef, payload: Buffer.alloc(160, i & 0xff) });
    const wire = tx.protect(plain);
    assert.equal(wire.length, plain.length + 10, '80-bit auth tag');
    assert.notDeepEqual(wire.subarray(12, 172), plain.subarray(12), 'payload is encrypted');
    assert.deepEqual(werift.decrypt(wire), plain, `werift decrypts ours, packet ${i}`);

    const back = werift.encrypt(Buffer.alloc(160, 0x5a), new RtpHeader({ payloadType: 8, sequenceNumber: seq, timestamp: i * 160, ssrc: 42 }));
    const dec = rx.unprotect(back);
    assert.ok(dec, `we decrypt werift's, packet ${i}`);
    assert.equal(dec.readUInt16BE(2), seq);
    assert.ok(dec.subarray(12).every((b) => b === 0x5a));
  }
});

test('srtp: rejects tampered packets, wrong keys and plain RTP', () => {
  const key = generateMasterKey();
  const plain = buildRtp({ pt: 0, marker: true, seq: 7, timestamp: 1, ssrc: 9, payload: Buffer.alloc(160, 1) });
  const wire = new SrtpContext(key).protect(plain);
  assert.deepEqual(new SrtpContext(key).unprotect(wire), plain);
  for (const i of [1, 20, wire.length - 1]) {
    const bad = Buffer.from(wire);
    bad[i] ^= 0x01;
    assert.equal(new SrtpContext(key).unprotect(bad), null, `flipped byte ${i}`);
  }
  assert.equal(new SrtpContext(generateMasterKey()).unprotect(wire), null, 'wrong key');
  assert.equal(new SrtpContext(key).unprotect(plain), null, 'unauthenticated plain RTP');
});

// ---------------------------------------------------------------------------------------------
// SDP / SDES

test('sdp: SRTP offer uses RTP/SAVP with an a=crypto line', () => {
  const key = generateMasterKey();
  const sdp = buildSdp({ ip: '10.0.0.5', port: 12000, sessionId: 1, version: 1, codecs: [{ name: 'PCMA', pt: 8 }], crypto: { tag: 1, keyB64: key } });
  assert.match(sdp, /^m=audio 12000 RTP\/SAVP 8 101\r$/m);
  assert.match(sdp, new RegExp(`^a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:${key.replace(/[+/]/g, '\\$&')}\\r$`, 'm'));
  const parsed = parseSdp(sdp)!;
  assert.equal(parsed.secure, true);
  assert.deepEqual(pickCrypto(parsed), { tag: 1, suite: 'AES_CM_128_HMAC_SHA1_80', keyB64: key, keyParams: '', sessionParams: [] });
  assert.doesNotMatch(buildSdp({ ip: '1.1.1.1', port: 1, sessionId: 1, version: 1, codecs: [{ name: 'PCMU', pt: 0 }] }), /SAVP|crypto/);
});

test('sdp: picks the usable crypto line (Asterisk-style offers)', () => {
  const k = () => generateMasterKey();
  const offer = (lines: string[]) => parseSdp(['v=0', 'c=IN IP4 1.2.3.4', 'm=audio 4000 RTP/SAVP 8', ...lines, ''].join('\r\n'))!;
  // Asterisk offers the 32-bit tag suite too, sometimes first.
  assert.equal(pickCrypto(offer([`a=crypto:1 AES_CM_128_HMAC_SHA1_32 inline:${k()}`, `a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:${k()}`]))!.tag, 2);
  // A key lifetime is fine; MKI and weakening session params are not.
  assert.equal(pickCrypto(offer([`a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:${k()}|2^31`]))!.tag, 3);
  assert.equal(pickCrypto(offer([`a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:${k()}|2^20|1:4`])), null, 'MKI');
  assert.equal(pickCrypto(offer([`a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:${k()} UNENCRYPTED_SRTP`])), null, 'session param');
  assert.equal(pickCrypto(offer(['a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:c2hvcnQ='])), null, 'short key');
  assert.equal(pickCrypto(offer([`a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:${k()}`])), null, 'unsupported suite');
});

// ---------------------------------------------------------------------------------------------
// SIP over a stream

test('stream parser: split chunks, several messages per chunk, keep-alives, bodies', () => {
  const body = 'v=0\r\n';
  const a = `INVITE sip:x SIP/2.0\r\nCall-ID: a\r\nContent-Length: ${body.length}\r\n\r\n${body}`;
  const b = 'SIP/2.0 200 OK\r\nCall-ID: b\r\nl: 0\r\n\r\n';
  const stream = Buffer.from(`\r\n\r\n${a}${b}\r\n`);
  const p = new SipStreamParser();
  const out: string[] = [];
  for (let i = 0; i < stream.length; i += 7) out.push(...p.push(stream.subarray(i, i + 7)).map((m) => m.toString()));
  assert.deepEqual(out, [a, b]);
  assert.deepEqual(new SipStreamParser().push(Buffer.from(a + b)).map(String), [a, b], 'two in one chunk');
  assert.throws(() => new SipStreamParser().push(Buffer.alloc(70 * 1024, 0x41)), /too large/);
});

// ---------------------------------------------------------------------------------------------
// SIP over TLS

function waitReg(ua: SipUA, pred: (r: RegistrationInfo) => boolean): Promise<RegistrationInfo> {
  return new Promise((resolve) => {
    const h = (r: RegistrationInfo) => {
      if (pred(r)) {
        ua.off('registration', h);
        resolve(r);
      }
    };
    ua.on('registration', h);
  });
}

test('tls: registers over TLS with a trusted PBX certificate', { timeout: 15000 }, async () => {
  const pbx = await startFakePbx({ transport: 'tls' });
  const ua = new SipUA();
  try {
    const done = waitReg(ua, (r) => r.state === 'registered' || r.state === 'failed');
    await ua.start(accountFor(pbx, { transport: 'tls' }));
    assert.equal((await until(done, 5000, 'registration')).state, 'registered');
    assert.equal(ua.transportProtocol, 'TLS');
    const regs = pbx.requests.filter((m) => m.method === 'REGISTER');
    assert.equal(regs.length, 2, 'challenge + authenticated REGISTER on one connection');
    assert.equal(pbx.connections, 1);
    assert.match(getHeader(regs[1], 'via')!, /^SIP\/2\.0\/TLS 127\.0\.0\.1:\d+;/);
    assert.match(getHeader(regs[1], 'contact')!, new RegExp(`<sip:1001@127\\.0\\.0\\.1:${ua.localPort};transport=tls>`));
  } finally {
    await ua.stop();
    pbx.close();
  }
  // un-REGISTER on stop went over TLS as well
});

test('tls: untrusted self-signed certificate fails before any SIP is sent', { timeout: 15000 }, async () => {
  const pbx = await startFakePbx({ transport: 'tls' });
  const ua = new SipUA();
  try {
    const done = waitReg(ua, (r) => r.state === 'registered' || r.state === 'failed');
    await ua.start({ ...accountFor(pbx, { transport: 'tls' }), tls: { rejectUnauthorized: true } });
    const r = await until(done, 5000, 'registration');
    assert.equal(r.state, 'failed');
    assert.match(r.error!, /not trusted.*PBX_TLS_CA/);
    assert.equal(pbx.requests.length, 0, 'no SIP (and so no credentials hash) leaves the gateway');
  } finally {
    await ua.stop();
    pbx.close();
  }
});

test('tls: PBX_TLS_VERIFY=false accepts a self-signed certificate', { timeout: 15000 }, async () => {
  const pbx = await startFakePbx({ transport: 'tls' });
  const ua = new SipUA();
  try {
    const done = waitReg(ua, (r) => r.state === 'registered' || r.state === 'failed');
    await ua.start({ ...accountFor(pbx, { transport: 'tls' }), tls: { rejectUnauthorized: false } });
    assert.equal((await until(done, 5000, 'registration')).state, 'registered');
  } finally {
    await ua.stop();
    pbx.close();
  }
});

test('tls: certificate host name is checked (PBX_TLS_SERVERNAME)', { timeout: 15000 }, async () => {
  const pbx = await startFakePbx({ transport: 'tls' });
  try {
    for (const [servername, expected] of [['pbx.test', 'registered'], ['wrong.example', 'failed']] as const) {
      const ua = new SipUA();
      const done = waitReg(ua, (r) => r.state === 'registered' || r.state === 'failed');
      const base = accountFor(pbx, { transport: 'tls' });
      await ua.start({ ...base, tls: { ...base.tls!, servername } });
      const r = await until(done, 5000, `registration with ${servername}`);
      assert.equal(r.state, expected, servername);
      if (expected === 'failed') assert.match(r.error!, /does not match.*PBX_TLS_SERVERNAME/);
      await ua.stop();
    }
  } finally {
    pbx.close();
  }
});

test('tls: reconnects and re-registers after the connection drops', { timeout: 20000 }, async () => {
  const pbx = await startFakePbx({ transport: 'tls' });
  const ua = new SipUA();
  try {
    const first = waitReg(ua, (r) => r.state === 'registered');
    await ua.start(accountFor(pbx, { transport: 'tls' }));
    await until(first, 5000, 'registration');
    const firstPort = ua.localPort;

    const lost = waitReg(ua, (r) => r.state === 'registering');
    const again = waitReg(ua, (r) => r.state === 'registered');
    pbx.dropConnections();
    assert.match((await until(lost, 5000, 'connection lost')).error!, /reconnecting/);
    await until(again, 10000, 're-registration');
    assert.equal(pbx.connections, 2);
    assert.notEqual(ua.localPort, firstPort, 'new connection, new local port');
    const last = pbx.requests.filter((m) => m.method === 'REGISTER').at(-1)!;
    assert.match(getHeader(last, 'contact')!, new RegExp(`:${ua.localPort};transport=tls>`), 'Contact updated');
  } finally {
    await ua.stop();
    pbx.close();
  }
});

// ---------------------------------------------------------------------------------------------
// Full calls: browser <-> gateway <-> PBX over TLS + SRTP

test('tls+srtp: outbound call, encrypted audio both ways', { timeout: 30000 }, async () => {
  const h = await setup({ transport: 'tls', srtp: true });
  try {
    h.send({ type: 'dial', number: '03001234567' });
    const active = await h.waitStatus((s) => s.call.state === 'active', 'call active');
    assert.equal(active.call.srtp, true);
    assert.equal(active.registration.transport, 'tls');

    const invite = h.pbx.requests.filter((m) => m.method === 'INVITE').at(-1)!;
    assert.match(invite.body, /m=audio \d+ RTP\/SAVP 8 0 101/);
    assert.match(invite.body, /a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:\S{40}/);

    // Browser -> PBX: the PBX (werift SRTP) decrypts exactly the browser's bytes.
    const frame = Buffer.alloc(160, 0x2a);
    for (let i = 1; i <= 5; i++) h.sendFromBrowser(frame, i);
    const up = await until(h.pbx.waitForRtp((p) => p.pt === 8 && p.payload[0] === 0x2a), 5000, 'decrypted audio at PBX');
    assert.deepEqual(up.payload, frame);
    assert.ok(!h.pbx.rawRtp.some((raw) => raw.includes(frame.subarray(0, 32))), 'plaintext never on the wire');
    assert.equal(h.pbx.badSrtp, 0);

    // PBX -> browser: encrypted by the PBX, decrypted by the gateway.
    const down = Buffer.alloc(160, 0x77);
    for (let i = 1; i <= 5; i++) h.pbx.sendRtp(down, 8, 100 + i, 5000 + i * 160);
    const got = await h.waitReceived((p) => p.payload[0] === 0x77, 'audio in browser');
    assert.deepEqual(got.payload, down);

    h.send({ type: 'dtmf', digit: '9' });
    const dtmf = await until(h.pbx.waitForRtp((p) => p.pt === 101), 5000, 'encrypted DTMF');
    assert.equal(dtmf.payload[0], 9);

    h.send({ type: 'hangup' });
    await until(h.pbx.waitFor((m) => m.method === 'BYE'), 5000, 'BYE over TLS');
  } finally {
    await h.close();
  }
});

test('tls+srtp: inbound call is answered with our key under the tag of the PBX line we accepted', { timeout: 30000 }, async () => {
  const h = await setup({ transport: 'tls', srtp: true });
  try {
    h.pbx.sendRequest(inboundInvite(h.pbx, h.ua.localPort, 'sec-in', 'TLS'), h.ua.localPort);
    await h.waitStatus((s) => s.call.state === 'incoming', 'incoming');
    h.send({ type: 'accept' });
    const ok = await until(h.pbx.waitFor((m) => m.status === 200 && m.body.includes('m=audio')), 5000, '200 OK');
    assert.match(ok.body, /RTP\/SAVP/);
    assert.match(ok.body, /a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:/, 'tag 1 = the _80 line of the offer');
    assert.doesNotMatch(ok.body, new RegExp(h.pbx.srtpKey.replace(/[+/]/g, '\\$&')), 'our own key, not an echo of the PBX key');
    await h.waitStatus((s) => s.call.state === 'active' && s.call.srtp === true, 'active');

    h.sendFromBrowser(Buffer.alloc(160, 0x2b), 1);
    h.sendFromBrowser(Buffer.alloc(160, 0x2b), 2);
    await until(h.pbx.waitForRtp((p) => p.payload[0] === 0x2b), 5000, 'decrypted audio at PBX');
    h.send({ type: 'hangup' });
  } finally {
    await h.close();
  }
});

test('encryption required: a PBX answering with plain RTP ends the call (no silent downgrade)', { timeout: 30000 }, async () => {
  const h = await setup({ srtp: false, uaSrtp: true });
  try {
    h.send({ type: 'dial', number: '1002' });
    const idle = await h.waitStatus((s) => s.call.state === 'idle' && Boolean(s.call.reason), 'call rejected');
    assert.match(idle.call.reason!, /plain RTP but PBX_ENCRYPTION is on/);
    await until(h.pbx.waitFor((m) => m.method === 'BYE'), 5000, 'BYE');
    assert.equal(h.pbx.rtpPackets.length, 0, 'no audio was sent unencrypted');
  } finally {
    await h.close();
  }
});

test('encryption off: an SRTP-only offer from the PBX gets 488', { timeout: 30000 }, async () => {
  const h = await setup({ srtp: true, uaSrtp: false });
  try {
    h.pbx.sendRequest(inboundInvite(h.pbx, h.ua.localPort, 'sec-488'), h.ua.localPort);
    await h.waitStatus((s) => s.call.state === 'incoming', 'incoming');
    h.send({ type: 'accept' });
    await until(h.pbx.waitFor((m) => m.status === 488), 5000, '488');
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------------------------
// Configuration

test('config: transport and encryption selection', async () => {
  const { loadConfig } = await import('../server/config.ts');
  const base = { SIP_EXTENSION: '1001', SIP_SECRET: 'x' };
  const udp = loadConfig({ ...base, PBX_IP: '192.168.200.14' });
  assert.deepEqual([udp.transport, udp.pbxPort, udp.encryption], ['udp', 5060, false]);

  const tls = loadConfig({ ...base, PBX_IP: '192.168.200.14', PBX_TRANSPORT: 'tls' });
  assert.deepEqual([tls.transport, tls.pbxPort, tls.encryption, tls.tls.rejectUnauthorized], ['tls', 5061, true, true], 'TLS implies SRTP and verification');

  const sips = loadConfig({ ...base, PBX_URI: 'sips:pbx.example.com' });
  assert.deepEqual([sips.pbxIp, sips.transport, sips.pbxPort], ['pbx.example.com', 'tls', 5061]);
  const param = loadConfig({ ...base, PBX_URI: 'sip:10.0.0.1:5071;transport=tls' });
  assert.deepEqual([param.pbxIp, param.transport, param.pbxPort], ['10.0.0.1', 'tls', 5071]);

  assert.match(loadConfig({ ...base, PBX_IP: 'x', PBX_ENCRYPTION: 'true' }).warnings.join(), /clear-text SDP/);
  assert.match(loadConfig({ ...base, PBX_IP: 'x', PBX_TRANSPORT: 'tls', PBX_PORT: '5060' }).warnings.join(), /5061/);
  assert.match(loadConfig({ ...base, PBX_IP: 'x', PBX_TRANSPORT: 'tls', PBX_TLS_VERIFY: 'false' }).warnings.join(), /man-in-the-middle/);
  assert.throws(() => loadConfig({ ...base, PBX_IP: 'x', PBX_TRANSPORT: 'tcp' }), /udp or tls/);
  assert.throws(() => loadConfig({ ...base, PBX_IP: 'x', PBX_TLS_CA: 'missing.pem' }), /not found/);
});
