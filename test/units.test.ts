import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildAuthorization, parseChallenge } from '../server/sip/digest.ts';
import { buildResponse, parseMessage, parseNameAddr, parseUri } from '../server/sip/message.ts';
import { buildSdp, negotiate, parseSdp } from '../server/sip/sdp.ts';
import { alawToLinear, transcode, ulawToLinear } from '../server/media/g711.ts';
import { buildRtp, parseRtp, RtpTimeline } from '../server/media/rtp.ts';

test('digest: RFC 2617 §3.5 example (qop=auth)', () => {
  const challenge = parseChallenge('Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"')!;
  const { response, header } = buildAuthorization({ challenge, method: 'GET', uri: '/dir/index.html', username: 'Mufasa', password: 'Circle Of Life', nc: 1, cnonce: '0a4f113b' });
  assert.equal(response, '6629fae49393a05397450978507c4ef1');
  assert.match(header, /qop=auth, nc=00000001, cnonce="0a4f113b"/);
  assert.match(header, /opaque="5ccc069c403ebaf9f0171e9517f40e41"/);
});

test('digest: no qop (chan_sip default)', () => {
  const challenge = parseChallenge('Digest algorithm=MD5, realm="asterisk", nonce="1a2b3c"')!;
  const a = buildAuthorization({ challenge, method: 'REGISTER', uri: 'sip:192.168.200.14', username: '1001', password: 'x' });
  assert.doesNotMatch(a.header, /qop/);
  assert.match(a.response, /^[0-9a-f]{32}$/);
});

test('message: parse compact headers, multi-value Via, body length', () => {
  const raw = 'SIP/2.0 200 OK\r\nv: SIP/2.0/UDP a;branch=z9hG4bK1, SIP/2.0/UDP b;branch=z9hG4bK2\r\ni: abc\r\nf: <sip:1@x>;tag=1\r\nt: <sip:2@x>\r\nCSeq: 1 INVITE\r\nl: 4\r\n\r\nbodyEXTRA';
  const m = parseMessage(Buffer.from(raw))!;
  assert.equal(m.status, 200);
  assert.equal(m.headers.get('via')!.length, 2);
  assert.equal(m.body, 'body');
  const res = buildResponse(parseMessage(Buffer.from('BYE sip:x SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bKq\r\nFrom: <sip:a@h>;tag=f\r\nTo: <sip:b@h>\r\nCall-ID: c\r\nCSeq: 2 BYE\r\n\r\n'))!, 200, 'OK', { toTag: 't1' });
  assert.match(res, /^SIP\/2\.0 200 OK\r\n/);
  assert.match(res, /To: <sip:b@h>;tag=t1\r\n/);
  assert.match(res, /Content-Length: 0\r\n\r\n$/);
});

test('message: name-addr and URI parsing', () => {
  const na = parseNameAddr('"Front Desk" <sip:1002@192.168.200.14:5060;transport=udp>;tag=abc');
  assert.equal(na.display, 'Front Desk');
  assert.equal(na.params.tag, 'abc');
  assert.deepEqual(parseUri(na.uri), { user: '1002', host: '192.168.200.14', port: 5060, params: { transport: 'udp' } });
});

test('sdp: build, parse, negotiate', () => {
  const sdp = buildSdp({ ip: '10.0.0.5', port: 12000, sessionId: 1, version: 1, codecs: [{ name: 'PCMA', pt: 8 }, { name: 'PCMU', pt: 0 }] });
  const parsed = parseSdp(sdp)!;
  assert.equal(parsed.ip, '10.0.0.5');
  assert.equal(parsed.port, 12000);
  assert.deepEqual(parsed.formats, [8, 0, 101]);
  // As offerer we pick our preference; as answer we honour the remote order.
  assert.equal(negotiate(parsed, ['PCMU', 'PCMA'])!.codec.name, 'PCMU');
  assert.equal(negotiate(parsed, ['PCMU', 'PCMA'], { remoteOrder: true })!.codec.name, 'PCMA');
  assert.equal(negotiate(parsed, ['PCMU'])!.dtmfPt, 101);
  const opusOnly = parseSdp('v=0\r\nc=IN IP4 1.2.3.4\r\nm=audio 5 RTP/AVP 107\r\na=rtpmap:107 opus/48000/2\r\n')!;
  assert.equal(negotiate(opusOnly, ['PCMA', 'PCMU']), null);
});

test('g711: µ-law <-> A-law transcoding keeps the sample value', () => {
  for (let i = 0; i < 256; i++) {
    const a = transcode(Buffer.from([i]), 'PCMU', 'PCMA')[0];
    const diff = Math.abs(ulawToLinear(i) - alawToLinear(a));
    assert.ok(diff <= Math.max(64, Math.abs(ulawToLinear(i)) * 0.07), `ulaw ${i}: ${ulawToLinear(i)} vs alaw ${alawToLinear(a)}`);
  }
  const same = Buffer.from([1, 2, 3]);
  assert.equal(transcode(same, 'PCMA', 'PCMA'), same);
});

test('rtp: build/parse round trip, RTCP ignored', () => {
  const pkt = buildRtp({ pt: 8, marker: true, seq: 65535, timestamp: 0xfffffff0, ssrc: 42, payload: Buffer.alloc(160, 0xd5) });
  const p = parseRtp(pkt)!;
  assert.deepEqual([p.pt, p.marker, p.seq, p.timestamp, p.ssrc, p.payload.length], [8, true, 65535, 0xfffffff0, 42, 160]);
  assert.equal(parseRtp(Buffer.from([0x80, 200, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0])), null);
});

test('rtp timeline: keeps gaps, drops duplicates, stays continuous across SSRC changes', () => {
  const tl = new RtpTimeline();
  const a = tl.map({ ssrc: 1, seq: 10, timestamp: 1000, marker: false }, 160)!;
  assert.equal(a.marker, true, 'first packet of a stream gets the marker bit');
  const b = tl.map({ ssrc: 1, seq: 11, timestamp: 1160, marker: false }, 160)!;
  assert.equal((b.timestamp - a.timestamp) >>> 0, 160);
  assert.equal((b.seq - a.seq) & 0xffff, 1);
  assert.equal(tl.map({ ssrc: 1, seq: 11, timestamp: 1160, marker: false }, 160), null, 'duplicate');
  assert.equal(tl.map({ ssrc: 1, seq: 9, timestamp: 840, marker: false }, 160), null, 'late');
  const gap = tl.map({ ssrc: 1, seq: 13, timestamp: 1480, marker: false }, 160)!;
  assert.equal((gap.timestamp - b.timestamp) >>> 0, 320, 'a lost packet keeps its time slot');
  const next = tl.map({ ssrc: 99, seq: 5000, timestamp: 777, marker: false }, 160)!;
  assert.equal((next.timestamp - gap.timestamp) >>> 0, 160, 'new source continues one frame later');
  assert.equal((next.seq - gap.seq) & 0xffff, 1);
  assert.equal(next.marker, true);
});
