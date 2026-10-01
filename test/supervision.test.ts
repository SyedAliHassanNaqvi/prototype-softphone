// Call supervision: AMI parsing, the live calls board, and listen / whisper / takeover end to end
// (werift "browser" <-> real gateway <-> fake Asterisk SIP + fake AMI).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildAmiAction, parseAmiMessage, type AmiFields } from '../server/ami/AmiClient.ts';
import { buildLiveCalls, channelFromEvent, extensionOf } from '../server/ami/channels.ts';
import { Supervisor } from '../server/ami/Supervisor.ts';
import { inboundInvite } from './fakePbx.ts';
import { AMI_SECRET, startFakeAmi, type FakeAmi } from './fakeAmi.ts';
import { setup, until } from './harness.ts';

const AGENT = 'SIP/115-0000001a';
const TRUNK = 'SIP/trunk-0000001b';
const SPY = 'SIP/1001-0000001c';

/** Agent 115 on an outbound PSTN call (Asterisk 13 CoreShowChannel fields). */
const agentCall = (): AmiFields[] => [
  { Channel: AGENT, ChannelStateDesc: 'Up', CallerIDNum: '115', CallerIDName: 'Ali', ConnectedLineNum: '03001234567', ConnectedLineName: '<unknown>', Application: 'Dial', ApplicationData: 'SIP/trunk/03001234567', Duration: '00:01:05', BridgeId: 'b1' },
  { Channel: TRUNK, ChannelStateDesc: 'Up', CallerIDNum: '03001234567', CallerIDName: '<unknown>', ConnectedLineNum: '115', Application: 'AppDial', ApplicationData: '(Outgoing Line)', Duration: '00:01:03', BridgeId: 'b1' },
];

const ev = (fields: AmiFields) => channelFromEvent(parseAmiMessage(buildAmiAction({ Event: 'CoreShowChannel', ...fields }).trim()));

test('ami: message parse / build round trip, repeated Variable lines', () => {
  const text = buildAmiAction({ Action: 'Originate', Channel: 'SIP/109', Variable: ['A=1', 'B=2'], Skip: undefined });
  assert.equal(text, 'Action: Originate\r\nChannel: SIP/109\r\nVariable: A=1\r\nVariable: B=2\r\n\r\n');
  const m = parseAmiMessage('Response: Success\r\nActionID: x1\r\nMessage: Channels: will follow');
  assert.deepEqual(m, { response: 'Success', actionid: 'x1', message: 'Channels: will follow' });
  assert.throws(() => buildAmiAction({ Action: 'Hangup', Channel: 'SIP/1\r\nAction: Originate' }), /line break/);
});

test('live calls: agents in two-party bridges, trunks and our own extension excluded, spies attributed', () => {
  assert.equal(extensionOf('PJSIP/1002-00000a1f', /^\d{2,6}$/), '1002');
  assert.equal(extensionOf('SIP/trunk-0000001b', /^\d{2,6}$/), null);
  assert.equal(extensionOf('Local/115@from-queue-00000001;1', /^\d{2,6}$/), null);

  const channels = [
    ...agentCall().map(ev),
    // An internal call 120 <-> 121: both are agents.
    ev({ Channel: 'SIP/120-00000020', CallerIDNum: '120', ConnectedLineNum: '121', Duration: '10', BridgeId: 'b2' }),
    ev({ Channel: 'SIP/121-00000021', CallerIDNum: '121', ConnectedLineNum: '120', Duration: '9', BridgeId: 'b2' }),
    // Our own call (1001) is never a target.
    ev({ Channel: 'SIP/1001-00000030', CallerIDNum: '1001', Duration: '5', BridgeId: 'b3' }),
    ev({ Channel: 'SIP/trunk-00000031', CallerIDNum: '0421111111', Duration: '5', BridgeId: 'b3' }),
    // A three-way conference and a ringing channel: not offered.
    ...['SIP/130-1', 'SIP/131-2', 'SIP/132-3'].map((c) => ev({ Channel: c, BridgeId: 'conf' })),
    ev({ Channel: 'SIP/140-00000040', ChannelStateDesc: 'Ringing', Application: 'Dial' }),
    // Another supervisor (112) spying on 115.
    ev({ Channel: 'SIP/112-00000050', Application: 'ChanSpy', ApplicationData: `${AGENT},qEd` }),
  ];
  const now = 1_000_000;
  const calls = buildLiveCalls(channels, { agentPattern: /^\d{2,6}$/, exclude: ['1001'], now });
  assert.deepEqual(calls.map((c) => c.extension), ['115', '120', '121']);
  const ali = calls[0];
  assert.equal(ali.channel, AGENT);
  assert.equal(ali.name, 'Ali');
  assert.deepEqual(ali.peer, { channel: TRUNK, number: '03001234567', name: undefined });
  assert.equal(ali.since, now - 65_000);
  assert.deepEqual(ali.monitoredBy, ['112']);
  assert.equal(calls[1].peer.number, '121');
});

test('live calls: Asterisk 11 BridgedChannel pairs', () => {
  const channels = [
    ev({ Channel: 'SIP/115-0000001a', CallerIDnum: '115', BridgedChannel: 'SIP/trunk-0000001b', Duration: '00:00:30' }),
    ev({ Channel: 'SIP/trunk-0000001b', CallerIDnum: '0300', BridgedChannel: 'SIP/115-0000001a', Duration: '00:00:29' }),
  ];
  const calls = buildLiveCalls(channels, { agentPattern: /^\d{2,6}$/, exclude: [], now: 0 });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].peer.number, '0300');
});

async function startSupervisor(ami: FakeAmi, secret = AMI_SECRET): Promise<Supervisor> {
  const sup = new Supervisor({ host: '127.0.0.1', port: ami.port, username: 'arzen', secret, extension: '1001', agentPattern: /^\d{2,6}$/, pollMs: 60000 });
  const settled = new Promise<string>((resolve) => sup.on('state', (s) => (s.state === 'connected' || s.state === 'failed') && resolve(s.state)));
  sup.start();
  assert.equal(await until(settled, 5000, 'AMI login'), secret === AMI_SECRET ? 'connected' : 'failed');
  return sup;
}

/** Script the fake PBX: on Originate, ring the gateway with the spy call and run ChanSpy. */
function scriptChanSpy(ami: FakeAmi, h: Awaited<ReturnType<typeof setup>>): void {
  ami.onAction = (a) => {
    if (a.action !== 'Originate') return;
    const token = /<(spy[0-9a-f]+)>/.exec(a.callerid ?? '')![1];
    h.pbx.sendRequest(inboundInvite(h.pbx, h.ua.localPort, `spycall-${token}`, 'UDP', `"Listen 115" <sip:${token}@127.0.0.1>`), h.ua.localPort);
    ami.channels.push({ Channel: SPY, ChannelStateDesc: 'Up', CallerIDNum: token, Application: 'ChanSpy', ApplicationData: a.data, Duration: '0' });
    setTimeout(() => ami.emitEvent({ Event: 'OriginateResponse', ActionID: a.actionid, Response: 'Success', Channel: 'SIP/1001', Reason: '4' }), 100);
  };
}

test('supervision: listen, switch to whisper (DTMF 5), take over the customer', { timeout: 30000 }, async () => {
  const ami = await startFakeAmi();
  ami.channels = agentCall();
  const sup = await startSupervisor(ami);
  const h = await setup({ supervisor: sup });
  scriptChanSpy(ami, h);
  try {
    const calls = await h.waitLiveCalls((c) => c.length === 1, 'live calls board');
    assert.equal(calls[0].extension, '115');
    assert.equal(calls[0].peer.number, '03001234567');
    const st0 = await h.waitStatus((s) => s.supervisor.state === 'connected', 'supervisor connected');
    assert.equal(st0.supervisor.monitor, null);

    h.send({ type: 'monitor', channel: AGENT, mode: 'listen' });
    const originate = await until(ami.waitFor((a) => a.action === 'Originate'), 5000, 'Originate');
    assert.equal(originate.channel, 'SIP/1001', 'rings our own extension, same technology as the agent');
    assert.equal(originate.application, 'ChanSpy');
    assert.equal(originate.data, `${AGENT},qEd`, 'spies on the full agent channel, quiet, DTMF mode switching');
    assert.equal(originate.async, 'true');

    // The gateway answers the spy call on its own; it shows as monitoring 115, not the token.
    const listening = await h.waitStatus((s) => s.supervisor.monitor?.state === 'listen' && s.call.state === 'active', 'listening');
    assert.equal(listening.call.number, '115');
    assert.equal(listening.call.display, 'Ali');
    await until(h.pbx.waitFor((m) => m.status === 200 && m.body.includes('m=audio')), 5000, '200 OK to the spy INVITE');

    // ChanSpy's audio reaches the browser like any call.
    for (let i = 1; i <= 5; i++) h.pbx.sendRtp(Buffer.alloc(160, 0x55), 8, i, i * 160);
    await h.waitReceived((p) => p.payload[0] === 0x55, 'spy audio in browser');

    // Keypad digits are swallowed while spying (they would drive ChanSpy)...
    h.send({ type: 'dtmf', digit: '*' });
    // ...and whisper is DTMF 5 on the spy call.
    h.send({ type: 'monitorMode', mode: 'whisper' });
    await h.waitStatus((s) => s.supervisor.monitor?.state === 'whisper', 'whisper');
    const dtmf = await until(h.pbx.waitForRtp((p) => p.pt === 101), 5000, 'DTMF 5');
    assert.equal(dtmf.payload[0], 5);
    assert.ok(!h.pbx.rtpPackets.some((p) => p.pt === 101 && p.payload[0] === 10), 'the * key was not sent');

    // Our own spy channel shows up on the board.
    ami.emitEvent({ Event: 'Newstate', Channel: SPY });
    await h.waitLiveCalls((c) => c[0]?.monitoredBy.includes('1001'), 'monitoredBy');

    h.send({ type: 'takeover' });
    const taken = await h.waitStatus((s) => s.supervisor.monitor?.state === 'takenOver', 'taken over');
    const bridge = ami.actions.find((a) => a.action === 'Bridge')!;
    assert.equal(bridge.channel1, TRUNK, 'the customer...');
    assert.equal(bridge.channel2, SPY, '...is bridged to our ChanSpy channel');
    const hangup = await until(ami.waitFor((a) => a.action === 'Hangup'), 5000, 'agent hangup');
    assert.equal(hangup.channel, AGENT);
    assert.equal(taken.call.number, '03001234567');
    assert.equal(taken.call.state, 'active', 'same SIP call, no re-dial');

    h.send({ type: 'hangup' });
    const idle = await h.waitStatus((s) => s.call.state === 'idle', 'idle');
    assert.equal(idle.supervisor.monitor, null);
  } finally {
    await h.close();
    await sup.stop();
    ami.close();
  }
});

test('supervision: "Take over" straight from the board, and the spy call ending with the agent call', { timeout: 30000 }, async () => {
  const ami = await startFakeAmi();
  ami.channels = agentCall();
  const sup = await startSupervisor(ami);
  const h = await setup({ supervisor: sup });
  scriptChanSpy(ami, h);
  try {
    await h.waitLiveCalls((c) => c.length === 1, 'live calls board');
    h.send({ type: 'monitor', channel: AGENT, mode: 'whisper' });
    const originate = await until(ami.waitFor((a) => a.action === 'Originate'), 5000, 'Originate');
    assert.equal(originate.data, `${AGENT},qEdw`, 'whisper from the start');
    const ok = await until(h.pbx.waitFor((m) => m.status === 200 && m.body.includes('m=audio')), 5000, '200 OK');
    await h.waitStatus((s) => s.supervisor.monitor?.state === 'whisper', 'whisper');

    // The agent's call ends: ChanSpy (option E) hangs up our spy call.
    const callId = ok.headers.get('call-id')![0];
    h.pbx.sendRequest(
      [`BYE sip:1001@127.0.0.1:${h.ua.localPort} SIP/2.0`, `Via: SIP/2.0/UDP 127.0.0.1:${h.pbx.port};branch=z9hG4bKbye9`, `From: <sip:x@127.0.0.1>;tag=from${callId}`, `To: ${ok.headers.get('to')![0]}`, `Call-ID: ${callId}`, 'CSeq: 103 BYE', 'Content-Length: 0', '', ''].join('\r\n'),
      h.ua.localPort,
    );
    const idle = await h.waitStatus((s) => s.call.state === 'idle', 'idle');
    assert.equal(idle.call.reason, "Monitoring ended: 115's call finished.");
    assert.equal(idle.supervisor.monitor, null);

    // Take over directly: listen first, then the takeover runs as soon as the spy call is up.
    ami.channels = agentCall();
    h.send({ type: 'monitor', channel: AGENT, mode: 'takeover' });
    await h.waitStatus((s) => s.supervisor.monitor?.state === 'takenOver', 'taken over');
    assert.equal(ami.actions.filter((a) => a.action === 'Originate').at(-1)!.data, `${AGENT},qEd`);
    assert.ok(ami.actions.some((a) => a.action === 'Bridge'));
    h.send({ type: 'hangup' });
    await h.waitStatus((s) => s.call.state === 'idle', 'idle');
  } finally {
    await h.close();
    await sup.stop();
    ami.close();
  }
});

test('supervision: PBX cannot ring us -> error, monitoring cleared; ended call refused', { timeout: 30000 }, async () => {
  const ami = await startFakeAmi();
  ami.channels = agentCall();
  const sup = await startSupervisor(ami);
  const h = await setup({ supervisor: sup });
  ami.onAction = (a) => {
    if (a.action === 'Originate') setTimeout(() => ami.emitEvent({ Event: 'OriginateResponse', ActionID: a.actionid, Response: 'Failure', Channel: 'SIP/1001', Reason: '0' }), 50);
  };
  try {
    await h.waitLiveCalls((c) => c.length === 1, 'live calls board');
    h.send({ type: 'monitor', channel: AGENT, mode: 'listen' });
    await h.waitStatus((s) => s.supervisor.monitor?.state === 'connecting', 'connecting');
    const err = await h.waitError((m) => /could not ring/.test(m), 'originate failure');
    assert.match(err, /not registered/);
    await h.waitStatus((s) => s.supervisor.monitor === null, 'monitor cleared');

    ami.channels = [];
    h.send({ type: 'monitor', channel: AGENT, mode: 'listen' });
    await h.waitError((m) => /already ended/.test(m), 'ended call');
    assert.equal(ami.actions.filter((a) => a.action === 'Originate').length, 1);
  } finally {
    await h.close();
    await sup.stop();
    ami.close();
  }
});

test('AMI: wrong secret fails once and never retries (fail2ban)', { timeout: 15000 }, async () => {
  const ami = await startFakeAmi();
  const sup = await startSupervisor(ami, 'wrong');
  try {
    assert.match(sup.state.error ?? '', /rejected.*Not retrying/);
    await new Promise((r) => setTimeout(r, 2500)); // longer than the first reconnect delay
    assert.equal(ami.logins, 1);
  } finally {
    await sup.stop();
    ami.close();
  }
});

test('config: AMI settings are optional and validated', async () => {
  const { loadConfig } = await import('../server/config.ts');
  const base = { PBX_IP: '192.168.200.14', SIP_EXTENSION: '109', SIP_SECRET: 'x' };
  assert.equal(loadConfig(base).ami, undefined);
  const c = loadConfig({ ...base, AMI_USER: 'arzen', AMI_PASSWORD: 'p' });
  assert.equal(c.ami?.host, '192.168.200.14', 'defaults to the PBX');
  assert.equal(c.ami?.port, 5038);
  assert.ok(c.ami?.agentPattern.test('109'));
  assert.throws(() => loadConfig({ ...base, AMI_USER: 'arzen' }), /AMI_SECRET/);
  assert.throws(() => loadConfig({ ...base, AMI_USER: 'a', AMI_SECRET: 'b', AMI_AGENT_PATTERN: '(' }), /regular expression/);
  assert.throws(() => loadConfig({ ...base, AMI_USER: 'a', AMI_SECRET: 'b', AMI_SPY_CHANNEL: 'SIP/109,qE' }), /AMI_SPY_CHANNEL/);
});
