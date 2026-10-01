// Call supervision over AMI: the live-calls list, and the PBX side of listen / whisper / takeover.
//
//   listen    Originate: ring our own extension, and when the gateway answers run
//             ChanSpy(<agent channel>,qEd). We hear both sides; nobody hears us.
//   whisper   Same with the w option (qEdw): only the spied-on channel, the agent, hears us.
//             We always spy on the AGENT's channel, never the customer's, so the customer
//             never hears the coaching.
//   switching The d option lets DTMF 4 (listen) / 5 (whisper) switch modes inside ChanSpy, so
//             the gateway just sends RFC 4733 digits on the call it already has.
//   takeover  Bridge(<customer channel>, <our ChanSpy channel>) moves the customer out of the
//             agent's bridge into a new one with us; then Hangup(<agent channel>). Our SIP call
//             never changes, it just carries the customer now.
//
// The spy call is recognised by the gateway through a one-time token in its caller ID number
// (and an X-Arzen-Monitor header where chan_sip honours SIPADDHEADER).
//
// Kept free of werift/express and of the SIP stack: in the PMS integration this part can move
// to the backend, which already holds an AMI connection.
import { EventEmitter } from 'node:events';
import { AmiClient, type AmiMessage, type AmiOptions, type AmiStateInfo } from './AmiClient.ts';
import { buildLiveCalls, channelFromEvent, deviceOf, spyTarget, type AmiChannel } from './channels.ts';
import type { LiveCall } from '../../shared/protocol.ts';

export interface SupervisorOptions extends AmiOptions {
  /** Our own extension: the one ChanSpy rings, and never offered as a target. */
  extension: string;
  /** Channel to ring, e.g. "SIP/109". Default: the target's technology + our extension. */
  spyChannel?: string;
  /** Peer names that are agent extensions (vs. trunks). */
  agentPattern: RegExp;
  /** Safety-net refresh interval; events trigger refreshes in between. */
  pollMs?: number;
  log?: (line: string) => void;
}

/** Header the gateway also accepts as proof that an INVITE is our spy call. */
export const MONITOR_HEADER = 'X-Arzen-Monitor';

const MIN_REFRESH_GAP = 1000;
const REFRESH_EVENTS = /^(newstate|hangup|bridgeenter|bridgeleave|bridge|rename|newconnectedline|originateresponse)$/i;
const ORIGINATE_TIMEOUT_MS = 20000;

/** OriginateResponse Reason codes (AST_CONTROL_*). */
function originateReason(code: string | undefined): string {
  switch (code) {
    case '0': return 'the extension does not exist or is not registered';
    case '1': return 'it hung up';
    case '3': return 'nobody answered';
    case '5': return 'it is busy';
    case '8': return 'congestion';
    default: return `reason ${code ?? 'unknown'}`;
  }
}

export class Supervisor extends EventEmitter<{ state: [AmiStateInfo]; calls: [LiveCall[]] }> {
  readonly ami: AmiClient;
  calls: LiveCall[] = [];
  private readonly opts: SupervisorOptions;
  private channels: AmiChannel[] = [];
  private since = new Map<string, number>();
  private callsJson = '[]';
  private pollTimer: NodeJS.Timeout | undefined;
  private refreshTimer: NodeJS.Timeout | undefined;
  private refreshing: Promise<LiveCall[]> | null = null;
  private lastRefresh = 0;
  /** The "missing write=reporting" hint was logged (polling would repeat it every 5 s). */
  private permissionLogged = false;
  /** Originate ActionID -> waiter for its OriginateResponse. */
  private originates = new Map<string, { resolve: () => void; reject: (err: Error) => void; timer: NodeJS.Timeout }>();

  constructor(opts: SupervisorOptions) {
    super();
    this.opts = opts;
    this.ami = new AmiClient({ ...opts, events: opts.events ?? 'call' });
    this.ami.on('state', (s) => {
      this.log(`AMI ${opts.host}:${opts.port}: ${s.state}${s.error ? ` (${s.error})` : ''}`);
      if (s.state === 'connected') void this.refresh().catch(() => {});
      if (s.state !== 'connected') this.setCalls([]);
      this.emit('state', s);
    });
    this.ami.on('event', (ev) => this.onEvent(ev));
  }

  get state(): AmiStateInfo {
    return this.ami.state;
  }

  start(): void {
    this.ami.start();
    this.pollTimer = setInterval(() => void this.refresh().catch(() => {}), this.opts.pollMs ?? 5000);
  }

  async stop(): Promise<void> {
    clearInterval(this.pollTimer);
    clearTimeout(this.refreshTimer);
    for (const [, o] of this.originates) clearTimeout(o.timer);
    this.originates.clear();
    await this.ami.stop();
  }

  private log(line: string): void {
    this.opts.log?.(line);
  }

  private onEvent(ev: AmiMessage): void {
    if (ev.event?.toLowerCase() === 'originateresponse' && ev.actionid) {
      const o = this.originates.get(ev.actionid);
      if (o) {
        clearTimeout(o.timer);
        this.originates.delete(ev.actionid);
        if (/^success$/i.test(ev.response ?? '')) o.resolve();
        else o.reject(new Error(`The PBX could not ring ${ev.channel || 'our extension'}: ${originateReason(ev.reason)}.`));
      }
    }
    if (ev.event && REFRESH_EVENTS.test(ev.event)) this.scheduleRefresh();
  }

  /** Coalesce bursts of call events into at most one refresh per second. */
  private scheduleRefresh(): void {
    if (this.refreshTimer) return;
    const wait = Math.max(150, this.lastRefresh + MIN_REFRESH_GAP - Date.now());
    this.refreshTimer = setTimeout(() => {
      this.refreshTimer = undefined;
      void this.refresh().catch(() => {});
    }, wait);
  }

  private setCalls(calls: LiveCall[]): void {
    const json = JSON.stringify(calls);
    if (json === this.callsJson) return;
    this.callsJson = json;
    this.calls = calls;
    this.emit('calls', calls);
  }

  /** Re-read the PBX's channels and recompute the live calls. Concurrent callers share one request. */
  refresh(): Promise<LiveCall[]> {
    this.refreshing ??= (async () => {
      try {
        const events = await this.ami.actionList({ Action: 'CoreShowChannels' }).catch((err: Error) => {
          if (!/permission/i.test(err.message)) throw err;
          const hint = `The PBX refused to list its channels: the AMI user needs write=reporting (for CoreShowChannels) in manager_custom.conf.`;
          if (!this.permissionLogged) this.log(`AMI: ${hint}`);
          this.permissionLogged = true;
          throw new Error(hint);
        });
        this.lastRefresh = Date.now();
        this.channels = events.filter((e) => e.event?.toLowerCase() === 'coreshowchannel').map(channelFromEvent);
        const present = new Set(this.channels.map((c) => c.name));
        for (const name of this.since.keys()) if (!present.has(name)) this.since.delete(name);
        this.setCalls(buildLiveCalls(this.channels, { agentPattern: this.opts.agentPattern, exclude: [this.opts.extension], now: Date.now(), since: this.since }));
        return this.calls;
      } finally {
        this.refreshing = null;
      }
    })();
    return this.refreshing;
  }

  /** The channel ChanSpy rings for a target, e.g. "SIP/109". */
  spyChannelFor(target: LiveCall): string {
    if (this.opts.spyChannel) return this.opts.spyChannel;
    const tech = deviceOf(target.channel)?.tech ?? 'SIP';
    return `${tech}/${this.opts.extension}`;
  }

  /**
   * Ring our extension into ChanSpy on the agent's channel. Resolves once the PBX reports the
   * spy call answered; rejects if the Originate is refused or the call cannot be placed.
   */
  async spy(target: LiveCall, opts: { whisper: boolean; token: string }): Promise<void> {
    const channel = this.spyChannelFor(target);
    const options = `qEd${opts.whisper ? 'w' : ''}`;
    // Full channel name: ChanSpy matches by prefix, so "SIP/11" would also match SIP/115.
    const data = `${target.channel},${options}`;
    const label = `${opts.whisper ? 'Whisper' : 'Listen'} ${target.extension}`;
    this.log(`AMI Originate ${channel} -> ChanSpy(${data})`);

    // Our own ActionID, so the OriginateResponse event can be matched to this request.
    const actionId = `arzen-spy-${opts.token}`;
    const answered = new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.originates.delete(actionId);
        reject(new Error(`The PBX did not ring ${channel} within ${ORIGINATE_TIMEOUT_MS / 1000} s.`));
      }, ORIGINATE_TIMEOUT_MS + 5000);
      this.originates.set(actionId, { resolve, reject, timer });
    });
    answered.catch(() => {}); // the caller may stop listening before it settles

    try {
      await this.ami.action({
        Action: 'Originate',
        ActionID: actionId,
        Channel: channel,
        Application: 'ChanSpy',
        Data: data,
        CallerID: `"${label}" <${opts.token}>`,
        Timeout: ORIGINATE_TIMEOUT_MS,
        Async: 'true',
        Variable: [`SIPADDHEADER51=${MONITOR_HEADER}: ${opts.token}`],
      });
    } catch (err) {
      const o = this.originates.get(actionId);
      if (o) clearTimeout(o.timer);
      this.originates.delete(actionId);
      const message = (err as Error).message;
      throw new Error(`The PBX refused to start monitoring: ${message}${/permission/i.test(message) ? ' (the AMI user needs write=originate)' : ''}`);
    }
    return answered;
  }

  /** Our ChanSpy channel on `agentChannel` (it may take a moment to appear after answering). */
  private async findSpyChannel(agentChannel: string, spyPrefix: string): Promise<AmiChannel | null> {
    for (let attempt = 0; attempt < 6; attempt++) {
      if (attempt) await new Promise((r) => setTimeout(r, 300));
      await this.refresh();
      const spy = this.channels.find((c) => c.name.startsWith(`${spyPrefix}-`) && spyTarget(c) === agentChannel);
      if (spy) return spy;
    }
    return null;
  }

  /**
   * Move the agent's caller to our spy call and drop the agent. Returns the other party.
   * Requires a running spy session on `target` from this gateway.
   */
  async takeover(target: LiveCall): Promise<LiveCall['peer']> {
    const spy = await this.findSpyChannel(target.channel, this.spyChannelFor(target));
    if (!spy) throw new Error('Could not find our monitoring channel on the PBX.');
    const agent = this.channels.find((c) => c.name === target.channel);
    if (!agent) throw new Error('The call has already ended.');
    const call = this.calls.find((c) => c.channel === target.channel);
    if (!call) throw new Error(`${target.extension} is no longer in a two-party call.`);

    this.log(`AMI Bridge ${call.peer.channel} <-> ${spy.name}, then Hangup ${call.channel}`);
    await this.ami.action({ Action: 'Bridge', Channel1: call.peer.channel, Channel2: spy.name, Tone: 'no' }).catch((err: Error) => {
      throw new Error(`The PBX refused the takeover: ${err.message}${/permission/i.test(err.message) ? ' (the AMI user needs write=call)' : ''}`);
    });
    // Asterisk usually drops the agent itself when its bridge dissolves; make sure.
    await this.ami.action({ Action: 'Hangup', Channel: call.channel }).catch(() => {});
    void this.refresh().catch(() => {});
    return call.peer;
  }
}
