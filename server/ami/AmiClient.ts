// Minimal Asterisk Manager Interface (AMI) client over TCP (port 5038):
//   * Login with a plain secret, then actions matched to responses by ActionID
//   * list actions (CoreShowChannels...) collect their events up to the "...Complete" event
//   * every other event is emitted as 'event'
//   * reconnects with backoff after the connection drops, but never after the PBX rejected the
//     login: Issabel's fail2ban counts AMI authentication failures too and would ban our IP.
//
// Messages are blocks of "Key: Value" lines ending with an empty line. Keys are lower-cased.
import net from 'node:net';
import { EventEmitter } from 'node:events';

export type AmiMessage = Record<string, string>;
export type AmiFields = Record<string, string | number | string[] | undefined>;

export type AmiConnState = 'disconnected' | 'connecting' | 'connected' | 'failed';
export interface AmiStateInfo {
  state: AmiConnState;
  error?: string;
}

export interface AmiOptions {
  host: string;
  port: number;
  username: string;
  secret: string;
  /** Event classes to receive (Login "Events:"), e.g. "call". "off" for none. */
  events?: string;
}

interface Pending {
  resolve: (m: AmiMessage) => void;
  reject: (err: Error) => void;
  timer: NodeJS.Timeout;
  /** List action: events collected so far, and the response once it arrived. */
  list?: { events: AmiMessage[]; response: AmiMessage | null; done: (events: AmiMessage[]) => void };
}

const ACTION_TIMEOUT = 10000;
const RECONNECT_MIN = 2000;
const RECONNECT_MAX = 30000;

/** Parse one AMI message block (without the terminating empty line). */
export function parseAmiMessage(block: string): AmiMessage {
  const msg: AmiMessage = {};
  for (const line of block.split(/\r?\n/)) {
    const i = line.indexOf(':');
    if (i <= 0) {
      if (line.trim()) msg.output = msg.output ? `${msg.output}\n${line}` : line;
      continue;
    }
    msg[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
  }
  return msg;
}

/** Serialise an action. Array values become repeated lines (Variable: a=1, Variable: b=2). */
export function buildAmiAction(fields: AmiFields): string {
  let out = '';
  for (const [key, value] of Object.entries(fields)) {
    if (value === undefined) continue;
    for (const v of Array.isArray(value) ? value : [value]) {
      const s = String(v);
      if (/[\r\n]/.test(s)) throw new Error(`AMI field ${key} contains a line break`);
      out += `${key}: ${s}\r\n`;
    }
  }
  return `${out}\r\n`;
}

export class AmiClient extends EventEmitter<{ state: [AmiStateInfo]; event: [AmiMessage] }> {
  state: AmiStateInfo = { state: 'disconnected' };
  /** Version from the banner, e.g. "2.10.4" (AMI 2.x = Asterisk 12+). */
  version = '';
  private readonly opts: AmiOptions;
  private socket: net.Socket | null = null;
  private buffer = '';
  private bannerSeen = false;
  private pending = new Map<string, Pending>();
  private nextId = 1;
  private stopped = true;
  private authRejected = false;
  private retryMs = RECONNECT_MIN;
  private retryTimer: NodeJS.Timeout | undefined;

  constructor(opts: AmiOptions) {
    super();
    this.opts = opts;
  }

  start(): void {
    this.stopped = false;
    this.connect();
  }

  async stop(): Promise<void> {
    this.stopped = true;
    clearTimeout(this.retryTimer);
    const s = this.socket;
    if (s && this.state.state === 'connected') {
      await this.action({ Action: 'Logoff' }, 1000).catch(() => {});
    }
    s?.destroy();
    this.socket = null;
    this.failPending(new Error('AMI connection closed'));
    this.setState('disconnected');
  }

  private setState(state: AmiConnState, error?: string): void {
    this.state = error ? { state, error } : { state };
    this.emit('state', this.state);
  }

  private connect(): void {
    if (this.stopped || this.authRejected) return;
    this.setState('connecting');
    this.buffer = '';
    this.bannerSeen = false;
    const socket = net.createConnection({ host: this.opts.host, port: this.opts.port });
    this.socket = socket;
    socket.setEncoding('utf8');
    socket.setKeepAlive(true, 30000);
    socket.on('data', (chunk: string) => this.onData(chunk));
    socket.on('error', (err: NodeJS.ErrnoException) => {
      if (this.socket !== socket) return;
      const why = err.code === 'ECONNREFUSED' ? `Connection refused by ${this.opts.host}:${this.opts.port}: is AMI enabled and the port open?` : err.message;
      this.state = { state: this.state.state, error: why };
    });
    socket.on('close', () => {
      if (this.socket !== socket) return;
      this.socket = null;
      this.failPending(new Error('AMI connection lost'));
      if (this.stopped) return;
      if (this.authRejected) return; // state already 'failed'
      const error = this.state.error ?? 'AMI connection closed';
      this.setState('disconnected', error);
      this.retryTimer = setTimeout(() => this.connect(), this.retryMs);
      this.retryMs = Math.min(this.retryMs * 2, RECONNECT_MAX);
    });
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    if (!this.bannerSeen) {
      // "Asterisk Call Manager/2.10.4\r\n": one line, not a message block.
      const nl = this.buffer.indexOf('\n');
      if (nl < 0) return;
      const banner = this.buffer.slice(0, nl).trim();
      this.buffer = this.buffer.slice(nl + 1);
      this.bannerSeen = true;
      this.version = banner.split('/')[1] ?? '';
      void this.login();
    }
    let end: number;
    while ((end = this.buffer.search(/\r?\n\r?\n/)) >= 0) {
      const block = this.buffer.slice(0, end);
      this.buffer = this.buffer.slice(end).replace(/^\r?\n\r?\n/, '');
      if (block.trim()) this.onMessage(parseAmiMessage(block));
    }
  }

  private async login(): Promise<void> {
    try {
      await this.send({ Action: 'Login', Username: this.opts.username, Secret: this.opts.secret, Events: this.opts.events ?? 'off' });
    } catch (err) {
      const message = (err as Error).message;
      if (/auth|denied|permission/i.test(message)) {
        // Never try again on our own: repeated failures get the gateway banned by fail2ban.
        this.authRejected = true;
        this.setState('failed', `AMI login rejected for "${this.opts.username}": check AMI_USER / AMI_SECRET and the permit= line in manager_custom.conf. Not retrying (fail2ban).`);
        this.socket?.destroy();
      } else {
        this.state = { state: this.state.state, error: `AMI login failed: ${message}` };
        this.socket?.destroy();
      }
      return;
    }
    this.retryMs = RECONNECT_MIN;
    this.setState('connected');
  }

  private onMessage(msg: AmiMessage): void {
    const id = msg.actionid;
    const p = id ? this.pending.get(id) : undefined;
    if (p) {
      if (msg.response !== undefined) {
        if (/^(error|failure)$/i.test(msg.response)) {
          this.settle(id!);
          p.reject(new Error(msg.message || msg.response));
        } else if (p.list) {
          p.list.response = msg;
        } else {
          this.settle(id!);
          p.resolve(msg);
        }
        return;
      }
      if (msg.event !== undefined && p.list) {
        if (/complete$/i.test(msg.event) || msg.eventlist?.toLowerCase() === 'complete') {
          this.settle(id!);
          p.list.done(p.list.events);
        } else {
          p.list.events.push(msg);
        }
        return;
      }
    }
    if (msg.event !== undefined) this.emit('event', msg);
  }

  private settle(id: string): void {
    const p = this.pending.get(id);
    if (!p) return;
    clearTimeout(p.timer);
    this.pending.delete(id);
  }

  private failPending(err: Error): void {
    for (const [id, p] of this.pending) {
      this.settle(id);
      p.reject(err);
    }
  }

  private send(fields: AmiFields, timeoutMs = ACTION_TIMEOUT, list?: (events: AmiMessage[]) => void): Promise<AmiMessage> {
    const socket = this.socket;
    if (!socket || socket.destroyed) return Promise.reject(new Error('Not connected to AMI'));
    const id = fields.ActionID ? String(fields.ActionID) : `arzen-${this.nextId++}`;
    const text = buildAmiAction({ ...fields, ActionID: id });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`AMI ${fields.Action} timed out`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer, list: list ? { events: [], response: null, done: list } : undefined });
      socket.write(text);
    });
  }

  /** Send an action and wait for its response. Rejects on "Response: Error". */
  action(fields: AmiFields, timeoutMs = ACTION_TIMEOUT): Promise<AmiMessage> {
    if (this.state.state !== 'connected') return Promise.reject(new Error('Not connected to AMI'));
    return this.send(fields, timeoutMs);
  }

  /** Send a list action (e.g. CoreShowChannels) and collect its events up to the "Complete" one. */
  actionList(fields: AmiFields, timeoutMs = ACTION_TIMEOUT): Promise<AmiMessage[]> {
    if (this.state.state !== 'connected') return Promise.reject(new Error('Not connected to AMI'));
    return new Promise((resolve, reject) => {
      this.send(fields, timeoutMs, resolve).catch(reject);
    });
  }
}
