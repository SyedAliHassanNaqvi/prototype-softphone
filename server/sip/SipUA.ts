// Minimal SIP user agent (RFC 3261), behaving like a desk softphone (X-Lite / MicroSIP / Bria)
// towards one Asterisk / Issabel PBX, over UDP or TLS (see transport.ts):
//   * REGISTER with MD5 digest auth, refreshed before expiry, un-REGISTER on stop
//   * outbound INVITE (100/180/183/200 -> ACK), CANCEL, BYE
//   * inbound INVITE (100 Trying, 180 Ringing, 200 OK retransmitted until ACK), CANCEL, BYE
//   * answers the PBX's re-INVITEs (hold from the far end, media moved), OPTIONS, NOTIFY, INFO
//
// Every request goes to the PBX (server:port), which acts as our outbound proxy. One call at a
// time; a second inbound call gets 486 Busy Here.
//
// Media: each call owns an RtpEndpoint (RTP, or SRTP keyed with SDES a=crypto lines when
// `srtp` is on). The UA only negotiates it; the gateway moves the audio via the 'audio' event
// and sendAudio().
import dgram from 'node:dgram';
import { EventEmitter } from 'node:events';
import {
  buildMessage, buildResponse, cseqOf, getHeader, getHeaders, newBranch, newTag, parseMessage,
  parseNameAddr, parseUri, parseVia, randomHex,
  type HeaderList, type ResponseOptions, type SipMessage,
} from './message.ts';
import { buildAuthorization, parseChallenge } from './digest.ts';
import { buildSdp, CODECS, DTMF_PT, negotiate, parseSdp, pickCrypto, type CodecName, type Direction } from './sdp.ts';
import { TlsTransport, UdpTransport, type Remote, type SipTransport, type TlsSettings } from './transport.ts';
import { RtpEndpoint } from '../media/RtpEndpoint.ts';
import { generateMasterKey } from '../media/srtp.ts';
import type { RtpInfo } from '../media/rtp.ts';

const T1 = 500; // RTT estimate: first retransmission interval
const T2 = 4000; // cap for non-INVITE retransmissions
const TIMEOUT = 64 * T1; // 32 s: Timer B / F
const USER_AGENT = 'ArzenGateway/0.1';
const ALLOW = 'INVITE, ACK, CANCEL, BYE, OPTIONS, NOTIFY, INFO';

export interface SipAccount {
  server: string;
  serverPort: number;
  /** 'udp' (plain, port 5060) or 'tls' (encrypted signalling, port 5061). */
  transport: 'udp' | 'tls';
  tls?: TlsSettings;
  /** Require SRTP (RTP/SAVP + SDES a=crypto) for every call. */
  srtp: boolean;
  extension: string;
  authUser?: string;
  password: string;
  displayName?: string;
  /** Local SIP UDP port (0 = any). Falls back to a random port if taken. Unused for TLS. */
  localPort: number;
  /** IP to advertise in Via / Contact / SDP. Auto-detected when empty. */
  localIp?: string;
  /** G.711 laws in preference order. */
  codecs: CodecName[];
  rtpPortMin: number;
  rtpPortMax: number;
  registerExpires?: number;
}

export type RegistrationState = 'unregistered' | 'registering' | 'registered' | 'failed';
export interface RegistrationInfo {
  state: RegistrationState;
  error?: string;
}

export type CallState = 'idle' | 'calling' | 'ringing' | 'incoming' | 'active';
export interface CallInfo {
  state: CallState;
  direction?: 'outgoing' | 'incoming';
  number?: string;
  display?: string;
  codec?: CodecName | null;
  startedAt?: number | null;
  muted?: boolean;
  /** SRTP keys negotiated with the PBX. */
  srtp?: boolean;
  remoteHold?: boolean;
  earlyMedia?: boolean;
  /** Why the call ended (on the transition to idle). */
  reason?: string;
}

export interface MediaStats {
  localPort: number;
  sdpTarget: string | null;
  sendTo: string | null;
  lastFrom: string | null;
  sent: number;
  received: number;
  badSrtp: number;
  ignored: number;
}

export interface SipLog {
  dir: 'in' | 'out';
  peer: string;
  text: string;
}

type Rinfo = Remote;

interface RequestFields {
  method: string;
  uri: string;
  branch?: string;
  from: string;
  to: string;
  callId: string;
  cseq: number;
  route?: string[];
  contact?: boolean | string;
  extraHeaders?: HeaderList;
  body?: string;
  contentType?: string;
}

interface ClientTx {
  fields: RequestFields & { branch: string };
  provisional: boolean;
  done: boolean;
  ackText: string | null;
  cancelTimers: () => void;
  onResponse: (res: SipMessage) => void;
}

interface Call {
  id: string;
  direction: 'outgoing' | 'incoming';
  state: Exclude<CallState, 'idle'>;
  number: string;
  display: string;
  callId: string;
  localHeader: string;
  remoteHeader: string;
  remoteTarget: string;
  routeSet: string[];
  localCseq: number;
  sdpSessionId: number;
  sdpVersion: number;
  /** Codec preference for this call (the browser leg's law first). */
  codecs: CodecName[];
  codec: CodecName | null;
  pt: number | null;
  dtmfPt: number | null;
  /** SDES keys: ours (sending) and the PBX's (receiving). Null for plain RTP. */
  srtp: { tag: number; localKey: string; remoteKey: string | null } | null;
  muted: boolean;
  remoteHold: boolean;
  mediaStarted: boolean;
  ended: boolean;
  startedAt: number | null;
  rtp: RtpEndpoint;
  // outgoing
  inviteTx?: ClientTx;
  cancelRequested?: boolean;
  cancelSent?: boolean;
  // incoming
  localTag?: string;
  remoteCseq?: number;
  inviteReq?: SipMessage;
  rinfo?: Rinfo;
  answering?: boolean;
  lastResponse?: string;
  uas2xx?: { cseq: number } | null;
  uas2xxTimer?: NodeJS.Timeout;
  awaitingAckSdp?: boolean;
}

/** Human-readable explanation for SIP failure codes, aimed at someone setting up Issabel. */
export function describeStatus(status: number, reason: string, context: 'register' | 'invite'): string {
  const byCode: Record<number, string> = {
    403: context === 'register'
      ? 'Forbidden: the PBX rejected this extension (wrong secret, or a "permit/deny" IP rule).'
      : 'Forbidden: this extension is not allowed to dial that number (check outbound routes / permissions).',
    404: context === 'register' ? 'Extension not found on the PBX.' : 'Number not found: no route matches it on the PBX.',
    408: context === 'register'
      ? 'No response from the PBX. Check PBX_IP, PBX_PORT and any firewall in between.'
      : 'No answer from the network (request timeout).',
    480: 'The other party is unavailable (not registered or DND).',
    484: 'Incomplete number.',
    486: 'Busy.',
    487: 'Call cancelled.',
    488: 'No common codec (allow ulaw/alaw on the extension in Issabel).',
    500: 'PBX internal error.',
    503: 'Service unavailable: the PBX could not route the call (all trunks busy or down?).',
    603: 'Declined.',
  };
  return byCode[status] ?? `${status} ${reason}`;
}

/** Find the local IPv4 address the OS would use to reach the PBX (no packet is sent). */
function detectLocalIp(host: string, port: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const s = dgram.createSocket('udp4');
    s.once('error', (err) => {
      s.close();
      reject(err);
    });
    s.connect(port, host, () => {
      const { address } = s.address();
      s.close();
      resolve(address);
    });
  });
}

const synthetic408 = (): SipMessage => ({
  isRequest: false, method: '', uri: '', status: 408, reason: 'Request Timeout', headers: new Map(), body: '',
});

export class SipUA extends EventEmitter<{
  registration: [RegistrationInfo];
  call: [CallInfo];
  /** Media up (codec known) / down (with the call's final counters). */
  media: [{ active: true; codec: CodecName } | { active: false; stats: MediaStats | null }];
  audio: [RtpInfo];
  log: [SipLog];
  /** Symmetric RTP: the PBX's audio comes from a different address than its SDP said. */
  mediaLatch: [{ address: string; port: number }];
}> {
  registration: RegistrationInfo = { state: 'unregistered' };
  localIp = '';
  localPort = 0;
  private account: SipAccount | null = null;
  private transport: SipTransport | null = null;
  private stopped = true;
  private contactUri = '';
  private reg = { callId: '', cseq: 0, fromTag: '' };
  private transactions = new Map<string, ClientTx>(); // `${branch}:${method}`
  private ackCache = new Map<string, string>(); // `${callId}:${cseq}` -> ACK, for retransmitted 2xx
  private recentlyEnded = new Map<string, string>(); // callId -> final response, absorbs INVITE retransmissions
  private call: Call | null = null;
  private timers = new Set<NodeJS.Timeout>();
  private regRefreshTimer: NodeJS.Timeout | undefined;
  private regRetryTimer: NodeJS.Timeout | undefined;
  /** The PBX rejected our credentials: never REGISTER again on our own (fail2ban). */
  private authRejected = false;

  // ======================================================================================
  // Lifecycle
  // ======================================================================================

  async start(account: SipAccount): Promise<void> {
    await this.stop();
    if (!account.codecs.length) throw new Error('No codec configured');
    this.account = account;
    this.stopped = false;
    this.authRejected = false;
    this.setRegistration('registering');
    await this.openTransport();
  }

  /** Open the UDP socket / TLS connection and REGISTER. Retries every 30 s if the PBX is unreachable. */
  private async openTransport(): Promise<void> {
    const account = this.acct;
    const { server, serverPort } = account;
    const transport: SipTransport = account.transport === 'tls'
      ? new TlsTransport(server, serverPort, account.tls ?? { rejectUnauthorized: true })
      : new UdpTransport(account.localPort);
    transport.on('message', (buf, remote) => this.onDatagram(buf, remote));
    transport.on('error', (err) => this.emit('log', { dir: 'in', peer: '-', text: `transport error: ${err.message}` }));

    try {
      await transport.open();
      this.localIp = account.localIp || transport.localIp || (await detectLocalIp(server, serverPort));
    } catch (err) {
      transport.close();
      const what = account.transport === 'tls' ? `TLS connection to ${server}:${serverPort} failed` : 'Cannot open the SIP UDP socket';
      this.setRegistration('failed', `${what}: ${(err as Error).message}`);
      // Not an authentication failure, so retrying cannot trigger fail2ban.
      this.regRetryTimer = this.timer(() => void (this.stopped || this.openTransport()), 30000);
      return;
    }
    if (this.stopped) {
      transport.close();
      return;
    }
    this.transport = transport;
    this.setLocalAddress(transport.localPort);
    this.reg = { callId: `${randomHex(12)}@${this.localIp}`, cseq: 0, fromTag: newTag() };

    // TLS: the connection can drop and come back on a new local port. Re-REGISTER so the PBX
    // learns the new Contact, unless the credentials were rejected (fail2ban).
    transport.on('disconnected', (reason) => {
      this.emit('log', { dir: 'in', peer: '-', text: reason });
      this.clearTimer(this.regRefreshTimer);
      if (!this.authRejected) this.setRegistration('registering', 'Connection to the PBX lost, reconnecting…');
    });
    transport.on('connected', ({ localIp, localPort }) => {
      if (!account.localIp && localIp) this.localIp = localIp;
      this.setLocalAddress(localPort);
      if (!this.authRejected) void this.register();
    });
    void this.register();
  }

  private setLocalAddress(localPort: number): void {
    this.localPort = localPort;
    const tlsParam = this.acct.transport === 'tls' ? ';transport=tls' : '';
    this.contactUri = `sip:${this.acct.extension}@${this.localIp}:${this.localPort}${tlsParam}`;
  }

  async stop(): Promise<void> {
    this.stopped = true;
    this.clearTimer(this.regRefreshTimer);
    this.clearTimer(this.regRetryTimer);
    if (this.call) this.hangup();
    if (this.transport && this.registration.state === 'registered') {
      // Un-register (Expires: 0) so the PBX stops sending calls here. Don't wait more than 2 s.
      await Promise.race([this.register(0).catch(() => {}), new Promise((r) => setTimeout(r, 2000))]);
    }
    for (const t of this.timers) clearTimeout(t);
    this.timers.clear();
    for (const tx of this.transactions.values()) tx.cancelTimers();
    this.transactions.clear();
    this.ackCache.clear();
    this.recentlyEnded.clear();
    this.transport?.close();
    this.transport = null;
    if (this.registration.state !== 'unregistered') this.setRegistration('unregistered');
  }

  private timer(fn: () => void, ms: number): NodeJS.Timeout {
    const t = setTimeout(() => {
      this.timers.delete(t);
      fn();
    }, ms);
    this.timers.add(t);
    return t;
  }

  private clearTimer(t: NodeJS.Timeout | undefined): void {
    if (!t) return;
    clearTimeout(t);
    this.timers.delete(t);
  }

  private setRegistration(state: RegistrationState, error?: string): void {
    this.registration = { state, ...(error ? { error } : {}) };
    this.emit('registration', this.registration);
  }

  private get acct(): SipAccount {
    if (!this.account) throw new Error('SIP UA not started');
    return this.account;
  }

  // ======================================================================================
  // Transport
  // ======================================================================================

  private get serverHostPort(): string {
    const { server, serverPort, transport } = this.acct;
    return serverPort === (transport === 'tls' ? 5061 : 5060) ? server : `${server}:${serverPort}`;
  }

  /** The transport in use ('UDP' | 'TLS'), or null before it is open. */
  get transportProtocol(): string | null {
    return this.transport?.protocol ?? null;
  }

  private send(text: string, host = this.acct.server, port = this.acct.serverPort): void {
    if (!this.transport) return;
    this.transport.send(text, host, port);
    this.emit('log', { dir: 'out', peer: `${host}:${port}`, text });
  }

  private onDatagram(buf: Buffer, rinfo: Remote): void {
    const msg = parseMessage(buf);
    if (!msg) return; // CRLF keep-alive or junk
    this.emit('log', { dir: 'in', peer: `${rinfo.address}:${rinfo.port}`, text: buf.toString('utf8') });
    try {
      if (msg.isRequest) this.onRequest(msg, rinfo);
      else this.onResponse(msg);
    } catch (err) {
      this.emit('log', { dir: 'in', peer: '-', text: `error handling message: ${(err as Error).stack}` });
    }
  }

  private buildRequest(f: RequestFields & { branch: string }): string {
    const headers: HeaderList = [
      ['Via', `SIP/2.0/${this.transport?.protocol ?? 'UDP'} ${this.localIp}:${this.localPort};branch=${f.branch};rport`],
      ['Max-Forwards', '70'],
      ...(f.route ?? []).map((r): [string, string] => ['Route', r]),
      ['From', f.from],
      ['To', f.to],
      ['Call-ID', f.callId],
      ['CSeq', `${f.cseq} ${f.method}`],
      ...(f.contact ? [['Contact', f.contact === true ? `<${this.contactUri}>` : f.contact] as [string, string]] : []),
      ['User-Agent', USER_AGENT],
      ...(f.method === 'INVITE' || f.method === 'REGISTER' ? [['Allow', ALLOW] as [string, string]] : []),
      ...(f.extraHeaders ?? []),
      ...(f.body ? [['Content-Type', f.contentType ?? 'application/sdp'] as [string, string]] : []),
    ];
    return buildMessage({ startLine: `${f.method} ${f.uri} SIP/2.0`, headers, body: f.body ?? '' });
  }

  // ======================================================================================
  // Client transactions (RFC 3261 §17.1) with UDP retransmission timers
  // ======================================================================================

  /**
   * Send a request and resolve with its final response. Retransmits over UDP (500 ms, 1 s,
   * 2 s... capped at 4 s for non-INVITE; INVITE stops once a provisional arrives) and resolves
   * with a synthetic 408 after 32 s of silence. For a non-2xx final response to INVITE, the
   * ACK is sent here, as part of the transaction.
   */
  private transact(
    fields: RequestFields,
    { onProvisional, branch = newBranch() }: { onProvisional?: (res: SipMessage, tx: ClientTx) => void; branch?: string } = {},
  ): Promise<SipMessage> {
    const f = { ...fields, branch };
    const text = this.buildRequest(f);
    const key = `${branch}:${f.method}`;
    const isInvite = f.method === 'INVITE';

    return new Promise((resolve) => {
      let interval = T1;
      let retransTimer: NodeJS.Timeout | undefined;
      const timeoutTimer = setTimeout(() => finish(synthetic408()), TIMEOUT);

      const tx: ClientTx = {
        fields: f,
        provisional: false,
        done: false,
        ackText: null,
        cancelTimers: () => {
          clearTimeout(retransTimer);
          clearTimeout(timeoutTimer);
        },
        onResponse: (res) => {
          if (res.status < 200) {
            if (tx.done) return;
            tx.provisional = true;
            onProvisional?.(res, tx);
            return;
          }
          if (isInvite && res.status >= 300) {
            // ACK for a non-2xx final response reuses the INVITE's branch and To-tag (§17.1.1.3).
            tx.ackText ??= this.buildRequest({ ...f, method: 'ACK', to: getHeader(res, 'to') ?? f.to, contact: false, body: '', extraHeaders: [] });
            this.send(tx.ackText);
          } else if (isInvite && tx.done) {
            this.resendAck(res); // retransmitted 200 OK: our ACK was lost
          }
          finish(res);
        },
      };

      const reliable = this.transport?.reliable ?? false;
      const retransmit = (): void => {
        if (tx.done || (isInvite && tx.provisional)) return;
        this.send(text);
        if (reliable) return; // TLS: no retransmissions (§17.1.1.2), only the Timer B/F timeout
        interval = isInvite ? interval * 2 : Math.min(interval * 2, T2);
        retransTimer = setTimeout(retransmit, tx.provisional ? T2 : interval);
      };

      const finish = (res: SipMessage): void => {
        if (tx.done) return;
        tx.done = true;
        tx.cancelTimers();
        // Keep the transaction around briefly to absorb retransmitted final responses.
        this.timer(() => this.transactions.delete(key), TIMEOUT);
        resolve(res);
      };

      this.transactions.set(key, tx);
      retransmit();
    });
  }

  /**
   * transact() with digest authentication: on 401/407 compute the credentials and resend.
   * `buildFields` is called for every attempt so each retry gets a fresh CSeq.
   */
  private async sendWithAuth(
    buildFields: () => RequestFields,
    opts: { onProvisional?: (res: SipMessage, tx: ClientTx) => void } = {},
  ): Promise<SipMessage> {
    let authHeader: ((f: RequestFields) => [string, string]) | null = null;
    let challenges = 0;
    for (;;) {
      const fields = buildFields();
      if (authHeader) fields.extraHeaders = [...(fields.extraHeaders ?? []), authHeader(fields)];
      const res = await this.transact(fields, opts);
      if (res.status !== 401 && res.status !== 407) return res;

      const challenge = parseChallenge(getHeader(res, res.status === 401 ? 'www-authenticate' : 'proxy-authenticate'));
      // A second challenge with a fresh nonce (not stale=true) means the credentials are wrong.
      // Never loop here: Issabel runs fail2ban and bans IPs that keep failing auth.
      const stale = /^true$/i.test(challenge?.stale ?? '');
      if (!challenge || challenges >= 2 || (challenges === 1 && !stale)) return res;
      challenges++;

      const headerName = res.status === 401 ? 'Authorization' : 'Proxy-Authorization';
      const { authUser, extension, password } = this.acct;
      authHeader = (f) => [headerName, buildAuthorization({ challenge, method: f.method, uri: f.uri, username: authUser || extension, password }).header];
    }
  }

  private onResponse(res: SipMessage): void {
    const via = parseVia(getHeaders(res, 'via')[0]);
    const { method } = cseqOf(res);
    const tx = via && this.transactions.get(`${via.params.branch}:${method}`);
    if (tx) tx.onResponse(res);
    else if (method === 'INVITE' && res.status >= 200 && res.status < 300) this.resendAck(res);
  }

  // ======================================================================================
  // Registration
  // ======================================================================================

  private async register(expires = this.acct.registerExpires ?? 300): Promise<void> {
    if (!this.transport) return;
    const { extension, displayName } = this.acct;
    const aor = `sip:${extension}@${this.serverHostPort}`;
    const from = `${displayName ? `"${displayName}" ` : ''}<${aor}>;tag=${this.reg.fromTag}`;
    if (expires > 0) this.clearTimer(this.regRetryTimer);

    const res = await this.sendWithAuth(() => ({
      method: 'REGISTER',
      uri: `sip:${this.serverHostPort}`,
      from,
      to: `<${aor}>`,
      callId: this.reg.callId,
      cseq: ++this.reg.cseq,
      contact: `<${this.contactUri}>;expires=${expires}`,
      extraHeaders: [['Expires', String(expires)]],
    }));

    if (expires === 0) {
      this.setRegistration('unregistered');
      return;
    }
    if (!this.transport) return; // stopped meanwhile

    if (res.status >= 200 && res.status < 300) {
      // The PBX may grant a different expiry than we asked for; refresh a bit before it runs out.
      const ours = getHeaders(res, 'contact').map(parseNameAddr).find((c) => c.uri.includes(`${this.localIp}:${this.localPort}`));
      const granted = Number(ours?.params.expires ?? getHeader(res, 'expires') ?? expires) || expires;
      this.regRefreshTimer = this.timer(() => void this.register(expires), Math.max(granted * 0.85, 15) * 1000);
      this.setRegistration('registered');
      return;
    }

    const authFailed = res.status === 401 || res.status === 407;
    this.authRejected = authFailed || res.status === 403;
    const error = authFailed ? 'Authentication failed: wrong extension, auth user or secret.' : describeStatus(res.status, res.reason, 'register');
    this.setRegistration('failed', error);
    // Retry transient failures only. Never auto-retry bad credentials (fail2ban).
    if (!authFailed && res.status !== 403 && res.status !== 404) {
      this.regRetryTimer = this.timer(() => void this.register(expires), 30000);
    }
  }

  // ======================================================================================
  // Call helpers
  // ======================================================================================

  get callInfo(): CallInfo {
    const c = this.call;
    if (!c) return { state: 'idle' };
    return {
      state: c.state,
      direction: c.direction,
      number: c.number,
      display: c.display,
      codec: c.codec,
      startedAt: c.startedAt,
      muted: c.muted,
      srtp: Boolean(c.srtp?.remoteKey),
      remoteHold: c.remoteHold,
      earlyMedia: c.mediaStarted && !c.startedAt,
    };
  }

  private emitCall(extra: Partial<CallInfo> = {}): void {
    this.emit('call', { ...this.callInfo, ...extra });
  }

  private targetUri(number: string): string {
    const n = number.trim();
    if (/^sips?:/i.test(n)) return n;
    if (n.includes('@')) return `sip:${n}`;
    // Keep digits, +, * and #; drop formatting such as spaces, dashes and brackets. '#' must be escaped in a URI.
    const user = n.replace(/[^\d+*#a-zA-Z]/g, '').replace(/#/g, '%23');
    return `sip:${user}@${this.serverHostPort}`;
  }

  private localSdp(call: Call, direction: Direction = 'sendrecv'): string {
    call.sdpVersion++;
    const codecs = call.codec && call.pt !== null ? [{ name: call.codec, pt: call.pt }] : call.codecs.map((c) => CODECS[c]);
    return buildSdp({
      ip: this.localIp,
      port: call.rtp.localPort,
      sessionId: call.sdpSessionId,
      version: call.sdpVersion,
      codecs,
      dtmfPt: call.codec ? call.dtmfPt : DTMF_PT,
      direction,
      crypto: call.srtp ? { tag: call.srtp.tag, keyB64: call.srtp.localKey } : null,
    });
  }

  /** Apply a remote SDP (answer or offer) to the call's RTP endpoint. Returns an error string or null. */
  private applyRemoteSdp(call: Call, sdpText: string, { isAnswer }: { isAnswer: boolean }): string | null {
    const remote = parseSdp(sdpText);
    if (!remote) return 'No audio stream in the remote SDP.';
    if (this.acct.srtp) {
      // Encrypted mode is strict: never fall back to plain RTP.
      if (!remote.secure) return 'The PBX offered/answered plain RTP but PBX_ENCRYPTION is on: set encryption=yes (media_encryption=sdes) on the extension.';
      const line = pickCrypto(remote);
      if (!line) return 'The PBX offered no usable SRTP key (AES_CM_128_HMAC_SHA1_80 without MKI is required).';
      call.srtp ??= { tag: line.tag, localKey: generateMasterKey(), remoteKey: null };
      // As answerer we reply with the tag of the line we accepted; as offerer the PBX echoes ours.
      if (!isAnswer) call.srtp.tag = line.tag;
      call.srtp.remoteKey = line.keyB64;
    } else if (remote.secure) {
      return 'The PBX requires SRTP: set PBX_ENCRYPTION=true (and PBX_TRANSPORT=tls), or encryption=no on the extension.';
    }
    const neg = negotiate(remote, call.codec ? [call.codec] : call.codecs, { remoteOrder: isAnswer });
    if (!neg) return 'No common codec with the PBX (allow ulaw or alaw on the extension).';

    call.codec = neg.codec.name;
    call.pt = neg.codec.pt;
    call.dtmfPt = neg.dtmfPt;
    call.remoteHold = remote.direction === 'sendonly' || remote.direction === 'inactive' || remote.ip === '0.0.0.0';
    call.rtp.configure({
      remoteIp: remote.ip,
      remotePort: remote.port,
      codec: call.codec,
      pt: call.pt,
      dtmfPt: call.dtmfPt,
      sendEnabled: remote.direction !== 'sendonly' && remote.direction !== 'inactive' && remote.port !== 0,
      srtp: call.srtp?.remoteKey ? { localKey: call.srtp.localKey, remoteKey: call.srtp.remoteKey } : null,
      latchHosts: [this.acct.server],
    });

    if (!call.mediaStarted) {
      call.mediaStarted = true;
      call.rtp.on('audio', (pkt) => this.emit('audio', pkt));
    }
    this.emit('media', { active: true, codec: call.codec });
    return null;
  }

  private newCall(fields: Pick<Call, 'direction' | 'state' | 'number' | 'display' | 'callId' | 'localHeader' | 'remoteHeader' | 'remoteTarget' | 'routeSet' | 'codecs'> & Partial<Call>): Call {
    const rtp = new RtpEndpoint();
    rtp.on('error', (err) => this.emit('log', { dir: 'in', peer: 'rtp', text: `RTP error: ${err.message}` }));
    rtp.on('latched', (to) => this.emit('mediaLatch', to));
    return {
      id: randomHex(4),
      localCseq: Math.floor(Math.random() * 10000),
      sdpSessionId: Math.floor(Math.random() * 1e9),
      sdpVersion: 0,
      codec: null,
      pt: null,
      dtmfPt: null,
      // Our SRTP key exists from the start so any offer we make (INVITE, late-offer 200) carries it.
      srtp: this.acct.srtp ? { tag: 1, localKey: generateMasterKey(), remoteKey: null } : null,
      muted: false,
      remoteHold: false,
      mediaStarted: false,
      ended: false,
      startedAt: null,
      rtp,
      ...fields,
    };
  }

  private openRtp(call: Call): Promise<number> {
    return call.rtp.open(this.acct.rtpPortMin, this.acct.rtpPortMax);
  }

  /** In-dialog request fields (BYE, re-INVITE, INFO). */
  private dialogFields(call: Call, method: string, extra: Partial<RequestFields> = {}): RequestFields {
    return {
      method,
      uri: call.remoteTarget,
      from: call.localHeader,
      to: call.remoteHeader,
      callId: call.callId,
      cseq: ++call.localCseq,
      route: call.routeSet,
      ...extra,
    };
  }

  private sendAck(call: Call, cseq: number): void {
    const text = this.buildRequest({
      method: 'ACK',
      uri: call.remoteTarget,
      branch: newBranch(), // ACK for 2xx is its own transaction (§13.2.2.4)
      from: call.localHeader,
      to: call.remoteHeader,
      callId: call.callId,
      cseq,
      route: call.routeSet,
    });
    const key = `${call.callId}:${cseq}`;
    this.ackCache.set(key, text);
    this.timer(() => this.ackCache.delete(key), TIMEOUT);
    this.send(text);
  }

  private resendAck(res: SipMessage): void {
    const text = this.ackCache.get(`${getHeader(res, 'call-id')}:${cseqOf(res).seq}`);
    if (text) this.send(text);
  }

  /** Take the dialog state (remote tag, target, route set) from a 2xx/1xx response to our INVITE. */
  private dialogFromResponse(call: Call, res: SipMessage): void {
    call.remoteHeader = getHeader(res, 'to') ?? call.remoteHeader;
    const contact = getHeaders(res, 'contact')[0];
    if (contact) call.remoteTarget = parseNameAddr(contact).uri;
    call.routeSet = getHeaders(res, 'record-route').slice().reverse();
  }

  private endCall(call: Call, reason = ''): void {
    if (call.ended) return;
    call.ended = true;
    this.clearTimer(call.uas2xxTimer);
    const stats = this.call === call ? this.mediaStats : null; // read before the socket and call are gone
    call.rtp.close();
    if (this.call === call) {
      this.call = null;
      this.emitCall({ reason });
      if (call.mediaStarted) this.emit('media', { active: false, stats });
    }
  }

  // ======================================================================================
  // Outbound calls
  // ======================================================================================

  /**
   * Place a call. `codecs` overrides the account's preference for this call (the gateway puts
   * the browser leg's law first so no transcoding is needed when Asterisk agrees).
   */
  async makeCall(number: string, codecs: CodecName[] = this.acct.codecs): Promise<void> {
    if (this.registration.state !== 'registered') throw new Error('Not registered to the PBX');
    if (this.call) throw new Error('Already in a call');
    if (!number.trim()) throw new Error('Enter a number');

    const { extension, displayName } = this.acct;
    const targetUri = this.targetUri(number);
    const call = this.newCall({
      direction: 'outgoing',
      state: 'calling',
      number: parseUri(targetUri)?.user || number,
      display: '',
      callId: `${randomHex(12)}@${this.localIp}`,
      localHeader: `${displayName ? `"${displayName}" ` : ''}<sip:${extension}@${this.serverHostPort}>;tag=${newTag()}`,
      remoteHeader: `<${targetUri}>`,
      remoteTarget: targetUri,
      routeSet: [],
      codecs,
    });
    this.call = call;
    this.emitCall();

    try {
      await this.openRtp(call);
    } catch (err) {
      this.endCall(call, (err as Error).message);
      return;
    }
    if (call.ended) return;
    const offer = this.localSdp(call);
    const res = await this.sendWithAuth(
      () => this.dialogFields(call, 'INVITE', { uri: targetUri, to: `<${targetUri}>`, contact: true, body: offer, route: [] }),
      {
        onProvisional: (prov, tx) => {
          call.inviteTx = tx;
          // Hung up before the PBX said anything: CANCEL is only allowed after a provisional (§9.1).
          if (call.cancelRequested) {
            this.sendCancel(call);
            return;
          }
          if (call.ended) return;
          if (prov.status === 180 || prov.status === 183) {
            call.state = 'ringing';
            // 183 Session Progress with SDP = early media (ringback / announcements from the PSTN).
            if (prov.body && getHeader(prov, 'to')?.includes('tag=')) {
              this.dialogFromResponse(call, prov);
              const err = this.applyRemoteSdp(call, prov.body, { isAnswer: true });
              if (err) this.emit('log', { dir: 'in', peer: '-', text: `early media ignored: ${err}` });
            }
            this.emitCall();
          }
        },
      },
    );

    const { seq } = cseqOf(res);
    if (res.status >= 200 && res.status < 300) {
      this.dialogFromResponse(call, res);
      this.sendAck(call, seq);
      if (call.ended) {
        // We hung up while the 200 OK was in flight: ACK it, then BYE.
        void this.transact(this.dialogFields(call, 'BYE'));
        return;
      }
      const err = this.applyRemoteSdp(call, res.body, { isAnswer: true });
      if (err) {
        void this.transact(this.dialogFields(call, 'BYE'));
        this.endCall(call, err);
        return;
      }
      call.state = 'active';
      call.startedAt = Date.now();
      this.emitCall();
      return;
    }

    if (call.ended) return; // we cancelled; the 487 is expected
    const authFailed = res.status === 401 || res.status === 407;
    this.endCall(call, authFailed ? 'The PBX refused to authenticate the call.' : describeStatus(res.status, res.reason, 'invite'));
  }

  private sendCancel(call: Call): void {
    if (call.cancelSent || !call.inviteTx) return;
    call.cancelSent = true;
    const inv = call.inviteTx.fields;
    // CANCEL copies the INVITE's Request-URI, Via branch, From, To, Call-ID and CSeq number (§9.1).
    void this.transact(
      { method: 'CANCEL', uri: inv.uri, from: inv.from, to: inv.to, callId: inv.callId, cseq: inv.cseq, route: inv.route },
      { branch: inv.branch },
    );
  }

  // ======================================================================================
  // Inbound calls
  // ======================================================================================

  private respond(req: SipMessage, rinfo: Rinfo, status: number, reason: string, opts?: ResponseOptions): string {
    const text = buildResponse(req, status, reason, opts);
    this.send(text, rinfo.address, rinfo.port);
    return text;
  }

  private rememberEnded(callId: string, response: string): void {
    this.recentlyEnded.set(callId, response);
    this.timer(() => this.recentlyEnded.delete(callId), TIMEOUT);
  }

  private onRequest(req: SipMessage, rinfo: Rinfo): void {
    const callId = getHeader(req, 'call-id') ?? '';
    const call = this.call && this.call.callId === callId ? this.call : null;

    switch (req.method) {
      case 'INVITE':
        this.onInvite(req, rinfo, call);
        return;
      case 'ACK':
        if (call?.uas2xx && cseqOf(req).seq === call.uas2xx.cseq) {
          this.clearTimer(call.uas2xxTimer);
          call.uas2xx = null;
          if (call.awaitingAckSdp && req.body) {
            call.awaitingAckSdp = false;
            const err = this.applyRemoteSdp(call, req.body, { isAnswer: true });
            if (err) this.hangup(err);
          }
        }
        return;
      case 'BYE':
        if (!call) {
          this.respond(req, rinfo, 481, 'Call/Transaction Does Not Exist');
          return;
        }
        this.respond(req, rinfo, 200, 'OK');
        this.endCall(call, 'The other party hung up.');
        return;
      case 'CANCEL':
        if (!call || call.state !== 'incoming' || !call.inviteReq) {
          this.respond(req, rinfo, 481, 'Call/Transaction Does Not Exist');
          return;
        }
        this.respond(req, rinfo, 200, 'OK');
        this.rememberEnded(callId, this.respond(call.inviteReq, rinfo, 487, 'Request Terminated', { toTag: call.localTag }));
        this.endCall(call, `Missed call from ${call.display || call.number}.`);
        return;
      case 'OPTIONS':
        this.respond(req, rinfo, 200, 'OK', { extraHeaders: [['Allow', ALLOW], ['Accept', 'application/sdp'], ['User-Agent', USER_AGENT]] });
        return;
      case 'NOTIFY':
      case 'INFO':
      case 'MESSAGE':
        this.respond(req, rinfo, 200, 'OK');
        return;
      default:
        this.respond(req, rinfo, 501, 'Not Implemented', { extraHeaders: [['Allow', ALLOW]] });
    }
  }

  private onInvite(req: SipMessage, rinfo: Rinfo, call: Call | null): void {
    const callId = getHeader(req, 'call-id') ?? '';
    const toTag = parseNameAddr(getHeader(req, 'to')).params.tag;

    if (call && toTag) {
      this.onReInvite(req, rinfo, call);
      return;
    }
    if (call) {
      // Retransmission of the initial INVITE: repeat our latest response.
      if (call.lastResponse) this.send(call.lastResponse, rinfo.address, rinfo.port);
      return;
    }
    const ended = this.recentlyEnded.get(callId);
    if (ended) {
      this.send(ended, rinfo.address, rinfo.port);
      return;
    }
    if (toTag) {
      this.respond(req, rinfo, 481, 'Call/Transaction Does Not Exist');
      return;
    }
    if (this.call) {
      this.respond(req, rinfo, 486, 'Busy Here', { toTag: newTag() });
      return;
    }

    this.respond(req, rinfo, 100, 'Trying');
    const from = parseNameAddr(getHeader(req, 'from'));
    const localTag = newTag();
    const incoming = this.newCall({
      direction: 'incoming',
      state: 'incoming',
      number: parseUri(from.uri)?.user || from.uri,
      display: from.display,
      callId,
      localTag,
      localHeader: `${getHeader(req, 'to')};tag=${localTag}`,
      remoteHeader: getHeader(req, 'from') ?? '',
      remoteTarget: parseNameAddr(getHeaders(req, 'contact')[0] ?? '').uri || from.uri,
      routeSet: getHeaders(req, 'record-route'),
      remoteCseq: cseqOf(req).seq,
      inviteReq: req,
      rinfo,
      codecs: this.acct.codecs,
    });
    this.call = incoming;
    incoming.lastResponse = this.respond(req, rinfo, 180, 'Ringing', { toTag: localTag, extraHeaders: [['Contact', `<${this.contactUri}>`]] });
    this.emitCall();
  }

  /** Send a 2xx to an INVITE and retransmit it until the ACK arrives (§13.3.1.4). */
  private sendReliable2xx(call: Call, req: SipMessage, rinfo: Rinfo, sdp: string): void {
    const text = this.respond(req, rinfo, 200, 'OK', {
      toTag: call.localTag,
      extraHeaders: [['Contact', `<${this.contactUri}>`], ['Allow', ALLOW], ['Content-Type', 'application/sdp'], ['User-Agent', USER_AGENT]],
      body: sdp,
    });
    call.lastResponse = text;
    call.uas2xx = { cseq: cseqOf(req).seq };
    let interval = T1;
    const started = Date.now();
    const again = (): void => {
      if (!call.uas2xx || call.ended) return;
      if (Date.now() - started > TIMEOUT) {
        this.hangup('No ACK from the PBX. The call was dropped.');
        return;
      }
      this.send(text, rinfo.address, rinfo.port);
      interval = Math.min(interval * 2, T2);
      call.uas2xxTimer = this.timer(again, interval);
    };
    call.uas2xxTimer = this.timer(again, interval);
  }

  /** Answer the ringing inbound call. `codecs` sets the preference used to pick from the PBX offer. */
  async answer(codecs: CodecName[] = this.acct.codecs): Promise<void> {
    const call = this.call;
    if (!call || call.state !== 'incoming' || call.answering || !call.inviteReq || !call.rinfo) return;
    call.answering = true;
    call.codecs = codecs;
    const req = call.inviteReq;
    const rinfo = call.rinfo;
    try {
      await this.openRtp(call);
    } catch (err) {
      this.rememberEnded(call.callId, this.respond(req, rinfo, 500, 'Server Internal Error', { toTag: call.localTag }));
      this.endCall(call, (err as Error).message);
      return;
    }
    if (call.ended) return; // caller hung up while we were binding the RTP port

    if (req.body) {
      const err = this.applyRemoteSdp(call, req.body, { isAnswer: false });
      if (err) {
        this.rememberEnded(call.callId, this.respond(req, rinfo, 488, 'Not Acceptable Here', { toTag: call.localTag }));
        this.endCall(call, err);
        return;
      }
    } else {
      call.awaitingAckSdp = true; // late offer: we offer in the 200, the answer comes in the ACK
    }

    this.sendReliable2xx(call, req, rinfo, this.localSdp(call));
    call.state = 'active';
    call.startedAt = Date.now();
    this.emitCall();
  }

  /** Decline the ringing inbound call (486 Busy Here by default). */
  reject(status = 486, reason = 'Busy Here', why = ''): void {
    const call = this.call;
    if (!call || call.state !== 'incoming' || call.answering || !call.inviteReq || !call.rinfo) return;
    this.rememberEnded(call.callId, this.respond(call.inviteReq, call.rinfo, status, reason, { toTag: call.localTag }));
    this.endCall(call, why);
  }

  /** PBX-initiated re-INVITE: hold from the far end, codec change, media moved elsewhere... */
  private onReInvite(req: SipMessage, rinfo: Rinfo, call: Call): void {
    const { seq } = cseqOf(req);
    if (call.remoteCseq !== undefined && seq <= call.remoteCseq) {
      if (call.lastResponse) this.send(call.lastResponse, rinfo.address, rinfo.port);
      return;
    }
    call.remoteCseq = seq;
    const contact = getHeaders(req, 'contact')[0];
    if (contact) call.remoteTarget = parseNameAddr(contact).uri;
    call.localTag ??= parseNameAddr(getHeader(req, 'to')).params.tag as string | undefined;

    let direction: Direction = 'sendrecv';
    if (req.body) {
      const err = this.applyRemoteSdp(call, req.body, { isAnswer: false });
      if (err) {
        this.respond(req, rinfo, 488, 'Not Acceptable Here');
        return;
      }
      // Answer the direction: if they only send, we only receive, and so on.
      const remote = parseSdp(req.body);
      if (remote?.direction === 'sendonly') direction = 'recvonly';
      if (remote?.direction === 'inactive') direction = 'inactive';
    } else {
      call.awaitingAckSdp = true;
    }
    this.sendReliable2xx(call, req, rinfo, this.localSdp(call, direction));
    this.emitCall();
  }

  // ======================================================================================
  // In-call controls
  // ======================================================================================

  hangup(reason = ''): void {
    const call = this.call;
    if (!call) return;
    if (call.direction === 'incoming' && call.state === 'incoming') {
      this.reject(486, 'Busy Here', reason);
      return;
    }

    if (call.direction === 'outgoing' && !call.startedAt) {
      // Not answered yet: CANCEL. The INVITE then completes with 487, or 200 if it raced (then we BYE).
      call.cancelRequested = true;
      if (call.inviteTx?.provisional) this.sendCancel(call);
      this.endCall(call, reason);
      return;
    }

    void this.transact(this.dialogFields(call, 'BYE'));
    this.endCall(call, reason);
  }

  setMute(muted: boolean): void {
    const call = this.call;
    if (!call) return;
    call.muted = muted;
    call.rtp.muted = muted;
    this.emitCall();
  }

  sendDtmf(digit: string): void {
    const call = this.call;
    if (!call || !call.startedAt) return;
    if (call.rtp.sendDtmf(digit)) return;
    // No telephone-event negotiated: fall back to SIP INFO (Asterisk: dtmfmode=info or auto).
    void this.transact(this.dialogFields(call, 'INFO', { body: `Signal=${digit}\r\nDuration=160\r\n`, contentType: 'application/dtmf-relay' }));
  }

  /** Relay one G.711 packet (already in the law negotiated with Asterisk) to the PBX. */
  sendAudio(payload: Buffer, src: { ssrc: number; seq: number; timestamp: number; marker: boolean }): void {
    const call = this.call;
    if (call && call.mediaStarted && !call.ended) call.rtp.sendAudio(payload, src);
  }

  /** RTP counters and addresses of the current call, for diagnostics. */
  get mediaStats(): MediaStats | null {
    const rtp = this.call?.mediaStarted ? this.call.rtp : null;
    if (!rtp) return null;
    const fmt = (r: { address: string; port: number } | null): string | null => (r ? `${r.address}:${r.port}` : null);
    return {
      localPort: rtp.localPort,
      sdpTarget: rtp.target ? `${rtp.target.remoteIp}:${rtp.target.remotePort}` : null,
      sendTo: fmt(rtp.sendTo),
      lastFrom: fmt(rtp.lastFrom),
      ...rtp.stats,
    };
  }

  /** Codec currently negotiated with Asterisk, or null before media is up. */
  get mediaCodec(): CodecName | null {
    return this.call?.mediaStarted ? this.call.codec : null;
  }
}
