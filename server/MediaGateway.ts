// Ties the three pieces together:
//
//   browser <--WebSocket signalling--> MediaGateway <--SipUA (SIP/UDP)--------> Asterisk
//   browser <--WebRTC (BrowserPeer)--> MediaGateway <--RtpEndpoint (RTP/UDP)--> Asterisk
//
// One extension, one browser session, one call. A new browser tab that joins takes over the
// session; a call in progress keeps running and its audio moves to the new tab once that tab's
// WebRTC leg connects.
import type { WebSocket } from 'ws';
import type { ClientMessage, GatewayStatus, ServerMessage } from '../shared/protocol.ts';
import { transcode } from './media/g711.ts';
import type { MediaStats, SipUA } from './sip/SipUA.ts';
import type { CodecName } from './sip/sdp.ts';
import { BrowserPeer } from './webrtc/BrowserPeer.ts';

export interface MediaGatewayOptions {
  extension: string;
  pbx: string;
  transport: 'udp' | 'tls';
  encryption: boolean;
  /** G.711 laws in preference order; the first one is used on the browser leg. */
  codecs: CodecName[];
  webrtcPortRange?: [number, number];
  stunServers?: string[];
  log?: (line: string) => void;
}

interface Session {
  ws: WebSocket;
  peer: BrowserPeer | null;
  alive: boolean;
}

const HEARTBEAT_MS = 15000;
const MEDIA_LOG_MS = 5000;

export class MediaGateway {
  private readonly ua: SipUA;
  private readonly opts: MediaGatewayOptions;
  private readonly browserCodec: CodecName;
  private session: Session | null = null;
  private lastEndReason = '';
  private readonly heartbeat: NodeJS.Timeout;
  /** Packets relayed on the browser leg during the current call. */
  private media = { fromBrowser: 0, toBrowser: 0 };
  private mediaTimer: NodeJS.Timeout | undefined;

  constructor(ua: SipUA, opts: MediaGatewayOptions) {
    this.ua = ua;
    this.opts = opts;
    this.browserCodec = opts.codecs[0];

    ua.on('registration', () => this.pushStatus());
    ua.on('media', (m) => {
      if (!m.active) this.logMedia(m.stats);
      this.pushStatus();
    });
    ua.on('mediaLatch', (to) => {
      const st = ua.mediaStats;
      this.log(`media: PBX audio comes from ${to.address}:${to.port} but its SDP said ${st?.sdpTarget}; sending there instead (symmetric RTP)`);
    });
    ua.on('call', (call) => {
      this.lastEndReason = call.state === 'idle' ? call.reason ?? '' : '';
      if (call.state === 'calling' || call.state === 'incoming') this.media = { fromBrowser: 0, toBrowser: 0 };
      if (call.state === 'active' && !this.mediaTimer) this.mediaTimer = setInterval(() => this.logMedia(), MEDIA_LOG_MS);
      if (call.state === 'idle' && this.mediaTimer) {
        clearInterval(this.mediaTimer);
        this.mediaTimer = undefined;
      }
      if (call.state === 'incoming' && this.session?.peer?.state !== 'connected') {
        // Nobody can take the call: let Asterisk route it to voicemail / the next step.
        this.log(`incoming call from ${call.number} rejected: no browser connected`);
        ua.reject(480, 'Temporarily Unavailable', 'No browser connected.');
        return;
      }
      this.log(`call ${call.state}${call.number ? ` ${call.number}` : ''}${call.reason ? ` (${call.reason})` : ''}`);
      this.pushStatus();
    });

    // Asterisk -> browser
    ua.on('audio', (pkt) => {
      const peer = this.session?.peer;
      const codec = ua.mediaCodec;
      if (!peer || !codec) return;
      this.media.toBrowser++;
      peer.sendAudio(transcode(pkt.payload, codec, peer.codec), pkt);
    });

    // Drop browsers that vanished without closing the socket (laptop lid, network change).
    this.heartbeat = setInterval(() => {
      const s = this.session;
      if (!s) return;
      if (!s.alive) {
        s.ws.terminate();
        return;
      }
      s.alive = false;
      s.ws.ping();
    }, HEARTBEAT_MS);
  }

  private log(line: string): void {
    this.opts.log?.(line);
  }

  /**
   * One line per 5 s during a call, showing where audio stops:
   *   browser -> gateway -> PBX   (what the other party hears)
   *   PBX -> gateway -> browser   (what you hear)
   */
  private logMedia(finalStats?: MediaStats | null): void {
    const final = finalStats !== undefined;
    const st = final ? finalStats : this.ua.mediaStats;
    if (!st) return;
    const m = this.media;
    this.log(
      `media${final ? ' (call end)' : ''}: you→PBX [browser→gw ${m.fromBrowser}, gw→PBX ${st.sent} to ${st.sendTo}${st.sendTo !== st.sdpTarget ? ` (SDP said ${st.sdpTarget})` : ''}]` +
        ` | PBX→you [PBX→gw ${st.received} from ${st.lastFrom ?? '-'}, gw→browser ${m.toBrowser}]` +
        `${st.badSrtp ? ` | bad SRTP ${st.badSrtp}` : ''}${st.ignored ? ` | ignored ${st.ignored} from unknown hosts` : ''} | local RTP port ${st.localPort}`,
    );
    if (!final && m.fromBrowser === 0) this.log('media: WARNING no audio from the browser. Check the microphone (Windows sound settings / the browser mic permission and device).');
  }

  status(): GatewayStatus {
    const call = this.ua.callInfo;
    return {
      registration: {
        ...this.ua.registration,
        extension: this.opts.extension,
        pbx: this.opts.pbx,
        transport: this.opts.transport,
        encryption: this.opts.encryption,
      },
      call: {
        ...call,
        browserCodec: call.codec ? this.browserCodec : null,
        ...(call.state === 'idle' && this.lastEndReason ? { reason: this.lastEndReason } : {}),
      },
      peer: this.session?.peer?.state ?? 'new',
    };
  }

  private send(ws: WebSocket, msg: ServerMessage): void {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(msg));
  }

  private pushStatus(): void {
    if (this.session) this.send(this.session.ws, { type: 'status', status: this.status() });
  }

  /** Handle one browser WebSocket connection. */
  handleSocket(ws: WebSocket): void {
    ws.on('message', (data) => {
      let msg: ClientMessage;
      try {
        msg = JSON.parse(data.toString()) as ClientMessage;
      } catch {
        this.send(ws, { type: 'error', message: 'Invalid JSON' });
        return;
      }
      this.onMessage(ws, msg).catch((err: Error) => {
        this.log(`error handling ${msg.type}: ${err.message}`);
        this.send(ws, { type: 'error', message: err.message });
      });
    });
    ws.on('pong', () => {
      if (this.session?.ws === ws) this.session.alive = true;
    });
    ws.on('close', () => {
      if (this.session?.ws !== ws) return;
      this.log('browser disconnected');
      void this.session.peer?.close();
      this.session = null;
      // Without a browser nobody can hear the call.
      this.ua.hangup('Browser disconnected.');
    });
  }

  private async onMessage(ws: WebSocket, msg: ClientMessage): Promise<void> {
    if (msg.type === 'join') {
      const old = this.session;
      if (old && old.ws !== ws) {
        this.send(old.ws, { type: 'error', message: 'This softphone was opened in another tab.' });
        void old.peer?.close();
        old.ws.close(4001, 'replaced');
      }
      this.session = { ws, peer: null, alive: true };
      this.log('browser joined');
      this.pushStatus();
      return;
    }

    const session = this.session;
    if (!session || session.ws !== ws) throw new Error('Send "join" first.');

    switch (msg.type) {
      case 'offer': {
        void session.peer?.close();
        const peer = new BrowserPeer({ codec: this.browserCodec, portRange: this.opts.webrtcPortRange, stunServers: this.opts.stunServers });
        session.peer = peer;
        peer.on('state', (s) => {
          if (session.peer !== peer) return;
          this.log(`browser WebRTC ${s}`);
          if ((s === 'failed' || s === 'closed') && this.ua.callInfo.state !== 'idle') this.ua.hangup('Browser audio connection lost.');
          this.pushStatus();
        });
        // browser -> Asterisk
        peer.on('audio', (pkt) => {
          const codec = this.ua.mediaCodec;
          if (session.peer !== peer || !codec) return;
          this.media.fromBrowser++;
          this.ua.sendAudio(transcode(pkt.payload, peer.codec, codec), pkt);
        });
        const sdp = await peer.answer(msg.sdp);
        this.send(ws, { type: 'answer', sdp });
        return;
      }
      case 'candidate':
        await session.peer?.addCandidate(msg.candidate);
        return;
      case 'dial': {
        if (session.peer?.state !== 'connected') throw new Error('Browser audio is not connected yet.');
        const number = String(msg.number ?? '').trim();
        // Digits, * # +, SIP URIs; spaces, dashes and brackets are stripped by the UA.
        if (!/^[\w+*#.@:()\s-]{1,64}$/.test(number)) throw new Error('Enter a valid number or extension.');
        this.log(`dial ${number}`);
        await this.ua.makeCall(number, this.codecOrder());
        return;
      }
      case 'hangup':
        this.ua.hangup();
        return;
      case 'accept':
        if (session.peer?.state !== 'connected') throw new Error('Browser audio is not connected yet.');
        await this.ua.answer(this.codecOrder());
        return;
      case 'reject':
        this.ua.reject();
        return;
      case 'mute':
        this.ua.setMute(Boolean(msg.muted));
        return;
      case 'dtmf':
        if (/^[0-9*#A-D]$/i.test(msg.digit)) this.ua.sendDtmf(msg.digit);
        return;
      default:
        throw new Error(`Unknown message type ${(msg as { type: string }).type}`);
    }
  }

  /** Browser law first, so Asterisk can match it and no transcoding is needed. */
  private codecOrder(): CodecName[] {
    return [this.browserCodec, ...this.opts.codecs.filter((c) => c !== this.browserCodec)];
  }

  async close(): Promise<void> {
    clearInterval(this.heartbeat);
    clearInterval(this.mediaTimer);
    const s = this.session;
    this.session = null;
    if (s) {
      await s.peer?.close();
      s.ws.close(1001, 'gateway shutting down');
    }
  }
}
