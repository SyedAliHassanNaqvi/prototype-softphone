// The Asterisk-facing end of the media relay: one RTP/UDP socket (RFC 3550), optionally SRTP
// (RFC 3711, SDES keys from the SDP).
//
//   browser leg --sendAudio()--> [timeline rewrite] --[SRTP protect]--UDP--> Asterisk media port
//   Asterisk --UDP--> [SRTP authenticate + decrypt] --[payload type filter]--> 'audio' event
//
// Symmetric RTP: if Asterisk's audio arrives from a different address than its SDP advertised
// (Issabel with a wrong externip/localnet, NAT, strict RTP relaying...), we send to where it
// actually comes from, like X-Lite/MicroSIP do. Otherwise the PBX never hears us (one-way
// audio). Only sources listed in `latchHosts` are accepted, so a stranger on the LAN can't
// redirect the stream; with SRTP only authenticated packets count.
//
// Payloads are G.711 bytes in the law negotiated with Asterisk; the caller converts if needed.
import dgram from 'node:dgram';
import { EventEmitter } from 'node:events';
import type { CodecName } from '../sip/sdp.ts';
import { SILENCE } from './g711.ts';
import { buildRtp, parseRtp, randomUint32, RtpTimeline, type RtpInfo } from './rtp.ts';
import { SrtpContext } from './srtp.ts';

const DTMF_EVENTS: Record<string, number> = {
  0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8, 9: 9, '*': 10, '#': 11, A: 12, B: 13, C: 14, D: 15,
};

export interface RtpTarget {
  remoteIp: string;
  remotePort: number;
  codec: CodecName;
  /** Payload type number Asterisk uses for `codec`. */
  pt: number;
  /** telephone-event payload type, or null when Asterisk did not offer RFC 4733. */
  dtmfPt: number | null;
  /** False while Asterisk has us on hold (a=sendonly / a=inactive). */
  sendEnabled: boolean;
  /** SDES master keys (base64 key||salt): ours for sending, the PBX's for receiving. Null = plain RTP. */
  srtp?: { localKey: string; remoteKey: string } | null;
  /** IPs we may latch onto (symmetric RTP), normally the PBX and the SDP address. */
  latchHosts?: string[];
}

export interface Remote {
  address: string;
  port: number;
}

export class RtpEndpoint extends EventEmitter<{ audio: [RtpInfo]; error: [Error]; latched: [Remote] }> {
  localPort = 0;
  target: RtpTarget | null = null;
  muted = false;
  stats = { sent: 0, received: 0, badSrtp: 0, ignored: 0 };
  /** Where the last packet from Asterisk came from. */
  lastFrom: Remote | null = null;
  /** Address learned from Asterisk's packets when it differs from the SDP (symmetric RTP). */
  latched: Remote | null = null;
  private socket: dgram.Socket | null = null;
  private readonly ssrc = randomUint32();
  private readonly timeline = new RtpTimeline();
  private dtmfBusy = false;
  private lastInSeq: number | null = null;
  private lastInSsrc: number | null = null;
  private srtpOut: { key: string; ctx: SrtpContext } | null = null;
  private srtpIn: { key: string; ctx: SrtpContext } | null = null;

  /** Bind an even UDP port in [min, max] (Asterisk's default rtp.conf range is 10000-20000). */
  async open(min = 10000, max = 20000): Promise<number> {
    for (let attempt = 0; attempt < 50; attempt++) {
      const port = min + 2 * Math.floor(Math.random() * Math.max(1, (max - min) / 2));
      const socket = dgram.createSocket('udp4');
      try {
        await new Promise<void>((resolve, reject) => {
          socket.once('error', reject);
          socket.bind(port, () => {
            socket.off('error', reject);
            resolve();
          });
        });
      } catch {
        socket.close();
        continue;
      }
      this.socket = socket;
      this.localPort = port;
      socket.on('message', (msg, rinfo) => this.onPacket(msg, rinfo));
      socket.on('error', (err) => this.emit('error', err));
      return port;
    }
    throw new Error(`Could not bind a UDP port for RTP in ${min}-${max}`);
  }

  configure(target: RtpTarget): void {
    // New media address from the PBX (answer, re-INVITE): forget what we learned before.
    if (this.target?.remoteIp !== target.remoteIp || this.target?.remotePort !== target.remotePort) this.latched = null;
    this.target = target;
    // Contexts are kept across re-INVITEs while the key is unchanged, so the rollover counter
    // (ROC) carries on; a new key from the PBX starts a fresh receive context.
    if (target.srtp) {
      if (this.srtpOut?.key !== target.srtp.localKey) this.srtpOut = { key: target.srtp.localKey, ctx: new SrtpContext(target.srtp.localKey) };
      if (this.srtpIn?.key !== target.srtp.remoteKey) this.srtpIn = { key: target.srtp.remoteKey, ctx: new SrtpContext(target.srtp.remoteKey) };
    } else {
      this.srtpOut = null;
      this.srtpIn = null;
    }
  }

  /** True while media to/from Asterisk is SRTP. */
  get secure(): boolean {
    return this.srtpOut !== null;
  }

  /** Relay one audio packet towards Asterisk, keeping the source packet's timing. */
  sendAudio(payload: Buffer, src: { ssrc: number; seq: number; timestamp: number; marker: boolean }): void {
    const t = this.target;
    if (!t || !payload.length) return;
    const out = this.timeline.map(src, payload.length);
    if (!out) return;
    // During a DTMF event the timeline still advances, but the audio itself is not sent.
    if (!t.sendEnabled || this.dtmfBusy) return;
    // Muted: keep the stream alive with silence so Asterisk's rtptimeout doesn't hang up.
    const body = this.muted ? Buffer.alloc(payload.length, SILENCE[t.codec]) : payload;
    this.transmit(buildRtp({ pt: t.pt, marker: out.marker, seq: out.seq, timestamp: out.timestamp, ssrc: this.ssrc, payload: body }));
  }

  /**
   * RFC 4733 telephone-event: 100 ms of the digit as 5 packets every 20 ms, then 3 end packets,
   * all sharing the event's start timestamp. Returns false if Asterisk did not negotiate
   * telephone-event (the caller then falls back to SIP INFO).
   */
  sendDtmf(digit: string): boolean {
    const t = this.target;
    const event = DTMF_EVENTS[digit.toUpperCase()];
    if (!t || t.dtmfPt == null || event === undefined) return false;
    if (this.dtmfBusy) return true;
    this.dtmfBusy = true;
    const dtmfPt = t.dtmfPt;
    const startTs = (this.timeline.timestamp + 160) >>> 0;
    let n = 0;
    const tick = (): void => {
      n++;
      const end = n > 5;
      const duration = Math.min(n, 5) * 160; // 20 ms steps at 8 kHz
      const payload = Buffer.from([event, (end ? 0x80 : 0) | 10, (duration >> 8) & 0xff, duration & 0xff]);
      this.transmit(buildRtp({ pt: dtmfPt, marker: n === 1, seq: this.timeline.nextSeq(), timestamp: startTs, ssrc: this.ssrc, payload }));
      if (n < 8) setTimeout(tick, end ? 0 : 20);
      else this.dtmfBusy = false;
    };
    tick();
    return true;
  }

  /** Where our packets go: the latched source, else the SDP address. */
  get sendTo(): Remote | null {
    const t = this.target;
    if (!t || !t.remotePort) return null;
    return this.latched ?? { address: t.remoteIp, port: t.remotePort };
  }

  private transmit(packet: Buffer): void {
    const to = this.sendTo;
    if (!this.socket || !to) return;
    this.socket.send(this.srtpOut ? this.srtpOut.ctx.protect(packet) : packet, to.port, to.address);
    this.stats.sent++;
  }

  private onPacket(msg: Buffer, from: Remote): void {
    if (msg.length < 12 || (msg[0] & 0xc0) !== 0x80) return;
    const rawPt = msg[1] & 0x7f;
    if (rawPt >= 72 && rawPt <= 76) return; // (S)RTCP multiplexed on the same port: not used
    let plain = msg;
    if (this.srtpIn) {
      const decrypted = this.srtpIn.ctx.unprotect(msg);
      if (!decrypted) {
        this.stats.badSrtp++; // forged, corrupted, or plain RTP while SRTP is required
        return;
      }
      plain = decrypted;
    }
    const pkt = parseRtp(plain);
    if (!pkt) return;
    const t = this.target;
    if (!t) return;
    const trusted = from.address === t.remoteIp || (t.latchHosts ?? []).includes(from.address);
    if (!trusted) {
      this.stats.ignored++; // not the PBX: never play or latch onto it
      return;
    }
    this.stats.received++;
    this.lastFrom = { address: from.address, port: from.port };
    if (from.address !== (this.sendTo?.address ?? '') || from.port !== this.sendTo?.port) {
      this.latched = { address: from.address, port: from.port };
      this.emit('latched', this.latched);
    }
    if (pkt.pt !== t.pt) return; // telephone-event, comfort noise, stray codecs

    // Drop duplicates / late packets within one source.
    if (this.lastInSsrc === pkt.ssrc && this.lastInSeq !== null) {
      const delta = (pkt.seq - this.lastInSeq) & 0xffff;
      if (delta === 0 || delta > 0x8000) return;
    }
    this.lastInSsrc = pkt.ssrc;
    this.lastInSeq = pkt.seq;
    this.emit('audio', pkt);
  }

  close(): void {
    try {
      this.socket?.close();
    } catch {
      /* already closed */
    }
    this.socket = null;
    this.target = null;
    this.removeAllListeners('audio');
  }
}
