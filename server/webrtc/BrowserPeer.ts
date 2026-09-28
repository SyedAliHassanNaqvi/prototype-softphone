// The browser-facing end of the media relay: a werift RTCPeerConnection that terminates the
// browser's WebRTC audio (ICE + DTLS-SRTP).
//
// Only one G.711 law is offered to the browser, so every browser packet is already a G.711
// frame the gateway can hand to Asterisk without decoding. Every browser supports PCMU/PCMA
// in WebRTC; Opus is left out on purpose (it would need a full decode/encode per packet).
//
// The peer connection lives for the whole browser session and is reused across calls.
import { EventEmitter } from 'node:events';
import { MediaStreamTrack, RTCPeerConnection, RTCRtpCodecParameters, RtpHeader, RtpPacket } from 'werift';
import type { PeerState } from '../../shared/protocol.ts';
import { CODECS, type CodecName } from '../sip/sdp.ts';
import { RtpTimeline, type RtpInfo } from '../media/rtp.ts';

export interface BrowserPeerOptions {
  codec: CodecName;
  /** UDP port range for ICE, e.g. to open a firewall. Undefined = any port. */
  portRange?: [number, number];
  /** STUN servers; empty on a LAN. */
  stunServers?: string[];
}

export class BrowserPeer extends EventEmitter<{ audio: [RtpInfo]; state: [PeerState] }> {
  readonly codec: CodecName;
  state: PeerState = 'new';
  private readonly pc: RTCPeerConnection;
  private readonly track = new MediaStreamTrack({ kind: 'audio' });
  private readonly timeline = new RtpTimeline();
  private negotiated = false;

  constructor({ codec, portRange, stunServers = [] }: BrowserPeerOptions) {
    super();
    this.codec = codec;
    this.pc = new RTCPeerConnection({
      codecs: {
        audio: [new RTCRtpCodecParameters({ mimeType: `audio/${codec}`, clockRate: 8000, channels: 1, payloadType: CODECS[codec].pt })],
      },
      iceServers: stunServers.map((urls) => ({ urls })),
      iceUseIpv6: false,
      icePortRange: portRange,
    });

    this.pc.connectionStateChange.subscribe((s) => {
      this.state = s;
      this.emit('state', s);
    });
    this.pc.onTrack.subscribe((track) => {
      track.onReceiveRtp.subscribe((rtp) => {
        const { header, payload } = rtp;
        if (header.payloadType !== CODECS[codec].pt || !payload.length) return; // CN, DTMF, ...
        this.emit('audio', {
          pt: header.payloadType,
          marker: header.marker,
          seq: header.sequenceNumber,
          timestamp: header.timestamp,
          ssrc: header.ssrc,
          payload,
        });
      });
    });
  }

  /**
   * Answer the browser's offer. ICE gathering completes before this resolves, so the answer
   * already carries the gateway's candidates (the browser may still trickle its own).
   */
  async answer(offerSdp: string): Promise<string> {
    if (this.negotiated) throw new Error('Renegotiation is not supported; reconnect instead');
    await this.pc.setRemoteDescription({ type: 'offer', sdp: offerSdp });
    const transceiver = this.pc.getTransceivers().find((t) => t.kind === 'audio');
    if (!transceiver) throw new Error('The offer has no audio section');
    await transceiver.sender.replaceTrack(this.track);
    transceiver.setDirection('sendrecv');
    await this.pc.setLocalDescription(await this.pc.createAnswer());
    if (this.pc.iceGatheringState !== 'complete') {
      await new Promise<void>((resolve) => {
        const { unSubscribe } = this.pc.iceGatheringStateChange.subscribe((s) => {
          if (s === 'complete') {
            unSubscribe();
            resolve();
          }
        });
      });
    }
    this.negotiated = true;
    const answer = this.pc.localDescription;
    if (!answer) throw new Error('No local description');
    return answer.sdp;
  }

  async addCandidate(candidate: { candidate?: string; sdpMid?: string | null; sdpMLineIndex?: number | null } | null): Promise<void> {
    if (!candidate?.candidate) return; // end-of-candidates
    await this.pc.addIceCandidate({
      candidate: candidate.candidate,
      sdpMid: candidate.sdpMid ?? undefined,
      sdpMLineIndex: candidate.sdpMLineIndex ?? undefined,
    });
  }

  /** Send one G.711 packet (in this peer's law) to the browser. */
  sendAudio(payload: Buffer, src: { ssrc: number; seq: number; timestamp: number; marker: boolean }): void {
    if (this.state !== 'connected') return;
    const out = this.timeline.map(src, payload.length);
    if (!out) return;
    const header = new RtpHeader({
      payloadType: CODECS[this.codec].pt,
      sequenceNumber: out.seq,
      timestamp: out.timestamp,
      marker: out.marker,
    });
    this.track.writeRtp(new RtpPacket(header, payload));
  }

  async close(): Promise<void> {
    this.removeAllListeners('audio');
    try {
      await this.pc.close();
    } catch {
      /* already closed */
    }
  }
}
