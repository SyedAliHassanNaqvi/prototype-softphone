// Browser side of the gateway: microphone, one RTCPeerConnection to the Node gateway, and the
// WebSocket signalling channel. The browser never talks SIP and never sees PBX credentials.
//
// Lifecycle: microphone -> WebSocket 'join' -> WebRTC offer/answer (+ trickled candidates).
// The peer connection stays up between calls; dial / hangup only drive the SIP side. If the
// WebSocket drops, everything except the local audio is torn down and rebuilt after a delay.
//
// No microphone (none plugged in, permission denied, device busy) must not cost the speaker:
// we then send a silent track so the WebRTC leg still comes up and you can hear the other
// party. When a microphone appears later (devicechange) it replaces the silent track in place,
// and if the mic is unplugged mid-call the silent track takes over again.
import { useCallback, useEffect, useRef, useState } from 'react';
import type { ClientMessage, GatewayStatus, ServerMessage } from '../../shared/protocol.ts';

export type LinkState = 'mic' | 'connecting' | 'online' | 'offline' | 'replaced';

const RECONNECT_MS = 2000;
const MIC_CONSTRAINTS: MediaStreamConstraints = {
  audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
  video: false,
};

function wsUrl(): string {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${location.host}/ws`;
}

function describeMicError(err: Error): string {
  switch (err.name) {
    case 'NotFoundError':
    case 'OverconstrainedError':
      return 'No microphone found. You can hear the other party, but they cannot hear you. Plug one in and it is picked up automatically.';
    case 'NotAllowedError':
      return 'Microphone access is blocked for this site. You can hear, but the other party cannot hear you. Allow the microphone in the address bar, then reload.';
    case 'NotReadableError':
      return 'The microphone is in use by another application or failed to start. You can hear, but the other party cannot hear you.';
    default:
      return `Microphone unavailable (${err.message}). You can hear, but the other party cannot hear you.`;
  }
}

/**
 * A live audio track that carries silence. It needs an actual (zero-valued) source: Chrome
 * produces no frames, and so sends no RTP, for a destination with nothing connected, and then
 * Asterisk's rtptimeout would eventually hang up.
 */
function createSilentTrack(): { track: MediaStreamTrack; ctx: AudioContext } {
  const ctx = new AudioContext();
  const source = ctx.createConstantSource();
  source.offset.value = 0;
  const dest = ctx.createMediaStreamDestination();
  source.connect(dest);
  source.start();
  return { track: dest.stream.getAudioTracks()[0], ctx };
}

export function useWebRTC() {
  const [status, setStatus] = useState<GatewayStatus | null>(null);
  const [link, setLink] = useState<LinkState>('mic');
  const [micError, setMicError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [muted, setMuted] = useState(false);

  const audioRef = useRef<HTMLAudioElement | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  /** The track we send: the microphone, or silence when there is none. */
  const localRef = useRef<{ track: MediaStreamTrack; stream: MediaStream; silent: AudioContext | null } | null>(null);
  const senderRef = useRef<RTCRtpSender | null>(null);
  const mutedRef = useRef(false);

  const applyMute = useCallback((next: boolean) => {
    mutedRef.current = next;
    setMuted(next);
    const local = localRef.current;
    if (local && !local.silent) local.track.enabled = !next;
  }, []);

  const send = useCallback((msg: ClientMessage) => {
    const ws = wsRef.current;
    if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
  }, []);

  useEffect(() => {
    let disposed = false;
    let pc: RTCPeerConnection | null = null;
    let reconnectTimer: number | undefined;
    let acquiring = false;

    const releaseLocal = () => {
      const local = localRef.current;
      localRef.current = null;
      if (!local) return;
      local.track.onended = null;
      local.track.stop();
      void local.silent?.close();
    };

    /** Swap what we send, on the live connection too (no renegotiation needed). */
    const setLocal = (track: MediaStreamTrack, silent: AudioContext | null) => {
      releaseLocal();
      const stream = new MediaStream([track]);
      localRef.current = { track, stream, silent };
      if (!silent) {
        track.enabled = !mutedRef.current;
        // Unplugged mid-session: fall back to silence so the call and your speaker keep working.
        track.onended = () => {
          if (disposed || localRef.current?.track !== track) return;
          setMicError('The microphone was disconnected. You can still hear the other party; plug it back in to talk.');
          fallBackToSilence();
        };
      }
      void senderRef.current?.replaceTrack(track).catch(() => {});
    };

    const fallBackToSilence = () => {
      const { track, ctx } = createSilentTrack();
      setLocal(track, ctx);
    };

    /** Try to open the microphone. Returns false (and shows why) when there is none. */
    const acquireMic = async (): Promise<boolean> => {
      if (acquiring) return false;
      acquiring = true;
      try {
        const mic = await navigator.mediaDevices.getUserMedia(MIC_CONSTRAINTS);
        const track = mic.getAudioTracks()[0];
        if (disposed || !track) {
          mic.getTracks().forEach((t) => t.stop());
          return false;
        }
        setLocal(track, null);
        setMicError(null);
        return true;
      } catch (err) {
        if (!disposed) setMicError(describeMicError(err as Error));
        return false;
      } finally {
        acquiring = false;
      }
    };

    // A headset plugged in (or out) while we're on silence: pick it up.
    const onDeviceChange = () => {
      if (localRef.current?.silent) void acquireMic();
    };
    navigator.mediaDevices.addEventListener('devicechange', onDeviceChange);

    const teardownPeer = () => {
      pc?.close();
      pc = null;
      senderRef.current = null;
    };

    const startPeer = async (ws: WebSocket) => {
      teardownPeer();
      const local = localRef.current;
      if (!local) return;
      const peer = new RTCPeerConnection({ iceServers: [] });
      pc = peer;
      senderRef.current = peer.addTrack(local.track, local.stream);
      peer.ontrack = (ev) => {
        const el = audioRef.current;
        if (!el) return;
        el.srcObject = ev.streams[0] ?? new MediaStream([ev.track]);
        el.play().catch(() => {
          /* autoplay blocked until the next click; play() is retried on dial/answer */
        });
      };
      peer.onicecandidate = (ev) => {
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'candidate', candidate: ev.candidate ? ev.candidate.toJSON() : null } satisfies ClientMessage));
      };
      const offer = await peer.createOffer();
      await peer.setLocalDescription(offer);
      if (pc !== peer || ws.readyState !== WebSocket.OPEN) return;
      ws.send(JSON.stringify({ type: 'offer', sdp: peer.localDescription!.sdp } satisfies ClientMessage));
    };

    const connect = () => {
      if (disposed) return;
      setLink('connecting');
      const ws = new WebSocket(wsUrl());
      wsRef.current = ws;

      ws.onopen = () => {
        ws.send(JSON.stringify({ type: 'join' } satisfies ClientMessage));
        setLink('online');
        setError(null);
        startPeer(ws).catch((err: Error) => setError(`WebRTC: ${err.message}`));
      };
      ws.onmessage = (ev) => {
        const msg = JSON.parse(ev.data as string) as ServerMessage;
        if (msg.type === 'status') {
          setStatus(msg.status);
          if (msg.status.call.state === 'idle' && mutedRef.current) applyMute(false); // mute is per call
        } else if (msg.type === 'answer') {
          pc?.setRemoteDescription({ type: 'answer', sdp: msg.sdp }).catch((err: Error) => setError(`WebRTC: ${err.message}`));
        } else if (msg.type === 'error') {
          setError(msg.message);
        }
      };
      ws.onclose = (ev) => {
        if (wsRef.current === ws) wsRef.current = null;
        teardownPeer();
        setStatus(null);
        if (disposed) return;
        if (ev.code === 4001) {
          setLink('replaced'); // another tab took over; don't fight it
          return;
        }
        setLink('offline');
        reconnectTimer = window.setTimeout(connect, RECONNECT_MS);
      };
    };

    void acquireMic().then((ok) => {
      if (disposed) return;
      if (!ok) fallBackToSilence(); // connect anyway: hearing must not depend on having a microphone
      connect();
    });

    return () => {
      disposed = true;
      navigator.mediaDevices.removeEventListener('devicechange', onDeviceChange);
      window.clearTimeout(reconnectTimer);
      wsRef.current?.close();
      wsRef.current = null;
      teardownPeer();
      releaseLocal();
    };
  }, [applyMute]);

  /**
   * Browsers may block autoplay (and keep the silent AudioContext suspended) until a user
   * gesture; every call control is one.
   */
  const unlockAudio = () => {
    audioRef.current?.play().catch(() => {});
    void localRef.current?.silent?.resume().catch(() => {});
  };

  const dial = useCallback(
    (number: string) => {
      unlockAudio();
      setError(null);
      send({ type: 'dial', number });
    },
    [send],
  );

  const hangup = useCallback(() => send({ type: 'hangup' }), [send]);

  const accept = useCallback(() => {
    unlockAudio();
    send({ type: 'accept' });
  }, [send]);

  const reject = useCallback(() => send({ type: 'reject' }), [send]);

  // Mute locally (the browser sends silence) and at the gateway (silence towards Asterisk).
  const toggleMute = useCallback(() => {
    const next = !mutedRef.current;
    applyMute(next);
    send({ type: 'mute', muted: next });
  }, [applyMute, send]);

  const sendDtmf = useCallback((digit: string) => send({ type: 'dtmf', digit }), [send]);

  const reconnect = useCallback(() => location.reload(), []);

  return { status, link, micError, error, muted, audioRef, dial, hangup, accept, reject, toggleMute, sendDtmf, reconnect, clearError: () => setError(null) };
}
