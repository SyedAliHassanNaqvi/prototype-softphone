// Browser <-> gateway signalling over the WebSocket at /ws. JSON, one message per frame.
// Shared by the Node gateway and the React app; type-only, so it compiles away on both sides.

export type RegistrationState = 'unregistered' | 'registering' | 'registered' | 'failed';
export type CallState = 'idle' | 'calling' | 'ringing' | 'incoming' | 'active';
export type PeerState = 'new' | 'connecting' | 'connected' | 'disconnected' | 'failed' | 'closed';

export interface GatewayStatus {
  registration: {
    state: RegistrationState;
    error?: string;
    extension: string;
    pbx: string;
    /** Signalling transport to the PBX. */
    transport: 'udp' | 'tls';
    /** SRTP required for calls. */
    encryption: boolean;
  };
  call: {
    state: CallState;
    direction?: 'outgoing' | 'incoming';
    number?: string;
    display?: string;
    /** G.711 law negotiated with Asterisk. */
    codec?: string | null;
    /** Law used on the browser leg; differs from `codec` only when the gateway transcodes. */
    browserCodec?: string | null;
    /** Epoch ms when the call was answered. */
    startedAt?: number | null;
    muted?: boolean;
    /** Media to/from the PBX is SRTP. */
    srtp?: boolean;
    remoteHold?: boolean;
    earlyMedia?: boolean;
    /** Why the last call ended (set on the transition to idle). */
    reason?: string;
  };
  /** State of the browser <-> gateway WebRTC leg. */
  peer: PeerState;
}

/** Messages the browser sends. */
export type ClientMessage =
  | { type: 'join' }
  | { type: 'offer'; sdp: string }
  | { type: 'candidate'; candidate: { candidate?: string; sdpMid?: string | null; sdpMLineIndex?: number | null } | null }
  | { type: 'dial'; number: string }
  | { type: 'hangup' }
  | { type: 'accept' }
  | { type: 'reject' }
  | { type: 'mute'; muted: boolean }
  | { type: 'dtmf'; digit: string };

/** Messages the gateway sends. */
export type ServerMessage =
  | { type: 'answer'; sdp: string }
  | { type: 'status'; status: GatewayStatus }
  | { type: 'error'; message: string };
