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
  /** Call supervision (listen / whisper / takeover) over AMI. */
  supervisor: SupervisorStatus;
}

export type MonitorMode = 'listen' | 'whisper';

/** An agent (extension) in a two-party call on the PBX: a row on the live calls board. */
export interface LiveCall {
  /** The agent's channel, e.g. SIP/115-0000001a. This is what ChanSpy spies on. */
  channel: string;
  extension: string;
  /** The agent's caller ID name, when it is set. */
  name?: string;
  /** The other party: a customer on a trunk, another extension, or a queue's Local/ channel. */
  peer: { channel: string; number: string; name?: string };
  /** Epoch ms, approximately when the agent's channel was created. */
  since: number;
  /** Extensions currently spying on this agent (any supervisor, not only us). */
  monitoredBy: string[];
}

export interface MonitorInfo {
  /**
   * connecting: the PBX is ringing our extension into ChanSpy.
   * listen / whisper: the spy call is up in that mode.
   * takingOver -> takenOver: the customer was moved to us and the agent dropped.
   */
  state: 'connecting' | MonitorMode | 'takingOver' | 'takenOver';
  target: LiveCall;
}

export interface SupervisorStatus {
  /** off: AMI is not configured, so the supervisor features are unavailable. */
  state: 'off' | 'disconnected' | 'connecting' | 'connected' | 'failed';
  error?: string;
  /** Our monitoring session, if any. */
  monitor: MonitorInfo | null;
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
  | { type: 'dtmf'; digit: string }
  /** Start monitoring an agent's call. 'takeover' listens first and takes over as soon as connected. */
  | { type: 'monitor'; channel: string; mode: MonitorMode | 'takeover' }
  /** Switch between listen and whisper during a monitoring session. */
  | { type: 'monitorMode'; mode: MonitorMode }
  /** Take over the monitored call: the customer moves to us and the agent is dropped. */
  | { type: 'takeover' };

/** Messages the gateway sends. */
export type ServerMessage =
  | { type: 'answer'; sdp: string }
  | { type: 'status'; status: GatewayStatus }
  /** The live calls board, sent on join and whenever it changes. Only when supervision is configured. */
  | { type: 'liveCalls'; calls: LiveCall[] }
  | { type: 'error'; message: string };
