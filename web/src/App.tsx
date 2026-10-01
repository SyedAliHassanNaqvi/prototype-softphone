import { useEffect, useState } from 'react';
import type { GatewayStatus, LiveCall, MonitorInfo, SupervisorStatus } from '../../shared/protocol.ts';
import { useWebRTC, type LinkState } from './useWebRTC.ts';

const KEYS: Array<[string, string]> = [
  ['1', ''], ['2', 'ABC'], ['3', 'DEF'],
  ['4', 'GHI'], ['5', 'JKL'], ['6', 'MNO'],
  ['7', 'PQRS'], ['8', 'TUV'], ['9', 'WXYZ'],
  ['*', ''], ['0', '+'], ['#', ''],
];

function useCallTimer(startedAt: number | null | undefined): string {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!startedAt) return;
    const t = window.setInterval(() => setNow(Date.now()), 500);
    return () => window.clearInterval(t);
  }, [startedAt]);
  if (!startedAt) return '00:00';
  const s = Math.max(0, Math.floor((now - startedAt) / 1000));
  const hh = Math.floor(s / 3600);
  const mm = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
  const ss = String(s % 60).padStart(2, '0');
  return hh ? `${hh}:${mm}:${ss}` : `${mm}:${ss}`;
}

function useNow(ms: number, active = true): number {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!active) return;
    const t = window.setInterval(() => setNow(Date.now()), ms);
    return () => window.clearInterval(t);
  }, [ms, active]);
  return now;
}

function elapsed(from: number, now: number): string {
  const s = Math.max(0, Math.floor((now - from) / 1000));
  const mm = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
  const ss = String(s % 60).padStart(2, '0');
  return s >= 3600 ? `${Math.floor(s / 3600)}:${mm}:${ss}` : `${mm}:${ss}`;
}

const agentLabel = (c: LiveCall): string => (c.name ? `${c.extension} · ${c.name}` : c.extension);
const peerLabel = (c: LiveCall): string => c.peer.number || c.peer.channel;

function supervisorPill(sup: SupervisorStatus): { tone: 'ok' | 'warn' | 'bad' | 'idle'; label: string } {
  switch (sup.state) {
    case 'connected':
      return { tone: 'ok', label: 'AMI connected' };
    case 'failed':
      return { tone: 'bad', label: 'AMI login failed' };
    case 'off':
      return { tone: 'idle', label: 'Not configured' };
    default:
      return { tone: 'warn', label: 'Connecting to AMI' };
  }
}

/** The phone card's call line while we supervise someone. */
function monitorLine(m: MonitorInfo): { title: string; detail: string } {
  const t = m.target;
  switch (m.state) {
    case 'connecting':
      return { title: `Connecting to ${t.extension}`, detail: 'The PBX is ringing this softphone into the call' };
    case 'listen':
      return { title: 'Listening', detail: `${agentLabel(t)} ↔ ${peerLabel(t)}` };
    case 'whisper':
      return { title: `Whispering to ${t.extension}`, detail: `Only ${t.extension} hears you · ${peerLabel(t)} does not` };
    case 'takingOver':
      return { title: 'Taking over', detail: `Moving ${peerLabel(t)} to you` };
    case 'takenOver':
      return { title: 'Connected', detail: `${t.peer.name ? `${t.peer.name} · ` : ''}${peerLabel(t)} (taken over from ${t.extension})` };
  }
}

interface LiveCallsProps {
  calls: LiveCall[];
  supervisor: SupervisorStatus;
  monitor: MonitorInfo | null;
  /** Why the buttons are disabled, or null when they can be used. */
  blocked: string | null;
  onMonitor: (channel: string, mode: 'listen' | 'whisper' | 'takeover') => void;
}

function LiveCalls({ calls, supervisor, monitor, blocked, onMonitor }: LiveCallsProps) {
  const now = useNow(1000, calls.length > 0);
  const pill = supervisorPill(supervisor);
  return (
    <section className="board" aria-label="Live calls">
      <header className="top">
        <div>
          <h1>Live calls</h1>
          <p className="sub">Listen, whisper to the agent, or take over the call</p>
        </div>
        <span className={`pill pill-${pill.tone}`} role="status">
          <span className="dot" />
          {pill.label}
        </span>
      </header>

      {supervisor.error && supervisor.state !== 'connected' && <div className="banner banner-bad">{supervisor.error}</div>}
      {supervisor.state === 'connected' && blocked && calls.length > 0 && <div className="banner banner-warn">{blocked}</div>}

      {supervisor.state === 'connected' && calls.length === 0 && <p className="empty">No agent is on a call right now.</p>}

      <ul className="calls">
        {calls.map((c) => {
          const mine = monitor?.target.channel === c.channel;
          return (
            <li key={c.channel} className={`row ${mine ? 'row-mine' : ''}`}>
              <div className="row-who">
                <div className="row-agent">
                  {agentLabel(c)}
                  <span className="row-time">{elapsed(c.since, now)}</span>
                </div>
                <div className="row-peer">
                  ↔ {peerLabel(c)}
                  {c.peer.name ? ` · ${c.peer.name}` : ''}
                </div>
                {(mine || c.monitoredBy.length > 0) && (
                  <div className="row-spies">{mine ? 'You are monitoring this call' : `Monitored by ${c.monitoredBy.join(', ')}`}</div>
                )}
              </div>
              <div className="row-actions">
                <button className="chip" disabled={Boolean(blocked)} onClick={() => onMonitor(c.channel, 'listen')} title="Hear both sides. Nobody hears you.">
                  Listen
                </button>
                <button className="chip" disabled={Boolean(blocked)} onClick={() => onMonitor(c.channel, 'whisper')} title="Only the agent hears you. The customer does not.">
                  Whisper
                </button>
                <button className="chip chip-warn" disabled={Boolean(blocked)} onClick={() => onMonitor(c.channel, 'takeover')} title="The customer is moved to you and the agent is dropped.">
                  Take over
                </button>
              </div>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

/** The single status line: Registered to Issabel / Registering / Registration failed ... */
function describe(status: GatewayStatus | null, link: LinkState): { tone: 'ok' | 'warn' | 'bad' | 'idle'; label: string } {
  if (link === 'mic') return { tone: 'idle', label: 'Waiting for microphone' };
  if (link === 'replaced') return { tone: 'warn', label: 'Opened in another tab' };
  if (link !== 'online' || !status) return { tone: 'warn', label: 'Connecting to gateway' };
  const { registration: reg } = status;
  if (reg.state === 'failed') return { tone: 'bad', label: 'Registration failed' };
  if (reg.state === 'registering') return { tone: 'warn', label: 'Registering' };
  if (reg.state !== 'registered') return { tone: 'bad', label: 'Unregistered' };
  return { tone: 'ok', label: 'Registered to Issabel' };
}

export default function App() {
  const {
    status, link, micError, error, muted, liveCalls, audioRef,
    dial, hangup, accept, reject, toggleMute, sendDtmf, monitor: startMonitor, setMonitorMode, takeover, reconnect, clearError,
  } = useWebRTC();
  const [number, setNumber] = useState('');

  const call = status?.call ?? { state: 'idle' as const };
  const reg = status?.registration;
  const supervisor = status?.supervisor ?? { state: 'off' as const, monitor: null };
  const monitor = supervisor.monitor;
  /** Listening or whispering: the keypad would drive ChanSpy, so it is locked. */
  const spying = Boolean(monitor && monitor.state !== 'takenOver');
  const inCall = call.state !== 'idle' || Boolean(monitor);
  const timer = useCallTimer(call.state === 'active' ? call.startedAt : null);
  const ready = link === 'online' && reg?.state === 'registered' && status?.peer === 'connected';
  const summary = describe(status, link);
  const monitorBlocked = !ready ? 'Wait until the softphone is registered and ready.' : inCall ? 'Finish the current call to monitor another one.' : null;

  const press = (key: string) => {
    if (spying) return;
    if (call.state === 'active') sendDtmf(key);
    setNumber((n) => (n + key).slice(0, 64));
  };

  const placeCall = () => {
    if (ready && number.trim() && !inCall) dial(number.trim());
  };

  // Keyboard: digits, Backspace, Enter to call, Escape to hang up.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement) return;
      if (/^[0-9*#]$/.test(e.key)) press(e.key);
      else if (e.key === 'Backspace') setNumber((n) => n.slice(0, -1));
      else if (e.key === 'Enter') placeCall();
      else if (e.key === 'Escape' && inCall) hangup();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  const callLine = (() => {
    if (monitor) return monitorLine(monitor);
    const who = call.display || call.number || '';
    switch (call.state) {
      case 'calling':
        return { title: 'Calling', detail: who };
      case 'ringing':
        return { title: call.earlyMedia ? 'Ringing (early media)' : 'Ringing', detail: who };
      case 'incoming':
        return { title: 'Incoming call', detail: call.display && call.number ? `${call.display} · ${call.number}` : who };
      case 'active':
        return { title: call.remoteHold ? 'On hold by remote' : 'Connected', detail: who };
      default:
        return { title: 'Idle', detail: call.reason || (ready ? 'Ready to call' : '') };
    }
  })();

  const callClass = monitor ? `call-monitor call-${monitor.state}` : `call-${call.state}`;

  return (
    <main className={`shell ${supervisor.state !== 'off' ? 'shell-wide' : ''}`}>
      <audio ref={audioRef} autoPlay />

      <section className="phone" aria-label="Softphone">
        <header className="top">
          <div>
            <h1>Arzen Softphone</h1>
            <p className="sub">
              {reg ? `Ext ${reg.extension} · ${reg.pbx} · ${reg.transport.toUpperCase()}${reg.encryption ? ' + SRTP' : ''}` : 'WebRTC → SIP gateway'}
            </p>
          </div>
          <span className={`pill pill-${summary.tone}`} role="status">
            <span className="dot" />
            {summary.label}
          </span>
        </header>

        {micError && (
          <div className="banner banner-warn" role="status">
            {micError}
            {/blocked/.test(micError) && (
              <>
                {' '}
                <button className="link" onClick={reconnect}>Reload</button>
              </>
            )}
          </div>
        )}
        {reg?.state === 'failed' && reg.error && <div className="banner banner-bad">{reg.error}</div>}
        {link === 'replaced' && (
          <div className="banner banner-warn">
            This softphone is active in another tab. <button className="link" onClick={reconnect}>Use it here</button>
          </div>
        )}
        {link === 'online' && status && status.peer !== 'connected' && <div className="banner banner-warn">Browser audio: {status.peer}…</div>}
        {error && (
          <div className="banner banner-bad" onClick={clearError} role="alert">
            {error}
          </div>
        )}

        <div className={`call ${callClass}`}>
          <div className="call-title">
            {callLine.title}
            {call.state === 'active' && <span className="timer">{timer}</span>}
          </div>
          <div className="call-detail">{callLine.detail || ' '}</div>
          {inCall && call.codec && (
            <div className="call-meta">
              {call.codec}
              {call.browserCodec && call.browserCodec !== call.codec ? ` ⇄ ${call.browserCodec} (transcoding)` : ''}
              {call.srtp ? ' · 🔒 SRTP to PBX' : ' · plain RTP to PBX'}
              {muted ? ' · muted' : ''}
            </div>
          )}
        </div>

        <div className="entry">
          <input
            value={number}
            onChange={(e) => setNumber(e.target.value.replace(/[^\d*#+]/g, ''))}
            onKeyDown={(e) => e.key === 'Enter' && placeCall()}
            placeholder="Extension or number"
            inputMode="tel"
            aria-label="Number to dial"
          />
          {number && (
            <button className="clear" onClick={() => setNumber((n) => n.slice(0, -1))} aria-label="Delete last digit">
              ⌫
            </button>
          )}
        </div>

        <div className="pad">
          {KEYS.map(([k, sub]) => (
            <button key={k} className="key" onClick={() => press(k)} disabled={call.state === 'incoming' || spying}>
              <span className="key-main">{k}</span>
              <span className="key-sub">{sub || ' '}</span>
            </button>
          ))}
        </div>

        {monitor && (monitor.state === 'listen' || monitor.state === 'whisper' || monitor.state === 'takingOver') && (
          <div className="monitor">
            <div className="seg" role="group" aria-label="Monitoring mode">
              <button className={monitor.state === 'listen' ? 'on' : ''} aria-pressed={monitor.state === 'listen'} disabled={monitor.state === 'takingOver'} onClick={() => setMonitorMode('listen')}>
                Listen
              </button>
              <button className={monitor.state === 'whisper' ? 'on' : ''} aria-pressed={monitor.state === 'whisper'} disabled={monitor.state === 'takingOver'} onClick={() => setMonitorMode('whisper')}>
                Whisper
              </button>
            </div>
            <button className="btn btn-warn" onClick={takeover} disabled={monitor.state === 'takingOver'}>
              Take over
            </button>
          </div>
        )}

        <div className="actions">
          {monitor?.state === 'connecting' ? (
            <button className="btn btn-stop" onClick={hangup}>Cancel</button>
          ) : spying ? (
            <>
              <button className={`btn btn-soft ${muted ? 'on' : ''}`} onClick={toggleMute} disabled={monitor?.state !== 'whisper'} aria-pressed={muted}>
                {muted ? 'Unmute' : 'Mute'}
              </button>
              <button className="btn btn-stop" onClick={hangup}>Leave</button>
            </>
          ) : call.state === 'incoming' ? (
            <>
              <button className="btn btn-go" onClick={accept}>Answer</button>
              <button className="btn btn-stop" onClick={reject}>Decline</button>
            </>
          ) : inCall ? (
            <>
              <button className={`btn btn-soft ${muted ? 'on' : ''}`} onClick={toggleMute} disabled={call.state !== 'active'} aria-pressed={muted}>
                {muted ? 'Unmute' : 'Mute'}
              </button>
              <button className="btn btn-stop" onClick={hangup}>Hang up</button>
            </>
          ) : (
            <button className="btn btn-go wide" onClick={placeCall} disabled={!ready || !number.trim()}>
              Call
            </button>
          )}
        </div>
      </section>

      {supervisor.state !== 'off' && (
        <LiveCalls calls={liveCalls} supervisor={supervisor} monitor={monitor} blocked={monitorBlocked} onMonitor={startMonitor} />
      )}
    </main>
  );
}
