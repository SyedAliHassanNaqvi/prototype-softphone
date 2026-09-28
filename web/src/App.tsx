import { useEffect, useState } from 'react';
import type { GatewayStatus } from '../../shared/protocol.ts';
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
  const { status, link, micError, error, muted, audioRef, dial, hangup, accept, reject, toggleMute, sendDtmf, reconnect, clearError } = useWebRTC();
  const [number, setNumber] = useState('');

  const call = status?.call ?? { state: 'idle' as const };
  const reg = status?.registration;
  const inCall = call.state !== 'idle';
  const timer = useCallTimer(call.state === 'active' ? call.startedAt : null);
  const ready = link === 'online' && reg?.state === 'registered' && status?.peer === 'connected';
  const summary = describe(status, link);

  const press = (key: string) => {
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

  return (
    <main className="shell">
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

        <div className={`call call-${call.state}`}>
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
            <button key={k} className="key" onClick={() => press(k)} disabled={call.state === 'incoming'}>
              <span className="key-main">{k}</span>
              <span className="key-sub">{sub || ' '}</span>
            </button>
          ))}
        </div>

        <div className="actions">
          {call.state === 'incoming' ? (
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
    </main>
  );
}
