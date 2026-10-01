// Turns the PBX's channel list (AMI CoreShowChannels) into "agents on a live call": the rows a
// supervisor can listen to, whisper to or take over. Pure functions, no I/O.
//
// A live call is a bridge with exactly two channels. Each side whose channel belongs to an
// extension (SIP/115-0000001a, PJSIP/115-0000001a) is one row; its bridge partner is the other
// party (a trunk channel for PSTN calls, another extension, or a Local/ channel for queues).
// ChanSpy channels are never in a bridge (ChanSpy uses audiohooks), so they show up only in
// `monitoredBy`.
import type { AmiMessage } from './AmiClient.ts';
import type { LiveCall } from '../../shared/protocol.ts';

export interface AmiChannel {
  name: string;
  uniqueid: string;
  state: string;
  callerNum: string;
  callerName: string;
  connectedNum: string;
  connectedName: string;
  exten: string;
  application: string;
  appData: string;
  /** Asterisk 12+: the bridge the channel is in. */
  bridgeId: string;
  /** Asterisk 11: the channel it is bridged with. */
  bridgedChannel: string;
  /** Seconds since the channel was created. */
  durationSec: number;
}

const unknown = (v: string | undefined): string => (!v || v === '<unknown>' || v === '(None)' ? '' : v);

/** HH:MM:SS (or plain seconds) to seconds. */
function durationOf(raw: string | undefined): number {
  if (!raw) return 0;
  if (/^\d+$/.test(raw)) return Number(raw);
  return raw.split(':').reduce((acc, part) => acc * 60 + (Number(part) || 0), 0);
}

export function channelFromEvent(ev: AmiMessage): AmiChannel {
  return {
    name: ev.channel ?? '',
    uniqueid: ev.uniqueid ?? '',
    state: ev.channelstatedesc ?? '',
    callerNum: unknown(ev.calleridnum),
    callerName: unknown(ev.calleridname),
    connectedNum: unknown(ev.connectedlinenum),
    connectedName: unknown(ev.connectedlinename),
    exten: ev.exten ?? ev.extension ?? '',
    application: ev.application ?? '',
    appData: ev.applicationdata ?? '',
    bridgeId: ev.bridgeid ?? '',
    bridgedChannel: unknown(ev.bridgedchannel),
    durationSec: durationOf(ev.duration),
  };
}

const DEVICE_CHANNEL = /^(SIP|PJSIP|IAX2)\/([^/]+)-[0-9a-f]+$/i;

/** "SIP/115-0000001a" -> { tech: 'SIP', peer: '115' }. Null for Local/, DAHDI and the like. */
export function deviceOf(channel: string): { tech: string; peer: string } | null {
  const m = DEVICE_CHANNEL.exec(channel);
  return m ? { tech: m[1], peer: m[2] } : null;
}

/** The extension a channel belongs to, if its peer name matches the agent pattern. */
export function extensionOf(channel: string, agentPattern: RegExp): string | null {
  const dev = deviceOf(channel);
  return dev && agentPattern.test(dev.peer) ? dev.peer : null;
}

/** The ChanSpy target of a spy channel: first argument of its ApplicationData. */
export function spyTarget(ch: AmiChannel): string | null {
  if (ch.application.toLowerCase() !== 'chanspy') return null;
  const target = ch.appData.split(/[,|]/)[0].trim();
  return target || null;
}

/** Group channels into bridges (Asterisk 12+ BridgeId, or Asterisk 11 BridgedChannel pairs). */
export function bridgesOf(channels: AmiChannel[]): AmiChannel[][] {
  const byId = new Map<string, AmiChannel[]>();
  const byName = new Map(channels.map((c) => [c.name, c]));
  const paired = new Set<string>();
  for (const ch of channels) {
    if (ch.bridgeId) {
      const list = byId.get(ch.bridgeId) ?? [];
      list.push(ch);
      byId.set(ch.bridgeId, list);
    } else if (ch.bridgedChannel && !paired.has(ch.name)) {
      const other = byName.get(ch.bridgedChannel);
      if (other && !other.bridgeId) {
        paired.add(ch.name).add(other.name);
        byId.set(`pair:${ch.name}`, [ch, other]);
      }
    }
  }
  return [...byId.values()];
}

export interface LiveCallOptions {
  agentPattern: RegExp;
  /** Extensions never offered as targets (the supervisor's own). */
  exclude: string[];
  now: number;
  /** Start times already handed out, by agent channel, so they don't jitter between polls. */
  since?: Map<string, number>;
}

/** The number to show for the other party. */
function peerNumber(agent: AmiChannel, peer: AmiChannel, extension: string): string {
  const candidates = [peer.callerNum, agent.connectedNum, peer.connectedNum, peer.exten];
  return candidates.find((n) => n && n !== extension && n !== agent.callerNum) ?? candidates.find(Boolean) ?? '';
}

export function buildLiveCalls(channels: AmiChannel[], opts: LiveCallOptions): LiveCall[] {
  const spies = new Map<string, string[]>(); // spied channel -> spy extensions
  for (const ch of channels) {
    const target = spyTarget(ch);
    if (!target) continue;
    const spiedOn = channels.filter((c) => c.name === target || c.name.startsWith(`${target}-`));
    const who = deviceOf(ch.name)?.peer ?? ch.name;
    for (const c of spiedOn) spies.set(c.name, [...(spies.get(c.name) ?? []), who]);
  }

  const calls: LiveCall[] = [];
  for (const bridge of bridgesOf(channels)) {
    if (bridge.length !== 2) continue; // conferences, or a channel alone in a bridge
    for (const [agent, peer] of [[bridge[0], bridge[1]], [bridge[1], bridge[0]]]) {
      const extension = extensionOf(agent.name, opts.agentPattern);
      if (!extension || opts.exclude.includes(extension)) continue;
      const since = opts.since?.get(agent.name) ?? opts.now - agent.durationSec * 1000;
      opts.since?.set(agent.name, since);
      const number = peerNumber(agent, peer, extension);
      calls.push({
        channel: agent.name,
        extension,
        name: agent.callerName && agent.callerName !== extension ? agent.callerName : undefined,
        peer: {
          channel: peer.name,
          number,
          name: [peer.callerName, agent.connectedName].find((n) => n && n !== number && n !== agent.callerName) || undefined,
        },
        since,
        monitoredBy: spies.get(agent.name) ?? [],
      });
    }
  }
  calls.sort((a, b) => a.since - b.since || a.extension.localeCompare(b.extension));
  return calls;
}
