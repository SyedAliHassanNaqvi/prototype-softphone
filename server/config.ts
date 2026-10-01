// Gateway configuration from environment variables (.env in the working directory).
import dotenv from 'dotenv';
import fs from 'node:fs';
import { parseUri } from './sip/message.ts';
import { isCodecName, type CodecName } from './sip/sdp.ts';
import type { TlsSettings } from './sip/transport.ts';

export interface GatewayConfig {
  pbxIp: string;
  pbxPort: number;
  /** SIP signalling transport towards the PBX. */
  transport: 'udp' | 'tls';
  tls: TlsSettings;
  /** SRTP (SDES) for the media towards the PBX. */
  encryption: boolean;
  extension: string;
  secret: string;
  authUser?: string;
  displayName?: string;
  sipLocalPort: number;
  sipLocalIp?: string;
  codecs: CodecName[];
  rtpPortMin: number;
  rtpPortMax: number;
  gatewayPort: number;
  gatewayHost: string;
  webrtcPortRange?: [number, number];
  stunServers: string[];
  logSip: boolean;
  /** Call supervision (listen / whisper / takeover) over AMI. Unset when AMI_USER is empty. */
  ami?: AmiConfig;
  /** Non-fatal configuration problems to print at startup. */
  warnings: string[];
}

export interface AmiConfig {
  host: string;
  port: number;
  username: string;
  secret: string;
  /** Channel ChanSpy rings for us, e.g. "SIP/109". Default: the agent's technology + our extension. */
  spyChannel?: string;
  /** Channel peer names that are agent extensions rather than trunks. */
  agentPattern: RegExp;
}

const bool = (raw: string | undefined, fallback: boolean): boolean =>
  raw === undefined || raw === '' ? fallback : /^(1|true|yes|on)$/i.test(raw);

function int(env: NodeJS.ProcessEnv, name: string, fallback: number): number {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0 || n > 65535) throw new Error(`${name} must be a port number, got "${raw}"`);
  return n;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): GatewayConfig {
  dotenv.config({ quiet: true });

  const warnings: string[] = [];

  // PBX address: either PBX_URI (sip:host[:port][;transport=tls] or sips:host[:port]) or
  // PBX_IP + PBX_PORT + PBX_TRANSPORT. A sips: URI or ;transport=tls selects TLS on 5061.
  let pbxIp = env.PBX_IP;
  let transportRaw = (env.PBX_TRANSPORT || '').toLowerCase();
  let uriPort: number | undefined;
  if (env.PBX_URI) {
    const uri = parseUri(env.PBX_URI);
    if (!uri) throw new Error(`PBX_URI is not a SIP URI: "${env.PBX_URI}"`);
    pbxIp = uri.host;
    uriPort = uri.port;
    const t = typeof uri.params.transport === 'string' ? uri.params.transport.toLowerCase() : '';
    if (/^sips:/i.test(env.PBX_URI) || t === 'tls') transportRaw = 'tls';
    else if (t === 'udp' || !transportRaw) transportRaw = 'udp';
  }
  const transport = transportRaw || 'udp';
  if (transport !== 'udp' && transport !== 'tls') throw new Error(`PBX_TRANSPORT must be udp or tls, got "${env.PBX_TRANSPORT}"`);

  const missing = [pbxIp ? '' : 'PBX_IP (or PBX_URI)', ...['SIP_EXTENSION', 'SIP_SECRET'].filter((k) => !env[k])].filter(Boolean);
  if (missing.length) throw new Error(`Missing ${missing.join(', ')}. Copy .env.example to .env and fill it in.`);
  if (env.SIP_SECRET === 'YourSecretHere') throw new Error('SIP_SECRET is still the placeholder from .env.example.');

  const codecs = (env.SIP_CODECS || 'PCMA,PCMU').split(',').map((c) => c.trim().toUpperCase()).filter(Boolean);
  const bad = codecs.filter((c) => !isCodecName(c));
  if (bad.length || !codecs.length) throw new Error(`SIP_CODECS may only contain PCMA and PCMU, got "${env.SIP_CODECS}"`);

  const rtpPortMin = int(env, 'RTP_PORT_MIN', 10000);
  const rtpPortMax = int(env, 'RTP_PORT_MAX', 20000);
  if (rtpPortMax <= rtpPortMin) throw new Error('RTP_PORT_MAX must be greater than RTP_PORT_MIN');

  // Encryption defaults to on with TLS (that is the point of TLS) and off with UDP.
  const encryption = bool(env.PBX_ENCRYPTION, transport === 'tls');
  if (encryption && transport === 'udp') {
    warnings.push('PBX_ENCRYPTION=true over UDP: the SRTP keys travel in clear-text SDP and can be sniffed. Use PBX_TRANSPORT=tls.');
  }
  if (!encryption && transport === 'tls') {
    warnings.push('PBX_TRANSPORT=tls without PBX_ENCRYPTION: signalling is encrypted but the audio is plain RTP.');
  }

  const tlsSettings: TlsSettings = {
    rejectUnauthorized: bool(env.PBX_TLS_VERIFY, true),
    caFile: env.PBX_TLS_CA || undefined,
    servername: env.PBX_TLS_SERVERNAME || undefined,
    certFile: env.PBX_TLS_CERT || undefined,
    keyFile: env.PBX_TLS_KEY || undefined,
  };
  for (const [name, file] of [['PBX_TLS_CA', tlsSettings.caFile], ['PBX_TLS_CERT', tlsSettings.certFile], ['PBX_TLS_KEY', tlsSettings.keyFile]] as const) {
    if (file && !fs.existsSync(file)) throw new Error(`${name} file not found: ${file}`);
  }
  if (Boolean(tlsSettings.certFile) !== Boolean(tlsSettings.keyFile)) throw new Error('Set both PBX_TLS_CERT and PBX_TLS_KEY, or neither.');
  if (transport === 'tls' && !tlsSettings.rejectUnauthorized) {
    warnings.push('PBX_TLS_VERIFY=false: the PBX certificate is not checked, so a man-in-the-middle could read the SRTP keys. Use PBX_TLS_CA instead outside of testing.');
  }

  const pbxPort = env.PBX_PORT ? int(env, 'PBX_PORT', 5060) : uriPort ?? (transport === 'tls' ? 5061 : 5060);
  if (transport === 'tls' && pbxPort === 5060) warnings.push('PBX_TRANSPORT=tls with PBX_PORT=5060: Asterisk listens for TLS on 5061 by default.');

  // Supervision is optional: without an AMI user the softphone works as before.
  let ami: AmiConfig | undefined;
  const amiUser = env.AMI_USER || env.AMI_USERNAME;
  const amiSecret = env.AMI_SECRET || env.AMI_PASSWORD;
  if (amiUser) {
    if (!amiSecret) throw new Error('AMI_USER is set but AMI_SECRET is missing.');
    let agentPattern: RegExp;
    try {
      agentPattern = new RegExp(env.AMI_AGENT_PATTERN || '^\\d{2,6}$');
    } catch (err) {
      throw new Error(`AMI_AGENT_PATTERN is not a valid regular expression: ${(err as Error).message}`);
    }
    const spyChannel = env.AMI_SPY_CHANNEL || undefined;
    if (spyChannel && !/^[A-Za-z0-9]+\/[^\s,]+$/.test(spyChannel)) throw new Error(`AMI_SPY_CHANNEL must look like SIP/109 or PJSIP/109, got "${spyChannel}"`);
    ami = { host: env.AMI_HOST || pbxIp!, port: int(env, 'AMI_PORT', 5038), username: amiUser, secret: amiSecret, spyChannel, agentPattern };
  }

  const wMin = int(env, 'WEBRTC_PORT_MIN', 0);
  const wMax = int(env, 'WEBRTC_PORT_MAX', 0);

  return {
    pbxIp: pbxIp!,
    pbxPort,
    transport,
    tls: tlsSettings,
    encryption,
    extension: env.SIP_EXTENSION!,
    secret: env.SIP_SECRET!,
    authUser: env.SIP_AUTH_USER || undefined,
    displayName: env.SIP_DISPLAY_NAME || undefined,
    sipLocalPort: int(env, 'SIP_LOCAL_PORT', 5062),
    sipLocalIp: env.SIP_LOCAL_IP || undefined,
    codecs: codecs as CodecName[],
    rtpPortMin,
    rtpPortMax,
    gatewayPort: int(env, 'GATEWAY_PORT', 4000),
    gatewayHost: env.GATEWAY_HOST || '127.0.0.1',
    webrtcPortRange: wMin && wMax > wMin ? [wMin, wMax] : undefined,
    stunServers: (env.STUN_SERVERS || '').split(',').map((s) => s.trim()).filter(Boolean),
    logSip: bool(env.LOG_SIP, false),
    ami,
    warnings,
  };
}
