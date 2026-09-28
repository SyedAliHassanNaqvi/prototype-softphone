// SIP message parsing / serialisation (RFC 3261 §7). Deliberately small: enough for a UA
// talking to Asterisk, not a general-purpose SIP stack.
import crypto from 'node:crypto';

export interface SipMessage {
  isRequest: boolean;
  /** Request method ('' for responses). */
  method: string;
  /** Request-URI ('' for responses). */
  uri: string;
  /** Response status code (0 for requests). */
  status: number;
  reason: string;
  /** Lower-case canonical header name -> values (multi-value headers are split on commas). */
  headers: Map<string, string[]>;
  body: string;
}

export type HeaderList = Array<[string, string | undefined]>;
export type Params = Record<string, string | true>;

// Compact header forms (RFC 3261 §7.3.3) -> canonical lower-case names.
const COMPACT: Record<string, string> = {
  v: 'via', f: 'from', t: 'to', i: 'call-id', m: 'contact', l: 'content-length',
  c: 'content-type', k: 'supported', s: 'subject', e: 'content-encoding',
};

// Headers that may carry several comma-separated values on one line.
const MULTI_VALUE = new Set(['via', 'route', 'record-route', 'contact']);

export const randomHex = (bytes = 8): string => crypto.randomBytes(bytes).toString('hex');
export const newBranch = (): string => `z9hG4bK${randomHex(8)}`; // magic cookie marks RFC 3261 branches
export const newTag = (): string => randomHex(6);

/** Split on commas that are not inside quotes or <...>. */
function splitTopLevelCommas(value: string): string[] {
  const out: string[] = [];
  let depthAngle = 0;
  let inQuote = false;
  let start = 0;
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (ch === '"' && value[i - 1] !== '\\') inQuote = !inQuote;
    else if (!inQuote && ch === '<') depthAngle++;
    else if (!inQuote && ch === '>') depthAngle--;
    else if (!inQuote && depthAngle === 0 && ch === ',') {
      out.push(value.slice(start, i).trim());
      start = i + 1;
    }
  }
  out.push(value.slice(start).trim());
  return out.filter(Boolean);
}

/** Parse a UDP datagram. Returns null for anything that is not SIP (e.g. CRLF keep-alives). */
export function parseMessage(buf: Buffer): SipMessage | null {
  const text = buf.toString('utf8');
  const split = text.indexOf('\r\n\r\n');
  const head = split === -1 ? text : text.slice(0, split);
  let body = split === -1 ? '' : text.slice(split + 4);

  // Unfold continuation lines (a line starting with whitespace continues the previous header).
  const lines = head.replace(/\r\n[ \t]+/g, ' ').split('\r\n');
  const startLine = lines.shift();
  if (!startLine || !startLine.trim()) return null;

  const msg: SipMessage = { isRequest: false, method: '', uri: '', status: 0, reason: '', headers: new Map(), body: '' };
  const resMatch = /^SIP\/2\.0\s+(\d{3})\s*(.*)$/.exec(startLine);
  const reqMatch = /^([A-Z]+)\s+(\S+)\s+SIP\/2\.0$/.exec(startLine);
  if (resMatch) {
    msg.status = Number(resMatch[1]);
    msg.reason = resMatch[2];
  } else if (reqMatch) {
    msg.isRequest = true;
    msg.method = reqMatch[1];
    msg.uri = reqMatch[2];
  } else {
    return null;
  }

  for (const line of lines) {
    const colon = line.indexOf(':');
    if (colon === -1) continue;
    let name = line.slice(0, colon).trim().toLowerCase();
    name = COMPACT[name] ?? name;
    const value = line.slice(colon + 1).trim();
    const values = MULTI_VALUE.has(name) && value !== '*' ? splitTopLevelCommas(value) : [value];
    const list = msg.headers.get(name) ?? [];
    list.push(...values);
    msg.headers.set(name, list);
  }

  const len = Number(getHeader(msg, 'content-length'));
  if (Number.isFinite(len) && len >= 0) body = Buffer.from(body, 'utf8').subarray(0, len).toString('utf8');
  msg.body = body;
  return msg;
}

export const getHeader = (msg: SipMessage, name: string): string | undefined => msg.headers.get(name.toLowerCase())?.[0];
export const getHeaders = (msg: SipMessage, name: string): string[] => msg.headers.get(name.toLowerCase()) ?? [];

/** Parse ';a=b;c' parameters into a lower-cased-key object. */
export function parseParams(str: string): Params {
  const params: Params = {};
  for (const part of str.split(';')) {
    const p = part.trim();
    if (!p) continue;
    const eq = p.indexOf('=');
    if (eq === -1) params[p.toLowerCase()] = true;
    else params[p.slice(0, eq).trim().toLowerCase()] = p.slice(eq + 1).trim().replace(/^"|"$/g, '');
  }
  return params;
}

export interface NameAddr {
  display: string;
  uri: string;
  params: Params;
}

/**
 * Parse a name-addr / addr-spec header value such as
 *   "Alice" <sip:1001@192.168.200.14;transport=udp>;tag=abc
 */
export function parseNameAddr(value = ''): NameAddr {
  const m = /^\s*(?:"((?:[^"\\]|\\.)*)"|([^<]*?))\s*<([^>]*)>(.*)$/.exec(value);
  if (m) return { display: (m[1] ?? m[2] ?? '').trim(), uri: m[3], params: parseParams(m[4]) };
  // addr-spec without <>: header params start at the first ';'
  const semi = value.indexOf(';');
  return {
    display: '',
    uri: (semi === -1 ? value : value.slice(0, semi)).trim(),
    params: semi === -1 ? {} : parseParams(value.slice(semi)),
  };
}

export interface SipUri {
  user: string;
  host: string;
  port?: number;
  params: Params;
}

/** sip:user@host:port;params */
export function parseUri(uri = ''): SipUri | null {
  const m = /^sips?:(?:([^@]+)@)?([^;:?>]+)(?::(\d+))?([^?]*)/i.exec(uri.trim());
  if (!m) return null;
  return {
    user: m[1] ? decodeURIComponent(m[1].split(':')[0]) : '',
    host: m[2],
    port: m[3] ? Number(m[3]) : undefined,
    params: parseParams(m[4] ?? ''),
  };
}

export interface Via {
  transport: string;
  host: string;
  port: number;
  params: Params;
}

/** Parse the top Via: "SIP/2.0/UDP host:port;branch=...;rport" */
export function parseVia(value = ''): Via | null {
  const m = /^SIP\/2\.0\/(\w+)\s+([^;:\s]+)(?::(\d+))?(.*)$/i.exec(value.trim());
  if (!m) return null;
  return { transport: m[1].toUpperCase(), host: m[2], port: m[3] ? Number(m[3]) : 5060, params: parseParams(m[4]) };
}

export const cseqOf = (msg: SipMessage): { seq: number; method: string } => {
  const [num, method] = (getHeader(msg, 'cseq') ?? '').split(/\s+/);
  return { seq: Number(num), method: (method ?? '').toUpperCase() };
};

/**
 * Serialise a message. `headers` is an ordered list of [name, value] pairs so the output is
 * predictable and easy to read in the SIP log. Empty values are skipped and Content-Length is
 * always computed here.
 */
export function buildMessage({ startLine, headers, body = '' }: { startLine: string; headers: HeaderList; body?: string }): string {
  const lines = [startLine];
  for (const [name, value] of headers) {
    if (value === undefined || value === '') continue;
    lines.push(`${name}: ${value}`);
  }
  lines.push(`Content-Length: ${Buffer.byteLength(body, 'utf8')}`);
  return `${lines.join('\r\n')}\r\n\r\n${body}`;
}

export interface ResponseOptions {
  toTag?: string;
  extraHeaders?: HeaderList;
  body?: string;
}

/**
 * Build a response to a received request (RFC 3261 §8.2.6): copy Via / From / To / Call-ID /
 * CSeq and add our To-tag where the dialog needs one.
 */
export function buildResponse(req: SipMessage, status: number, reason: string, { toTag, extraHeaders = [], body = '' }: ResponseOptions = {}): string {
  let to = getHeader(req, 'to') ?? '';
  if (toTag && !/;\s*tag=/i.test(to)) to += `;tag=${toTag}`;
  const headers: HeaderList = [
    ...getHeaders(req, 'via').map((v): [string, string] => ['Via', v]),
    ...getHeaders(req, 'record-route').map((v): [string, string] => ['Record-Route', v]),
    ['From', getHeader(req, 'from')],
    ['To', to],
    ['Call-ID', getHeader(req, 'call-id')],
    ['CSeq', getHeader(req, 'cseq')],
    ...extraHeaders,
  ];
  return buildMessage({ startLine: `SIP/2.0 ${status} ${reason}`, headers, body });
}
