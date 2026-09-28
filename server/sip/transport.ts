// SIP transports towards the PBX.
//
//   UdpTransport: one dgram socket (RFC 3261 §18 over UDP). Unreliable: transactions retransmit.
//   TlsTransport: one persistent TLS connection to the PBX (normally port 5061). Reliable, so
//                 transactions don't retransmit. Requests from the PBX (incoming INVITE, BYE,
//                 OPTIONS...) arrive on the same connection, which is also where every response
//                 goes back. This is how X-Lite / Bria / MicroSIP run SIP over TLS: they never
//                 accept inbound TLS connections, the PBX reuses the one the phone opened.
//
// SIP over a stream needs framing: messages are delimited by the blank line after the headers
// plus Content-Length bytes of body (RFC 3261 §18.3). SipStreamParser does that.
import dgram from 'node:dgram';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import net from 'node:net';
import tls from 'node:tls';

export type TransportProtocol = 'UDP' | 'TLS';

export interface Remote {
  address: string;
  port: number;
}

export interface TlsSettings {
  /** Verify the PBX certificate (chain + host name). Only disable for self-signed test PBXs. */
  rejectUnauthorized: boolean;
  /** PEM file with the CA (or the PBX's self-signed certificate) to trust. */
  caFile?: string;
  /** Host name to verify the certificate against (and to send as SNI) when connecting by IP. */
  servername?: string;
  /** Optional client certificate + key (PEM files) if Asterisk has tlsverifyclient=yes. */
  certFile?: string;
  keyFile?: string;
}

interface TransportEvents {
  message: [Buffer, Remote];
  /** TLS only: the connection came up (again). Carries the new local address. */
  connected: [{ localIp: string; localPort: number }];
  /** TLS only: the connection dropped; the transport reconnects on its own. */
  disconnected: [string];
  error: [Error];
}

export interface SipTransport extends EventEmitter<TransportEvents> {
  readonly protocol: TransportProtocol;
  /** Reliable (stream) transports don't retransmit requests. */
  readonly reliable: boolean;
  readonly localPort: number;
  /** For TLS: the local address of the connection; for UDP: undefined (detected separately). */
  readonly localIp: string | undefined;
  open(): Promise<void>;
  send(text: string, host: string, port: number): void;
  close(): void;
}

// ---------------------------------------------------------------------------------------------

export class UdpTransport extends EventEmitter<TransportEvents> implements SipTransport {
  readonly protocol = 'UDP';
  readonly reliable = false;
  readonly localIp = undefined;
  localPort = 0;
  private socket: dgram.Socket | null = null;
  private readonly port: number;

  constructor(port: number) {
    super();
    this.port = port;
  }

  async open(): Promise<void> {
    const tryBind = (p: number): Promise<dgram.Socket> =>
      new Promise((resolve, reject) => {
        const s = dgram.createSocket('udp4');
        s.once('error', (err) => {
          s.close();
          reject(err);
        });
        s.bind(p, '0.0.0.0', () => {
          s.removeAllListeners('error');
          s.on('error', (err) => this.emit('error', err));
          s.on('message', (buf, rinfo) => this.emit('message', buf, rinfo));
          resolve(s);
        });
      });
    // If the port is taken (another softphone on this PC) fall back to a random one.
    const socket = await tryBind(this.port).catch((err: NodeJS.ErrnoException) =>
      this.port !== 0 && err.code === 'EADDRINUSE' ? tryBind(0) : Promise.reject(err));
    this.socket = socket;
    this.localPort = socket.address().port;
  }

  send(text: string, host: string, port: number): void {
    this.socket?.send(text, port, host);
  }

  close(): void {
    try {
      this.socket?.close();
    } catch {
      /* already closed */
    }
    this.socket = null;
  }
}

// ---------------------------------------------------------------------------------------------

const MAX_MESSAGE = 64 * 1024;

/** Splits a SIP byte stream into messages (RFC 3261 §18.3). */
export class SipStreamParser {
  private buf: Buffer = Buffer.alloc(0);

  /** Feed received bytes; returns the complete messages. Throws on a malformed stream. */
  push(chunk: Buffer): Buffer[] {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    const out: Buffer[] = [];
    for (;;) {
      // Keep-alives (RFC 5626 CRLF / CRLFCRLF) and stray line breaks between messages.
      let start = 0;
      while (start < this.buf.length && (this.buf[start] === 0x0d || this.buf[start] === 0x0a)) start++;
      if (start) this.buf = this.buf.subarray(start);
      if (!this.buf.length) break;

      const headerEnd = this.buf.indexOf('\r\n\r\n');
      if (headerEnd === -1) {
        if (this.buf.length > MAX_MESSAGE) throw new Error('SIP header too large');
        break;
      }
      const head = this.buf.subarray(0, headerEnd).toString('utf8');
      const m = /^(?:content-length|l)[ \t]*:[ \t]*(\d+)[ \t]*$/im.exec(head);
      // Over a stream Content-Length is mandatory (§18.3); treat a missing one as 0.
      const bodyLen = m ? Number(m[1]) : 0;
      if (bodyLen > MAX_MESSAGE) throw new Error('SIP body too large');
      const total = headerEnd + 4 + bodyLen;
      if (this.buf.length < total) break;
      out.push(Buffer.from(this.buf.subarray(0, total)));
      this.buf = this.buf.subarray(total);
    }
    return out;
  }
}

const KEEPALIVE_MS = 30000;
const CONNECT_TIMEOUT_MS = 10000;
const RECONNECT_MIN_MS = 1000;
const RECONNECT_MAX_MS = 30000;

export class TlsTransport extends EventEmitter<TransportEvents> implements SipTransport {
  readonly protocol = 'TLS';
  readonly reliable = true;
  localPort = 0;
  localIp: string | undefined;
  private socket: tls.TLSSocket | null = null;
  private parser = new SipStreamParser();
  private keepalive: NodeJS.Timeout | undefined;
  private reconnectTimer: NodeJS.Timeout | undefined;
  private reconnectDelay = RECONNECT_MIN_MS;
  private closed = false;
  private readonly host: string;
  private readonly port: number;
  private readonly settings: TlsSettings;

  constructor(host: string, port: number, settings: TlsSettings) {
    super();
    this.host = host;
    this.port = port;
    this.settings = settings;
  }

  /** Connect once. Rejects with a readable error (certificate problems included). */
  open(): Promise<void> {
    this.closed = false;
    return this.connect();
  }

  private connect(): Promise<void> {
    const s = this.settings;
    const options: tls.ConnectionOptions = {
      host: this.host,
      port: this.port,
      rejectUnauthorized: s.rejectUnauthorized,
      minVersion: 'TLSv1.2',
      ca: s.caFile ? fs.readFileSync(s.caFile) : undefined,
      cert: s.certFile ? fs.readFileSync(s.certFile) : undefined,
      key: s.keyFile ? fs.readFileSync(s.keyFile) : undefined,
      // SNI must be a host name, never an IP literal.
      servername: s.servername ?? (net.isIP(this.host) ? undefined : this.host),
    };
    if (s.servername) {
      // Connect to the IP, but verify the certificate against the configured name.
      options.checkServerIdentity = (_host, cert) => tls.checkServerIdentity(s.servername!, cert);
    }

    return new Promise((resolve, reject) => {
      let settled = false;
      const socket = tls.connect(options);
      socket.setNoDelay(true);
      socket.setKeepAlive(true, KEEPALIVE_MS);
      socket.setTimeout(CONNECT_TIMEOUT_MS, () => {
        if (!settled) socket.destroy(Object.assign(new Error('TLS handshake timed out'), { code: 'ETIMEDOUT' }));
      });

      socket.once('secureConnect', () => {
        settled = true;
        socket.setTimeout(0);
        this.socket = socket;
        this.parser = new SipStreamParser();
        this.localIp = socket.localAddress;
        this.localPort = socket.localPort ?? 0;
        this.reconnectDelay = RECONNECT_MIN_MS;
        // RFC 5626 CRLFCRLF ping keeps NAT/firewall state for the connection alive.
        clearInterval(this.keepalive);
        this.keepalive = setInterval(() => socket.write('\r\n\r\n'), KEEPALIVE_MS);
        this.emit('connected', { localIp: this.localIp ?? '', localPort: this.localPort });
        resolve();
      });

      socket.on('data', (chunk: Buffer) => {
        let messages: Buffer[];
        try {
          messages = this.parser.push(chunk);
        } catch (err) {
          socket.destroy(err as Error); // unrecoverable framing error: start over
          return;
        }
        for (const m of messages) this.emit('message', m, { address: this.host, port: this.port });
      });

      socket.on('error', (err) => {
        if (!settled) {
          settled = true;
          reject(new Error(describeTlsError(err)));
        } else {
          this.emit('error', err);
        }
      });

      socket.on('close', () => {
        if (this.socket !== socket) return; // a connection attempt that never came up
        this.socket = null;
        clearInterval(this.keepalive);
        if (this.closed) return;
        this.emit('disconnected', 'TLS connection to the PBX closed');
        this.scheduleReconnect();
      });
    });
  }

  private scheduleReconnect(): void {
    clearTimeout(this.reconnectTimer);
    this.reconnectTimer = setTimeout(() => {
      if (this.closed) return;
      this.connect().catch((err: Error) => {
        this.emit('error', err);
        this.reconnectDelay = Math.min(this.reconnectDelay * 2, RECONNECT_MAX_MS);
        this.scheduleReconnect();
      });
    }, this.reconnectDelay);
  }

  send(text: string): void {
    // Host/port are ignored: everything goes to the PBX over the one connection. A message
    // sent while reconnecting is lost; the transaction layer times it out (408).
    if (this.socket && !this.socket.destroyed) this.socket.write(text);
  }

  close(): void {
    this.closed = true;
    clearTimeout(this.reconnectTimer);
    clearInterval(this.keepalive);
    this.socket?.end();
    this.socket?.destroy();
    this.socket = null;
  }
}

/** Turn OpenSSL / socket errors into something a PBX admin can act on. */
export function describeTlsError(err: NodeJS.ErrnoException): string {
  const code = err.code ?? '';
  if (code === 'DEPTH_ZERO_SELF_SIGNED_CERT' || code === 'SELF_SIGNED_CERT_IN_CHAIN' || code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || code === 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY') {
    return `The PBX certificate is not trusted (${code}). Set PBX_TLS_CA to the PBX's CA/certificate file, or PBX_TLS_VERIFY=false for a test PBX.`;
  }
  if (code === 'ERR_TLS_CERT_ALTNAME_INVALID') {
    return `The PBX certificate does not match the address (${err.message}). Set PBX_TLS_SERVERNAME to the name in the certificate.`;
  }
  if (code === 'CERT_HAS_EXPIRED') return 'The PBX certificate has expired.';
  if (code === 'ECONNREFUSED') return 'Connection refused: is TLS enabled on the PBX (tlsenable=yes / a PJSIP TLS transport) on this port?';
  if (code === 'ETIMEDOUT' || code === 'EHOSTUNREACH' || code === 'ENETUNREACH') return `Cannot reach the PBX (${code}).`;
  return `TLS error: ${err.message}`;
}
