// SIP Digest authentication (RFC 2617 / RFC 3261 §22.4), MD5 only.
//
// Asterisk answers a REGISTER or INVITE with 401 (WWW-Authenticate) or 407 (Proxy-Authenticate)
// holding a realm + nonce. We resend the request with an Authorization / Proxy-Authorization
// header whose `response` proves we know the secret without sending it:
//   HA1      = MD5(username:realm:password)
//   HA2      = MD5(method:digest-uri)
//   response = MD5(HA1:nonce:HA2)                         (no qop, chan_sip's default)
//   response = MD5(HA1:nonce:nc:cnonce:qop:HA2)           (qop=auth, e.g. PJSIP)
import crypto from 'node:crypto';

export type Challenge = Record<string, string>;

const md5 = (s: string): string => crypto.createHash('md5').update(s).digest('hex');

/** Parse `Digest realm="asterisk",nonce="abc",qop="auth"` into an object. */
export function parseChallenge(header = ''): Challenge | null {
  const m = /^\s*Digest\s+(.*)$/i.exec(header);
  if (!m) return null;
  // Params are comma separated; values may be quoted and contain commas (e.g. qop="auth,auth-int").
  const params: Challenge = {};
  const re = /([a-zA-Z0-9_-]+)\s*=\s*(?:"([^"]*)"|([^,\s]*))/g;
  let p: RegExpExecArray | null;
  while ((p = re.exec(m[1]))) params[p[1].toLowerCase()] = p[2] ?? p[3];
  return params;
}

export interface AuthorizationInput {
  challenge: Challenge;
  method: string;
  uri: string;
  username: string;
  password: string;
  /** Nonce count: 1 for the first use of a nonce. */
  nc?: number;
  cnonce?: string;
}

/** Compute the Authorization header value for a challenge. */
export function buildAuthorization({
  challenge, method, uri, username, password, nc = 1, cnonce = crypto.randomBytes(8).toString('hex'),
}: AuthorizationInput): { header: string; response: string } {
  const algorithm = (challenge.algorithm ?? 'MD5').toUpperCase();
  if (algorithm !== 'MD5') throw new Error(`Unsupported digest algorithm ${challenge.algorithm}`);

  const realm = challenge.realm ?? '';
  const nonce = challenge.nonce ?? '';
  const qopOptions = (challenge.qop ?? '').split(',').map((q) => q.trim().toLowerCase());
  const qop = qopOptions.includes('auth') ? 'auth' : '';
  const ncHex = nc.toString(16).padStart(8, '0');

  const ha1 = md5(`${username}:${realm}:${password}`);
  const ha2 = md5(`${method}:${uri}`);
  const response = qop ? md5(`${ha1}:${nonce}:${ncHex}:${cnonce}:${qop}:${ha2}`) : md5(`${ha1}:${nonce}:${ha2}`);

  const parts = [`username="${username}"`, `realm="${realm}"`, `nonce="${nonce}"`, `uri="${uri}"`, `response="${response}"`, 'algorithm=MD5'];
  if (qop) parts.push(`qop=${qop}`, `nc=${ncHex}`, `cnonce="${cnonce}"`);
  if (challenge.opaque !== undefined) parts.push(`opaque="${challenge.opaque}"`);
  return { header: `Digest ${parts.join(', ')}`, response };
}
