# Arzen WebRTC-to-SIP Gateway Softphone (MVP)

A browser softphone for Issabel / Asterisk that needs **no WebRTC support on the PBX**. There's no WSS on 8089, no mini-HTTP and no JsSIP. The browser only talks WebRTC to a small Node gateway. The gateway registers to the PBX as an ordinary SIP desk phone (like X-Lite, MicroSIP or Bria) and relays the audio. It has two modes:

- **Plain local mode** (default): SIP over UDP 5060, plain RTP. This is what a LAN desk phone does.
- **Encrypted mode**: SIP over TLS 5061 and SRTP media (`PBX_TRANSPORT=tls`). See [Encrypted mode](#encrypted-mode-sip-over-tls--srtp).

```
 Browser (React)                    Node gateway (TypeScript)                       Issabel / Asterisk
 ───────────────                    ────────────────────────────                    ──────────────────
 getUserMedia (mic)                 MediaGateway: sessions, bridge, transcoding
 RTCPeerConnection ◄── WebRTC ────► BrowserPeer (werift: ICE, DTLS-SRTP)
   G.711, DTLS-SRTP                   │  G.711 payload relay (µ-law⇄A-law if needed)
 <audio autoPlay>                     ▼
                                    RtpEndpoint ◄──────── RTP or SRTP / UDP ─────► RTP port from Asterisk SDP
 WebSocket /ws ◄── JSON signalling ─► SipUA ◄──────── SIP/UDP 5060 or SIP/TLS 5061 ─► 192.168.200.14
   join/offer/candidate/dial/...      REGISTER + MD5 digest, INVITE/100/180/183/200/ACK, CANCEL, BYE
```

The browser never sees the SIP secret. It lives only in the gateway's `.env`.

## Quick start

Requires **Node.js 22.18 or newer**. The gateway runs its `.ts` files directly with Node's built-in type stripping, so there's no ts-node or tsx.

```bash
npm install
cp .env.example .env        # then set SIP_EXTENSION / SIP_SECRET (and PBX_IP if different)
npm run dev                 # gateway on :4000 + Vite on :5173 (hot reload)
```

Open **http://localhost:5173** and allow the microphone. The status pill turns green ("Registered to Issabel") once the extension is registered. "Ready to call" means the browser's WebRTC leg to the gateway is up.

Production (one process, one port):

```bash
npm start                   # builds to dist/ and serves UI + /ws on http://127.0.0.1:4000
```

## Configuration (`.env`)

| Variable | Default | Meaning |
|---|---|---|
| `PBX_IP` / `PBX_PORT` | – / `5060` (udp), `5061` (tls) | Issabel / Asterisk SIP address |
| `PBX_TRANSPORT` | `udp` | `udp` or `tls` (SIP over TLS) |
| `PBX_ENCRYPTION` | `true` with tls, else `false` | Require SRTP for the audio. No fallback to plain RTP |
| `PBX_URI` | – | Alternative to the three above: `sips:host` or `sip:host;transport=tls` selects TLS |
| `PBX_TLS_CA` | system CAs | PEM file with the CA, or the PBX's self-signed certificate, to trust |
| `PBX_TLS_SERVERNAME` | – | Name to verify the certificate against when it has no IP SAN for `PBX_IP` |
| `PBX_TLS_VERIFY` | `true` | `false` skips certificate verification (testing only) |
| `PBX_TLS_CERT` / `PBX_TLS_KEY` | – | Client certificate, only if Asterisk verifies clients |
| `SIP_EXTENSION` / `SIP_SECRET` | – | Extension to register and its secret |
| `SIP_AUTH_USER`, `SIP_DISPLAY_NAME` | – | Optional auth username (if it differs from the extension) and caller name |
| `GATEWAY_PORT` / `GATEWAY_HOST` | `4000` / `127.0.0.1` | HTTP + WebSocket listener |
| `SIP_LOCAL_PORT` | `5062` | Local UDP port for SIP (falls back to a random port if taken) |
| `SIP_LOCAL_IP` | auto | IP written into Via/Contact/SDP. Auto-detected as the interface that routes to `PBX_IP` |
| `SIP_CODECS` | `PCMA,PCMU` | G.711 preference. The first entry is also the browser-leg codec |
| `RTP_PORT_MIN` / `RTP_PORT_MAX` | `10000` / `20000` | RTP ports towards Asterisk |
| `WEBRTC_PORT_MIN` / `WEBRTC_PORT_MAX` | any | Optional fixed UDP range for the browser's ICE/media (for firewalls) |
| `STUN_SERVERS` | none | Comma-separated `stun:` URLs. Only needed if browser and gateway are not on the same LAN |
| `LOG_SIP` | `0` | `1` prints every SIP message (in encrypted mode this includes the SRTP keys) |

### Issabel extension settings (plain mode)

Use a normal **chan_sip / PJSIP SIP extension**, not a WebRTC one: `transport=udp`, `encryption=no`, `avpf=no`, `nat=yes` (or `force_rport,comedia`), and allow **alaw** and/or **ulaw**. For encrypted mode, see the next section. Put the codec your trunks use first in `SIP_CODECS`, usually `PCMA` in Pakistan and Europe and `PCMU` in North America. Then no transcoding happens anywhere.

## Encrypted mode (SIP over TLS + SRTP)

```env
PBX_IP=192.168.200.14
PBX_TRANSPORT=tls            # SIP over TLS, port 5061 unless PBX_PORT says otherwise
PBX_ENCRYPTION=true          # the default with tls
PBX_TLS_CA=./certs/issabel.crt
```

This mirrors Bria and X-Lite in TLS mode:

- **Signalling.** The gateway opens one TLS 1.2+ connection to the PBX and keeps it up with CRLF keep-alives. REGISTER, INVITE and BYE, and the PBX's own requests (incoming INVITE, BYE, OPTIONS), all run over that one connection. If it drops, the gateway reconnects with backoff and re-registers with the new Contact. It never re-registers after a 401/403, so a bad secret cannot trigger fail2ban. Contact is `<sip:1001@<ip>:<port>;transport=tls>` and Via is `SIP/2.0/TLS`.
- **Keys.** SRTP uses SDES (RFC 4568). Each side puts a random 30-byte master key+salt in its SDP: `m=audio … RTP/SAVP` plus `a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:<base64>`. These keys are only protected because the SIP around them runs over TLS. They are not derived from the TLS handshake (that would be DTLS-SRTP, which Asterisk uses only for WebRTC). That is why SRTP over UDP prints a warning.
- **Media.** [server/media/srtp.ts](server/media/srtp.ts) implements RFC 3711 AES_CM_128_HMAC_SHA1_80: AES-128 counter mode, an 80-bit HMAC-SHA1 tag, rollover-counter tracking, and packets that fail authentication are dropped. It is checked against the RFC 3711 test vectors and against werift's independent SRTP implementation.
- **Strict.** With `PBX_ENCRYPTION=true`, an answer or offer without usable SRTP ends the call with a clear reason. It never falls back to plain RTP. The UI shows `🔒 SRTP to PBX` during encrypted calls.

### Issabel / Asterisk settings for TLS + SRTP

**1. A certificate for the PBX.** It must contain the address the gateway connects to, as an IP SAN (or DNS SAN plus `PBX_TLS_SERVERNAME`). A self-signed one is fine because the gateway pins it with `PBX_TLS_CA`. On the Issabel server:

```bash
mkdir -p /etc/asterisk/keys && cd /etc/asterisk/keys
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=issabel.local" \
  -addext "subjectAltName=IP:192.168.200.14,DNS:issabel.local" \
  -keyout asterisk.key -out asterisk.crt
cat asterisk.crt asterisk.key > asterisk.pem
chown asterisk:asterisk asterisk.* && chmod 600 asterisk.key asterisk.pem
```

Copy `asterisk.crt` (never the key) to the gateway and set `PBX_TLS_CA` to it. On OpenSSL older than 1.1.1 (CentOS 7), which has no `-addext`, put the SAN in a config file with `-extensions`.

**2a. chan_sip.** This is the Issabel default. Add to `/etc/asterisk/sip_general_custom.conf`:

```ini
tlsenable=yes
tlsbindaddr=0.0.0.0:5061
tlscertfile=/etc/asterisk/keys/asterisk.pem
tlsprivatekey=/etc/asterisk/keys/asterisk.key
tlsclientmethod=tlsv1_2
transport=udp,tls
```

For the extension, set these in the Issabel GUI (PBX → Extensions → 1001, device options) or in `sip_custom_post.conf` as `[1001](+)`:

```ini
transport=tls          ; tls only, so the extension can't register over UDP
encryption=yes         ; SRTP (SDES) required: RTP/SAVP + a=crypto
avpf=no
icesupport=no
nat=force_rport,comedia
disallow=all
allow=alaw,ulaw
```

**2b. PJSIP** (Issabel 5 with chan_pjsip). Add to `pjsip.transports_custom.conf`:

```ini
[transport-tls]
type=transport
protocol=tls
bind=0.0.0.0:5061
cert_file=/etc/asterisk/keys/asterisk.crt
priv_key_file=/etc/asterisk/keys/asterisk.key
method=tlsv1_2
```

On the endpoint, set `transport=transport-tls`, `media_encryption=sdes`, `media_encryption_optimistic=no` and `allow=alaw,ulaw`.

**3. Apply and open the port.** Run `asterisk -rx "module reload chan_sip.so"` (or `core restart when convenient`, which a TLS listener change often needs). Then allow **TCP 5061** and the RTP range **UDP 10000-20000** in the Issabel firewall. Check with `asterisk -rx "sip show settings" | grep -i tls` or `pjsip show transports`, and after the gateway registers, `sip show peer 1001`, which should list the TLS transport.

**4. Verify.** In the gateway log: `SIP TLS … -> 192.168.200.14:5061, media SRTP`, then `registered`. During a call `sip show channels` / `core show channel` shows the encryption, and in a packet capture the RTP payloads are unreadable.

Common failures, shown in the UI and log:

| Message | Fix |
|---|---|
| `certificate is not trusted` | Set `PBX_TLS_CA` to the PBX's `asterisk.crt` |
| `does not match the address` | Add an IP SAN for `PBX_IP`, or set `PBX_TLS_SERVERNAME` to the certificate's name |
| `Connection refused: is TLS enabled…` | `tlsenable=yes` / TLS transport missing, or firewall on 5061 |
| `PBX … answered plain RTP but PBX_ENCRYPTION is on` | `encryption=yes` (chan_sip) / `media_encryption=sdes` (PJSIP) on the extension |
| `The PBX requires SRTP: set PBX_ENCRYPTION=true` | The extension has encryption on but the gateway doesn't |

## How the media works

- **Codec strategy: G.711 passthrough.** The gateway offers the browser only one G.711 law. Every browser supports PCMU/PCMA in WebRTC. Each 20 ms RTP payload from the browser is therefore already a frame Asterisk understands, and the gateway just rewrites the RTP header (SSRC, sequence, timestamp) and forwards it. No decoding, no jitter buffer, no extra delay. Opus is left out on purpose because it would need a full decode and re-encode per packet.
- **µ-law ⇄ A-law.** If Asterisk answers with the other law, each byte is mapped through a 256-entry table. The UI shows `PCMU ⇄ PCMA (transcoding)` when that happens.
- **Timelines.** `RtpTimeline` keeps each outgoing stream continuous across SSRC changes, for example when Asterisk re-bridges the call. Gaps are preserved, and duplicates and late packets are dropped.
- **Early media.** A 183 with SDP (PSTN ringback or announcements) is relayed to the browser before answer.
- **Mute** disables the mic track in the browser, and the gateway also sends G.711 silence to Asterisk. The RTP stream stays alive, so `rtptimeout` doesn't hang up.
- **DTMF.** Keypad presses during a call go to the gateway and are sent as RFC 4733 telephone-events, or as SIP INFO if the PBX didn't offer them.

## Signalling protocol (`/ws`, JSON)

Types are in [`shared/protocol.ts`](shared/protocol.ts).

| Browser → gateway | Gateway → browser |
|---|---|
| `join` | `status` (registration, call, WebRTC state: full snapshot on every change) |
| `offer {sdp}`, `candidate {candidate}` | `answer {sdp}` (includes the gateway's ICE candidates) |
| `dial {number}`, `hangup`, `accept`, `reject` | `error {message}` |
| `mute {muted}`, `dtmf {digit}` | |

There is one browser session per gateway. A second tab takes over the session, and a call in progress continues in the new tab. Inbound calls ring in the browser. If no browser is connected, the gateway answers `480 Temporarily Unavailable` so Asterisk can fall through to voicemail.

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Gateway (`node --watch`) + Vite dev server with a `/ws` proxy |
| `npm start` | Build, then run `dist/server/gateway.js` (serves `dist/web`) |
| `npm run build` | `tsc` for the server, typecheck + Vite build for the web app |
| `npm run typecheck` | Typecheck both projects |
| `npm test` | Unit tests (SIP, SDP, G.711, RTP, SRTP vectors, TLS framing, config) + end-to-end tests: a werift peer acting as the browser ⇄ real gateway ⇄ fake Asterisk, over UDP and over TLS + SRTP |

## Layout

```
server/
  gateway.ts          entry: express + WebSocket server + SIP UA start/stop
  config.ts           .env parsing and validation
  MediaGateway.ts     browser sessions, signalling, media bridge between the two legs
  sip/                SipUA (transactions, REGISTER, calls), transport.ts (UDP + TLS framing/reconnect),
                      message parser, MD5 digest, SDP (incl. SDES a=crypto)
  media/              RtpEndpoint (RTP/SRTP towards Asterisk, RFC 4733), srtp.ts (RFC 3711),
                      rtp helpers, G.711 tables
  webrtc/BrowserPeer.ts  werift peer connection for the browser leg
shared/protocol.ts    WebSocket message types (used by both sides)
web/                  Vite + React app (App.tsx, useWebRTC.ts)
test/                 node --test suites, harness, fake PBX (UDP/TLS, SRTP via werift), fixtures/ test cert
```

## Limits of this MVP

- One extension, one call at a time. No hold, transfer or conference.
- The browser must reach the gateway over UDP (same LAN, or open `WEBRTC_PORT_*`). No TURN.
- `getUserMedia` needs a secure context. `localhost` / `127.0.0.1` is fine. To use it from another PC, put the gateway behind HTTPS, for example with a reverse proxy, and set `GATEWAY_HOST=0.0.0.0`. Anyone who can reach the gateway can call on its extension, so keep it private or add auth.
- Encrypted mode supports AES_CM_128_HMAC_SHA1_80 only: no MKI, no AES-256/GCM suites, no SRTCP (RTCP isn't used). TLS must be to the PBX directly (no outbound proxy), and the PBX must be able to reach the gateway's connection. That means no double NAT unless Asterisk uses `nat=force_rport`.
