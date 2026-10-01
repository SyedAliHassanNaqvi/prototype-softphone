Act as a Principal VoIP, Real-Time Audio, and WebRTC Systems Engineer.

I want to build an end-to-end Minimum Viable Product (MVP) of a WebRTC-to-SIP Media Gateway softphone.

### Architecture Overview

1. Frontend (Browser / React):
   - Captures user microphone audio via `navigator.mediaDevices.getUserMedia()`.
   - Establishes a standard peer-to-peer WebRTC connection (`RTCPeerConnection`) with our Node.js backend.
   - Provides a dialer UI with call controls (Dial, Mute, Hang Up, Status indicator).
   - DOES NOT talk to Issabel directly (no JsSIP, no WSS:8089, no PBX credentials in the browser).

2. Backend (Node.js Gateway / Media Proxy):
   - Browser Side: Acts as the WebRTC Peer endpoint using a modern Node WebRTC engine (`werift`). Terminates the browser's WebRTC audio track, performs ICE candidate gathering, and negotiates SDP via a local WebSocket/REST signaling channel.
   - Issabel/Asterisk Side: Emulates a native desktop softphone (exactly like X-Lite):
     - Signaling: Native SIP over raw UDP on port 5060 (RFC 3261) using the `sip` npm library or Node `dgram` sockets to register the extension and manage dialogs (REGISTER with MD5 Digest Auth, INVITE, 100/180/200, ACK, BYE).
     - Media Transcoding & Forwarding: Converts the browser's inbound WebRTC audio track (Opus/G.711) into raw, unencrypted RTP/UDP packets and streams them directly to Asterisk's negotiated RTP media port (RFC 3550). Concurrently reads incoming RTP UDP packets from Asterisk and routes them back into the WebRTC outgoing track to the browser.
   - Target PBX: Issabel / Asterisk at 192.168.200.14:5060 (No WSS/port 8089 or mini-HTTP required on Issabel).

---

### Key Requirements & Deliverables

#### 1. Backend WebRTC-to-SIP Gateway (`gateway.js` / Node.js)

- Dependencies: `express`, `ws`, `sip`, `werift` (or `@roamhq/wrtc`), `dotenv`.
- SIP User Agent Module:
  - Binds a native UDP socket on `0.0.0.0:5062` to communicate with `192.168.200.14:5060`.
  - Implements SIP Digest Authentication (`MD5`) handling `401 Unauthorized` challenges from Asterisk to register an extension (e.g., `1001`) with its SIP secret.
  - Exposes an interface to trigger an outbound call: generates a standard SIP `INVITE` with an SDP offer containing the backend's local RTP port and payload types (PCMA / PCMU / G.711 or Opus).
- WebRTC Termination & Media Relay (`werift`):
  - Accepts WebRTC SDP offer from the React browser.
  - Pulls the audio track from the WebRTC peer connection.
  - Bridges the WebRTC RTP payload directly to raw UDP sockets pointing to the Asterisk media IP/port extracted from Asterisk's `200 OK` SDP.
  - Listens on a local UDP socket for Asterisk's return RTP stream and feeds it into `RTCAudioSource` / `MediaStreamTrack` back to the browser.
- Browser Signaling Socket:
  - A lightweight WebSocket server for browser-to-gateway signaling (`join`, `offer`, `answer`, `candidate`, `dial`, `hangup`, `status`).

#### 2. React Frontend (`App.jsx` + `useWebRTC.js`)

- Requests microphone permission on mount (`audio: true`).
- Creates an `RTCPeerConnection` and attaches local audio stream tracks.
- Plays incoming remote audio streams through an HTML5 `<audio autoPlay />` element.
- Exposes controls:
  - Extension registration status (Registered to Issabel, Idle, Calling, Connected).
  - Dial pad for entering extensions (e.g. `1002`) or PSTN numbers (`03...`).
  - Active call timer, Mute toggle, and Hangup button.

#### 3. Execution & Configuration

- Provide a clean `.env.example`:

---

## Implementation notes (current state)

Everything is TypeScript. See README.md for setup, config and architecture.

### Layout
- `server/gateway.ts`: entry (express, `ws` at `/ws`, SIP UA start, SIGINT un-REGISTER). `server/config.ts`: `.env`.
- `server/MediaGateway.ts`: one browser session, WS signalling, media bridge + G.711 law transcoding.
  (Not `Gateway.ts`: Windows is case-insensitive and it would clash with `gateway.ts`.)
- `server/sip/`: hand-written SIP UA (`SipUA.ts`, `message.ts`, `digest.ts`, `sdp.ts`). The `sip` npm package is not used. `transport.ts` has `UdpTransport` (dgram) and `TlsTransport` (one persistent TLS connection to the PBX, `SipStreamParser` framing, CRLF keep-alive, reconnect + re-REGISTER).
- `server/media/`: `RtpEndpoint.ts` (RTP/SRTP to Asterisk, RFC 4733 DTMF), `srtp.ts` (RFC 3711 AES_CM_128_HMAC_SHA1_80, SDES keys), `rtp.ts` (parse/build, `RtpTimeline`), `g711.ts`.
- Modes: `PBX_TRANSPORT=udp|tls`, `PBX_ENCRYPTION` (SRTP, defaults to on with tls). Encrypted mode is strict: no fallback to plain RTP.
- `server/webrtc/BrowserPeer.ts`: werift peer. It offers the browser ONE G.711 law (`SIP_CODECS[0]`), so payloads pass through untouched. No Opus.
- `shared/protocol.ts`: WS message types for both sides. `web/`: Vite + React (`App.tsx`, `useWebRTC.ts`).
- Supervision (listen / whisper / takeover), optional, enabled by `AMI_USER`/`AMI_SECRET`. `server/ami/`: `AmiClient.ts` (hand-written AMI over TCP 5038), `channels.ts` (pure: CoreShowChannels → `LiveCall[]`), `Supervisor.ts` (live-calls polling + event-triggered refresh, Originate ChanSpy, takeover = AMI `Bridge` customer↔our spy channel + `Hangup` agent). `MediaGateway` auto-answers the spy INVITE by its one-time token (caller ID number `spy<hex>`, or `X-Arzen-Monitor`). Listen/whisper switching is DTMF 4/5 (ChanSpy `d` option); keypad DTMF is blocked while spying. Always spy on the AGENT's full channel name (whisper must reach only the agent; ChanSpy matches by prefix).

### Commands
- `npm run dev`: `node --watch server/gateway.ts` + Vite (127.0.0.1:5173, proxies `/ws` and `/api` to GATEWAY_PORT).
- `npm start`: build to `dist/` and run `dist/server/gateway.js` (serves `dist/web` from the cwd).
- `npm test`: `node --test "test/*.test.ts"`, with unit tests + werift "browser" ⇄ gateway ⇄ fake PBX over real UDP. `test/fakeAmi.ts` is a scripted AMI server for the supervision tests.
- `npm run typecheck`: server + tests (`tsconfig.test.json`) + web.
- The TLS tests use `test/fixtures/pbx-cert.pem` (self-signed, SAN pbx.test/localhost/127.0.0.1, valid to 2126). The fake PBX does SRTP with werift's `SrtpSession` so the tests check interoperability.

### Rules / gotchas
- The server runs `.ts` directly with Node type stripping. Use `.ts` extensions in relative imports, `import type` for types, and no enums, namespaces or parameter properties (`erasableSyntaxOnly`). `tsc` rewrites the extensions to `.js` for `dist/`.
- Never auto-retry REGISTER after 401/403. Issabel's fail2ban bans the IP. Don't point tests or experiments at the real PBX with a wrong secret. TLS reconnects re-REGISTER only while `authRejected` is false. The same applies to AMI logins (`AmiClient.authRejected`).
- Keep `server/ami` free of werift/express/the SIP stack: it is meant to move into the PMS backend (which already has an AMI connection) during integration.
- Regex-heavy edits through shell heredocs / `node -e` lose backslashes. Use the Edit tool or a script file.
- One call at a time. All SIP requests go to the PBX as the outbound proxy (no DNS SRV, no NAT traversal beyond `rport`).
- Keep `server/sip` and `server/media` free of werift/express so they stay unit-testable.
