// Entry point: HTTP (built React app + /api/status), WebSocket signalling at /ws, and the SIP UA
// registered to Issabel / Asterisk.
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import express from 'express';
import { WebSocketServer } from 'ws';
import { loadConfig } from './config.ts';
import { MediaGateway } from './MediaGateway.ts';
import { Supervisor } from './ami/Supervisor.ts';
import { SipUA } from './sip/SipUA.ts';

const ts = (): string => new Date().toISOString().slice(11, 23);
const log = (line: string): void => console.log(`${ts()} ${line}`);

let config;
try {
  config = loadConfig();
} catch (err) {
  console.error(`Configuration error: ${(err as Error).message}`);
  process.exit(1);
}

const ua = new SipUA();
const pbx = `${config.pbxIp}:${config.pbxPort}`;
for (const w of config.warnings) console.warn(`${ts()} WARNING ${w}`);
const supervisor = config.ami ? new Supervisor({ ...config.ami, extension: config.extension, log }) : undefined;
if (!supervisor) log('call supervision (listen / whisper / takeover) is off: set AMI_USER and AMI_SECRET to enable it');
const gateway = new MediaGateway(ua, {
  supervisor,
  extension: config.extension,
  pbx,
  transport: config.transport,
  encryption: config.encryption,
  codecs: config.codecs,
  webrtcPortRange: config.webrtcPortRange,
  stunServers: config.stunServers,
  log,
});

ua.on('registration', (r) => log(`SIP ${config.extension}@${pbx}: ${r.state}${r.error ? ` (${r.error})` : ''}`));
if (config.logSip) {
  ua.on('log', ({ dir, peer, text }) => log(`${dir === 'out' ? '>>' : '<<'} ${peer}\n${text.trimEnd()}\n`));
}

const app = express();
app.get('/api/status', (_req, res) => {
  res.json(gateway.status());
});
app.get('/api/calls', (_req, res) => {
  res.json(supervisor?.calls ?? []);
});
const webDir = path.resolve(process.cwd(), 'dist/web');
if (fs.existsSync(webDir)) {
  app.use(express.static(webDir));
} else {
  app.get('/', (_req, res) => {
    res.type('text').send('Frontend not built. Run "npm run dev" and open http://localhost:5173, or "npm start".');
  });
}

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });
wss.on('connection', (ws) => gateway.handleSocket(ws));

server.listen(config.gatewayPort, config.gatewayHost, () => {
  log(`gateway listening on http://${config.gatewayHost}:${config.gatewayPort} (WebSocket /ws)`);
  void ua.start({
    server: config.pbxIp,
    serverPort: config.pbxPort,
    transport: config.transport,
    tls: config.tls,
    srtp: config.encryption,
    extension: config.extension,
    authUser: config.authUser,
    password: config.secret,
    displayName: config.displayName,
    localPort: config.sipLocalPort,
    localIp: config.sipLocalIp,
    codecs: config.codecs,
    rtpPortMin: config.rtpPortMin,
    rtpPortMax: config.rtpPortMax,
  }).then(() => log(`SIP ${config.transport.toUpperCase()} ${ua.localIp}:${ua.localPort} -> ${pbx}, media ${config.encryption ? 'SRTP' : 'plain RTP'}`));
  supervisor?.start();
});

let stopping = false;
async function shutdown(): Promise<void> {
  if (stopping) process.exit(1); // second Ctrl+C: don't wait for the un-REGISTER
  stopping = true;
  log('shutting down (un-registering)...');
  await gateway.close();
  await supervisor?.stop();
  await ua.stop();
  wss.close();
  server.close();
  process.exit(0);
}
process.on('SIGINT', () => void shutdown());
process.on('SIGTERM', () => void shutdown());
