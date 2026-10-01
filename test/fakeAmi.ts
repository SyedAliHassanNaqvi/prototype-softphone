// A tiny scripted Asterisk Manager Interface on 127.0.0.1 for tests: banner, Login, a
// configurable channel list for CoreShowChannels, and Originate / Bridge / Hangup that are
// recorded (and can be scripted through onAction).
import net from 'node:net';
import { buildAmiAction, parseAmiMessage, type AmiFields, type AmiMessage } from '../server/ami/AmiClient.ts';

export const AMI_SECRET = 'amisecret';

export interface FakeAmi {
  port: number;
  /** Every action received (keys lower-cased). */
  actions: AmiMessage[];
  /** Channels returned by CoreShowChannels, as AMI fields (Channel, BridgeId, Application...). */
  channels: AmiFields[];
  logins: number;
  /** Script extra behaviour; runs after the Success response was sent. */
  onAction?: (action: AmiMessage) => void;
  waitFor(pred: (a: AmiMessage) => boolean): Promise<AmiMessage>;
  /** Send an event to every logged-in client. */
  emitEvent(fields: AmiFields): void;
  close(): void;
}

export async function startFakeAmi(): Promise<FakeAmi> {
  const sockets = new Set<net.Socket>();
  const loggedIn = new Set<net.Socket>();
  let waiters: Array<{ pred: (a: AmiMessage) => boolean; resolve: (a: AmiMessage) => void }> = [];

  const ami: FakeAmi = {
    port: 0,
    actions: [],
    channels: [],
    logins: 0,
    waitFor: (pred) =>
      new Promise((resolve) => {
        const hit = ami.actions.find(pred);
        if (hit) resolve(hit);
        else waiters.push({ pred, resolve });
      }),
    emitEvent: (fields) => {
      for (const s of loggedIn) s.write(buildAmiAction(fields));
    },
    close: () => {
      for (const s of sockets) s.destroy();
      server.close();
    },
  };

  const handle = (socket: net.Socket, a: AmiMessage): void => {
    const reply = (fields: AmiFields): void => {
      socket.write(buildAmiAction({ ...fields, ActionID: a.actionid }));
    };
    const action = (a.action ?? '').toLowerCase();
    if (action === 'login') {
      ami.logins++;
      if (a.secret === AMI_SECRET) {
        loggedIn.add(socket);
        reply({ Response: 'Success', Message: 'Authentication accepted' });
      } else {
        reply({ Response: 'Error', Message: 'Authentication failed' });
      }
    } else if (!loggedIn.has(socket)) {
      reply({ Response: 'Error', Message: 'Permission denied' });
    } else if (action === 'coreshowchannels') {
      reply({ Response: 'Success', EventList: 'start', Message: 'Channels will follow' });
      for (const ch of ami.channels) reply({ Event: 'CoreShowChannel', ...ch });
      reply({ Event: 'CoreShowChannelsComplete', EventList: 'Complete', ListItems: ami.channels.length });
    } else if (action === 'originate') {
      reply({ Response: 'Success', Message: 'Originate successfully queued' });
    } else if (action === 'bridge') {
      reply({ Response: 'Success', Message: 'Channels have been bridged' });
    } else if (action === 'hangup') {
      reply({ Response: 'Success', Message: 'Channel Hungup' });
    } else if (action === 'logoff') {
      reply({ Response: 'Goodbye', Message: 'Thanks for all the fish.' });
    } else {
      reply({ Response: 'Error', Message: 'Invalid/unknown command' });
    }
    ami.onAction?.(a);
  };

  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.setEncoding('utf8');
    socket.write('Asterisk Call Manager/2.10.4\r\n');
    let buffer = '';
    socket.on('data', (chunk: string) => {
      buffer += chunk;
      let end: number;
      while ((end = buffer.indexOf('\r\n\r\n')) >= 0) {
        const a = parseAmiMessage(buffer.slice(0, end));
        buffer = buffer.slice(end + 4);
        ami.actions.push(a);
        handle(socket, a);
        waiters = waiters.filter((w) => (w.pred(a) ? (w.resolve(a), false) : true));
      }
    });
    socket.on('error', () => {});
    socket.on('close', () => {
      sockets.delete(socket);
      loggedIn.delete(socket);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  ami.port = (server.address() as net.AddressInfo).port;
  return ami;
}
