// The local filtering HTTP proxy, ported from proxy.go in the parent
// directory: HTTPS goes through CONNECT tunneling, plain HTTP through
// absolute-URI forwarding; DNS for the target happens on the host side, so
// the sandbox needs no UDP at all. A host is reachable if and only if it is
// loopback or on the allow list and not on the deny list.
import * as http from 'node:http';
import * as net from 'node:net';
import type { Duplex } from 'node:stream';

export interface ProxyPolicy {
  allow: string[];
  deny: string[];
}

// Reports whether host equals domain or is a subdomain of it (entries with a
// leading '*.' are treated as suffix matches).
export function domainMatches(host: string, domain: string): boolean {
  const d = domain.replace(/^\*\./, '');
  return host === d || host.endsWith('.' + d);
}

function isLoopbackHost(host: string): boolean {
  if (host === 'localhost') return true;
  const family = net.isIP(host);
  if (family === 4) return host.startsWith('127.');
  if (family === 6) return host === '::1';
  return false;
}

export function splitHostPort(hostPort: string): { host: string; port: number } {
  if (hostPort.startsWith('[')) {
    const end = hostPort.indexOf(']');
    if (end === -1) return { host: hostPort, port: 80 };
    const host = hostPort.slice(1, end);
    const port = Number(hostPort.slice(end + 2));
    return { host, port: Number.isNaN(port) || port === 0 ? 80 : port };
  }
  const colon = hostPort.lastIndexOf(':');
  if (colon === -1) return { host: hostPort, port: 80 };
  const port = Number(hostPort.slice(colon + 1));
  if (Number.isNaN(port)) return { host: hostPort.slice(0, colon), port: 80 };
  return { host: hostPort.slice(0, colon), port };
}

// Reports whether hostPort (host or host:port) may be reached. Deny wins
// over allow; loopback is always admitted; allow entries match the host
// itself and its subdomains; an empty allow list means every non-loopback
// host is blocked.
export function allowedHost(policy: ProxyPolicy, hostPort: string): boolean {
  const { host } = splitHostPort(hostPort);
  const h = host.toLowerCase().replace(/\.$/, '');
  for (const d of policy.deny) {
    if (domainMatches(h, d.toLowerCase())) return false;
  }
  if (isLoopbackHost(h)) return true;
  for (const d of policy.allow) {
    if (domainMatches(h, d.toLowerCase())) return true;
  }
  return false;
}

const dialTimeoutMs = 30_000;
const responseHeaderTimeoutMs = 60_000;

// The forwarding agent dials directly; the host's own proxy environment
// must not influence where traffic goes (Node's http.request ignores
// HTTP(S)_PROXY by default, so this is inherent).
const forwardAgent = new http.Agent({ keepAlive: true, maxSockets: 8 });

function denyBody(host: string): string {
  return (
    `mxc-node proxy: ${host} is not in the network allow list.\n` +
    'Allow it by adding it to network.allow_domain in the profile\n' +
    'and restarting the sandbox.\n'
  );
}

function denyResponse(res: http.ServerResponse, host: string): void {
  const body = denyBody(host);
  res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(body);
}

function denyConnect(client: Duplex, host: string): void {
  const body = denyBody(host);
  client.end(
    'HTTP/1.1 403 Forbidden\r\n' +
    'Content-Type: text/plain; charset=utf-8\r\n' +
    `Content-Length: ${Buffer.byteLength(body)}\r\n` +
    'Connection: close\r\n\r\n' +
    body,
  );
}

function handleForward(req: http.IncomingMessage, res: http.ServerResponse, policy: ProxyPolicy): void {
  let url: URL;
  try {
    url = new URL(req.url ?? '');
  } catch {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('mxc-node proxy: expected an absolute URI (is the client configured to use this proxy?)');
    return;
  }
  if (url.protocol !== 'http:') {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(`mxc-node proxy: unsupported scheme "${url.protocol}" (HTTPS must go through CONNECT)`);
    return;
  }
  if (!allowedHost(policy, url.host)) {
    denyResponse(res, url.host);
    return;
  }
  const headers: http.OutgoingHttpHeaders = { ...req.headers, host: url.host };
  delete headers['proxy-connection'];
  const upstream = http.request(url, { method: req.method, headers, agent: forwardAgent }, (up) => {
    res.writeHead(up.statusCode ?? 502, up.headers);
    up.pipe(res);
  });
  upstream.setTimeout(responseHeaderTimeoutMs, () => {
    upstream.destroy(new Error(`response header timeout after ${responseHeaderTimeoutMs}ms`));
  });
  upstream.on('error', (err) => {
    if (res.headersSent) {
      res.destroy();
      return;
    }
    res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(`mxc-node proxy: upstream ${url.host}: ${err.message}`);
  });
  req.pipe(upstream);
}

function handleConnect(req: http.IncomingMessage, client: Duplex, head: Buffer, policy: ProxyPolicy): void {
  const hostPort = req.url ?? '';
  if (!allowedHost(policy, hostPort)) {
    denyConnect(client, splitHostPort(hostPort).host);
    return;
  }
  const { host, port } = splitHostPort(hostPort);
  const upstream = net.connect({ host, port });
  let established = false;
  upstream.setTimeout(dialTimeoutMs, () => {
    upstream.destroy(new Error(`dial ${hostPort}: timed out after ${dialTimeoutMs}ms`));
  });
  upstream.on('connect', () => {
    established = true;
    client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head.length > 0) upstream.write(head);
    upstream.pipe(client);
    client.pipe(upstream);
  });
  upstream.on('error', (err) => {
    if (!established) {
      const body = `mxc-node proxy: dial ${hostPort}: ${err.message}`;
      client.end(
        'HTTP/1.1 502 Bad Gateway\r\n' +
        'Content-Type: text/plain; charset=utf-8\r\n' +
        `Content-Length: ${Buffer.byteLength(body)}\r\n` +
        'Connection: close\r\n\r\n' +
        body,
      );
    } else {
      client.destroy();
    }
  });
  client.on('error', () => upstream.destroy());
}

export class FilteringProxy {
  private readonly server: http.Server;
  private readonly sockets: Set<net.Socket>;
  readonly port: number;

  private constructor(server: http.Server, sockets: Set<net.Socket>, port: number) {
    this.server = server;
    this.sockets = sockets;
    this.port = port;
  }

  static async start(policy: ProxyPolicy): Promise<FilteringProxy> {
    const server = http.createServer((req, res) => handleForward(req, res, policy));
    const sockets = new Set<net.Socket>();
    server.on('connection', (socket) => {
      sockets.add(socket);
      socket.on('close', () => sockets.delete(socket));
    });
    server.on('connect', (req, client, head) => handleConnect(req, client, head, policy));
    server.headersTimeout = 30_000;
    server.requestTimeout = 0; // long-lived forwarded streams must not be cut off
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve());
    });
    const address = server.address();
    if (address === null || typeof address === 'string') {
      throw new Error('failed to determine the proxy port');
    }
    return new FilteringProxy(server, sockets, address.port);
  }

  // Points HTTP clients at the proxy. Loopback stays direct via NO_PROXY so
  // the agent can still reach loopback services without a pointless detour.
  envVars(): Record<string, string> {
    const u = `http://127.0.0.1:${this.port}`;
    const no = 'localhost,127.0.0.1,::1';
    return {
      HTTP_PROXY: u, http_proxy: u,
      HTTPS_PROXY: u, https_proxy: u,
      NO_PROXY: no, no_proxy: no,
    };
  }

  // Closes the listener and destroys any open tunnels, mirroring Go's
  // http.Server.Close, which closes active connections too.
  async close(): Promise<void> {
    for (const socket of this.sockets) socket.destroy();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }
}
