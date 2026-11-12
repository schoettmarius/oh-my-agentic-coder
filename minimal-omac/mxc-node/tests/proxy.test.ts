import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'node:http';
import * as net from 'node:net';
import { FilteringProxy, allowedHost, domainMatches, splitHostPort } from '../src/proxy.ts';

test('domainMatches covers equality, subdomains, and *. entries', () => {
  assert.ok(domainMatches('github.com', 'github.com'));
  assert.ok(domainMatches('api.github.com', 'github.com'));
  assert.ok(!domainMatches('notgithub.com', 'github.com'));
  assert.ok(!domainMatches('github.com.evil.example', 'github.com'));
  assert.ok(domainMatches('a.example', '*.example'));
});

test('splitHostPort handles host, host:port, and IPv6 brackets', () => {
  assert.deepEqual(splitHostPort('example.com'), { host: 'example.com', port: 80 });
  assert.deepEqual(splitHostPort('example.com:8080'), { host: 'example.com', port: 8080 });
  assert.deepEqual(splitHostPort('[::1]:443'), { host: '::1', port: 443 });
});

test('allowedHost: deny wins, loopback always admitted, empty allow blocks the rest', () => {
  const policy = { allow: ['github.com'], deny: [] };
  assert.ok(allowedHost(policy, 'github.com:443'));
  assert.ok(allowedHost(policy, 'api.github.com'));
  assert.ok(allowedHost(policy, 'localhost:3000'));
  assert.ok(allowedHost(policy, '127.0.0.1:8080'));
  assert.ok(!allowedHost(policy, 'example.com'));
  assert.ok(!allowedHost({ allow: [], deny: [] }, 'example.com'));
  assert.ok(!allowedHost({ allow: ['github.com'], deny: ['github.com'] }, 'api.github.com'));
  // A trailing dot (DNS root form) must not bypass the allow list.
  assert.ok(!allowedHost({ allow: [], deny: [] }, 'example.com.'));
});

// Starts a loopback listener; returns null after marking the test skipped
// when the environment forbids binding (e.g. inside an outer sandbox).
async function listenOrSkip(
  t: TestContext,
  server: http.Server | net.Server,
  label: string,
): Promise<net.AddressInfo | null> {
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EACCES') {
      server.close();
      t.skip(`binding loopback listeners is not permitted in this environment (${label})`);
      return null;
    }
    throw err;
  }
  const address = server.address();
  if (address === null || typeof address === 'string') {
    throw new Error('failed to determine the listen port');
  }
  return address;
}

test('proxy forwards allowed plain-HTTP requests and denies others', async (t) => {
  const upstream = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('upstream-ok');
  });
  const upstreamAddress = await listenOrSkip(t, upstream, 'upstream server');
  if (upstreamAddress === null) return;
  t.after(() => upstream.close());
  const upstreamPort = upstreamAddress.port;

  const proxy = await FilteringProxy.start({ allow: ['github.com'], deny: [] });
  t.after(() => proxy.close());

  // Loopback is always allowed, so a forwarded request to the local test
  // server must succeed.
  const ok = await requestThroughProxy(proxy.port, `http://127.0.0.1:${upstreamPort}/`);
  assert.equal(ok.status, 200);
  assert.equal(ok.body, 'upstream-ok');

  const denied = await requestThroughProxy(proxy.port, 'http://example.com/');
  assert.equal(denied.status, 403);
  assert.match(denied.body, /not in the network allow list/);
});

test('proxy tunnels CONNECT to allowed hosts and denies others', async (t) => {
  const upstream = net.createServer((socket) => {
    socket.on('data', (data) => {
      socket.write(`echo:${data.toString()}`);
    });
  });
  const upstreamAddress = await listenOrSkip(t, upstream, 'upstream server');
  if (upstreamAddress === null) return;
  t.after(() => upstream.close());
  const upstreamPort = upstreamAddress.port;

  const proxy = await FilteringProxy.start({ allow: ['github.com'], deny: [] });
  t.after(() => proxy.close());

  const tunnel = await connectThroughProxy(proxy.port, `127.0.0.1:${upstreamPort}`);
  assert.equal(tunnel.status, 200);
  const echoed = await tunnel.roundTrip('hello\n');
  assert.equal(echoed, 'echo:hello\n');

  const denied = await connectThroughProxy(proxy.port, 'example.com:443');
  assert.equal(denied.status, 403);
});

function requestThroughProxy(
  proxyPort: number,
  url: string,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port: proxyPort, path: url, method: 'GET' },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString() }));
      },
    );
    req.on('error', reject);
    req.end();
  });
}

function connectThroughProxy(
  proxyPort: number,
  target: string,
): Promise<{
  status: number;
  roundTrip: (payload: string) => Promise<string>;
}> {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port: proxyPort,
      method: 'CONNECT',
      path: target,
    });
    req.on('connect', (res, socket) => {
      const roundTrip = (payload: string) =>
        new Promise<string>((res2, reject2) => {
          const chunks: Buffer[] = [];
          socket.on('data', (c: Buffer) => chunks.push(c));
          socket.once('data', () => res2(Buffer.concat(chunks).toString()));
          socket.once('error', reject2);
          socket.write(payload);
        });
      resolve({ status: res.statusCode ?? 0, roundTrip });
    });
    req.on('error', reject);
    req.end();
  });
}
