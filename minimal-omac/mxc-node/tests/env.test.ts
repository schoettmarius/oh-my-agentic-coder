import test from 'node:test';
import assert from 'node:assert/strict';
import { defaultAllowEnv, envVarAllowed, filterEnv } from '../src/env.ts';

test('envVarAllowed matches exact names and trailing-* globs', () => {
  assert.ok(envVarAllowed('HOME', ['HOME']));
  assert.ok(envVarAllowed('LC_ALL', ['LC_*']));
  assert.ok(envVarAllowed('LC_CTYPE', ['LC_*']));
  assert.ok(!envVarAllowed('XLC_ALL', ['LC_*']));
  assert.ok(!envVarAllowed('HOSTNAME_EXTRA', ['HOSTNAME']));
  assert.ok(!envVarAllowed('HTTP', ['HTTP_*']));
});

test('envVarAllowed is case-insensitive when asked (Windows)', () => {
  assert.ok(envVarAllowed('SystemRoot', ['SYSTEMROOT'], true));
  assert.ok(!envVarAllowed('SystemRoot', ['SYSTEMROOT']));
});

test('defaultAllowEnv extends the Windows set on win32 only', () => {
  const linux = defaultAllowEnv('linux');
  assert.ok(linux.includes('HOME'));
  assert.ok(!linux.includes('SYSTEMROOT'));
  const win = defaultAllowEnv('win32');
  assert.ok(win.includes('SYSTEMROOT'));
  assert.ok(win.includes('PATH'));
});

test('filterEnv keeps only allowed vars, strips proxies, overlays injections', () => {
  const env = {
    HOME: '/home/u',
    PATH: '/usr/bin',
    TERM: 'xterm',
    LC_CTYPE: 'UTF-8',
    GITHUB_TOKEN: 'secret',
    HTTP_PROXY: 'http://evil:1',
    no_proxy: 'evil',
    EDITOR: 'vim',
    HOSTNAME: 'h',
  };
  const out = filterEnv(env, ['EDITOR'], ['HOSTNAME'], { HTTPS_PROXY: 'http://127.0.0.1:2' }, 'linux');
  assert.equal(out.HOME, '/home/u');
  assert.equal(out.LC_CTYPE, 'UTF-8');
  assert.equal(out.EDITOR, 'vim');
  assert.equal(out.HTTPS_PROXY, 'http://127.0.0.1:2');
  assert.equal(out.GITHUB_TOKEN, undefined);
  assert.equal(out.HTTP_PROXY, undefined);
  assert.equal(out.no_proxy, undefined);
  assert.equal(out.HOSTNAME, undefined);
});

test('filterEnv deny wins over the default allowlist', () => {
  const out = filterEnv({ HOME: '/home/u' }, [], ['HOME'], {}, 'linux');
  assert.equal(out.HOME, undefined);
});

test('filterEnv on Windows matches names case-insensitively', () => {
  const out = filterEnv(
    { SystemRoot: 'C:\\Windows', ShAdOw: 'x', SeCrEtS: 'y' },
    ['shadow'],
    ['secrets'],
    {},
    'win32',
  );
  assert.equal(out.SystemRoot, 'C:\\Windows');
  assert.equal(out.ShAdOw, 'x'); // allowed case-insensitively
  assert.equal(out.SeCrEtS, undefined); // denied case-insensitively
});
