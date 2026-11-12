import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { loadProfile } from '../src/profile.ts';
import { resolveGrants } from '../src/grants.ts';

async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(path.join(tmpdir(), 'mxc-node-test-'));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('loadProfile defaults missing sections and validates types', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'mxc-node-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const minimal = path.join(dir, 'minimal.json');
  await writeFile(minimal, JSON.stringify({ network: { allow_domain: ['github.com'] } }));
  const p1 = await loadProfile(minimal);
  assert.deepEqual(p1.filesystem, { read: [], write: [], deny: [] });
  assert.deepEqual(p1.network, { allow_domain: ['github.com'], deny_domain: [], open_ports: [] });
  assert.deepEqual(p1.environment, { allow_vars: [], deny_vars: [] });

  const bad = path.join(dir, 'bad.json');
  await writeFile(bad, JSON.stringify({ network: { open_ports: ['nope'] } }));
  await assert.rejects(loadProfile(bad), /open_ports must be an array of TCP ports/);

  const invalid = path.join(dir, 'invalid.json');
  await writeFile(invalid, '{oops');
  await assert.rejects(loadProfile(invalid), /parse profile/);

  await assert.rejects(loadProfile(path.join(dir, 'missing.json')), /read profile/);
});

test('resolveGrants: workdir + home always writable, missing grants dropped, ~ expanded', async () => {
  await withTempDir(async (dir) => {
    const home = path.join(dir, 'home');
    const cwd = path.join(dir, 'work');
    const readTarget = path.join(home, 'docs');
    await mkdir(home, { recursive: true });
    await mkdir(cwd, { recursive: true });
    await mkdir(readTarget, { recursive: true });

    const profile = {
      filesystem: {
        read: ['~/docs', path.join(dir, 'does-not-exist')],
        write: [],
        deny: [],
      },
      network: { allow_domain: ['github.com'], deny_domain: [], open_ports: [] },
      environment: { allow_vars: [], deny_vars: [] },
    };
    const { grants, warnings } = await resolveGrants(profile, { home, cwd, platform: 'linux' });
    assert.equal(grants.workdir, cwd);
    assert.ok(grants.writePaths.includes(home));
    assert.ok(grants.writePaths.includes(cwd));
    assert.ok(grants.readPaths.includes(readTarget));
    assert.deepEqual(warnings, [`grant ${path.join(dir, 'does-not-exist')} does not exist on the host; dropped`]);
    // The default protected set is denied even though it does not exist.
    assert.ok(grants.protectedPaths.includes(path.join(home, '.ssh')));
    assert.ok(grants.protectedPaths.includes(path.join(home, '.config', 'gcloud')));
  });
});

test('resolveGrants rejects a non-directory workdir', async () => {
  await withTempDir(async (dir) => {
    const profile = {
      filesystem: { read: [], write: [], deny: [] },
      network: { allow_domain: [], deny_domain: [], open_ports: [] },
      environment: { allow_vars: [], deny_vars: [] },
    };
    await assert.rejects(
      resolveGrants(profile, { home: dir, cwd: path.join(dir, 'missing'), platform: 'linux' }),
      /workdir .* is not an existing directory/,
    );
  });
});

test('baselineReadPaths is platform-specific', async () => {
  const { resolve } = await import('node:path');
  const { baselineReadPaths } = await import('../src/grants.ts');
  assert.ok(baselineReadPaths('linux').includes(resolve('/usr')));
  assert.ok(baselineReadPaths('darwin').includes(resolve('/usr')));
  assert.deepEqual(baselineReadPaths('win32'), []);
});
