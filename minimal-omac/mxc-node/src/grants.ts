// Grant resolution, ported from grants.go in the parent directory: absolute,
// existing path grants, the protected set to deny, and the network rules.
import { lstat } from 'node:fs/promises';
import path from 'node:path';
import type { Profile } from './profile.ts';

export interface Grants {
  workdir: string;
  readPaths: string[]; // read-only
  writePaths: string[]; // read+write
  protectedPaths: string[]; // denied; not filtered for existence
  allowDomains: string[];
  denyDomains: string[];
  openPorts: number[];
}

export interface GrantResolution {
  grants: Grants;
  warnings: string[];
}

// Granted read-only so the sandboxed command finds its toolchain and the C
// library. Platform-specific: the Go original is Linux-only.
export function baselineReadPaths(platform: NodeJS.Platform = process.platform): string[] {
  switch (platform) {
    case 'linux':
      return ['/usr', '/bin', '/sbin', '/lib', '/lib64', '/etc'];
    case 'darwin':
      return ['/usr', '/bin', '/sbin', '/etc'];
    default:
      return [];
  }
}

// Protected by default even when the whole home directory is granted:
// credentials and the shell startup files.
export function defaultDenyRelPaths(): string[] {
  return [
    '.ssh', '.gnupg', '.aws', '.kube', '.docker', '.config/gcloud',
    '.bashrc', '.bash_profile', '.profile',
    '.zshenv', '.zshrc', '.zprofile', '.zlogin',
    '.config/fish/config.fish',
  ];
}

// Resolves ~ and makes the path absolute and clean.
export function expandPath(p: string, home: string): string {
  if (p === '~' || p.startsWith('~/')) {
    p = path.join(home, p.slice(1));
  }
  return path.resolve(p);
}

export async function resolveGrants(
  profile: Profile,
  opts: { home: string; cwd: string; platform?: NodeJS.Platform },
): Promise<GrantResolution> {
  const platform = opts.platform ?? process.platform;
  const warnings: string[] = [];

  const workdir = path.resolve(opts.cwd);
  const workdirInfo = await lstat(workdir).catch(() => null);
  if (workdirInfo === null || !workdirInfo.isDirectory()) {
    throw new Error(`workdir ${workdir} is not an existing directory`);
  }

  const readPaths = await filterExisting(
    [...baselineReadPaths(platform), ...profile.filesystem.read].map((p) => expandPath(p, opts.home)),
    warnings,
  );
  const writePaths = await filterExisting(
    [opts.home, workdir, ...profile.filesystem.write].map((p) => expandPath(p, opts.home)),
    warnings,
  );

  // Protected paths are NOT existence-filtered: a missing ~/.ssh today may
  // exist tomorrow, and denying is idempotent either way.
  const protectedPaths: string[] = [];
  const deny = [
    ...defaultDenyRelPaths().map((rel) => path.join(opts.home, rel)),
    ...profile.filesystem.deny,
  ];
  for (const p of deny.map((p) => expandPath(p, opts.home))) {
    if (!protectedPaths.includes(p)) protectedPaths.push(p);
  }

  return {
    grants: {
      workdir,
      readPaths,
      writePaths,
      protectedPaths,
      allowDomains: profile.network.allow_domain,
      denyDomains: profile.network.deny_domain,
      openPorts: profile.network.open_ports,
    },
    warnings,
  };
}

// Drops paths that do not exist on the host with a warning: MXC backends
// abort the whole launch on a missing grant.
async function filterExisting(paths: string[], warnings: string[]): Promise<string[]> {
  const out: string[] = [];
  for (const p of paths) {
    const info = await lstat(p).catch(() => null);
    if (info === null) {
      warnings.push(`grant ${p} does not exist on the host; dropped`);
      continue;
    }
    if (!out.includes(p)) out.push(p);
  }
  return out;
}
