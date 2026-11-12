// Profile loading and validation. The JSON profile format is identical to
// the one consumed by the Go implementation in the parent directory
// (see its README.md): absent fields default to empty lists.
import { readFile } from 'node:fs/promises';

export interface FilesystemProfile {
  read: string[];
  write: string[];
  deny: string[];
}

export interface NetworkProfile {
  allow_domain: string[];
  deny_domain: string[];
  open_ports: number[];
}

export interface EnvironmentProfile {
  allow_vars: string[];
  deny_vars: string[];
}

export interface Profile {
  filesystem: FilesystemProfile;
  network: NetworkProfile;
  environment: EnvironmentProfile;
}

function stringArray(value: unknown, field: string, pathname: string): string[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.some((e) => typeof e !== 'string')) {
    throw new Error(`profile ${pathname}: ${field} must be an array of strings`);
  }
  return [...value];
}

function portArray(value: unknown, field: string, pathname: string): number[] {
  if (value === undefined || value === null) return [];
  if (
    !Array.isArray(value) ||
    value.some((e) => !Number.isInteger(e) || e < 1 || e > 65535)
  ) {
    throw new Error(`profile ${pathname}: ${field} must be an array of TCP ports (integers 1-65535)`);
  }
  return [...value];
}

export async function loadProfile(pathname: string): Promise<Profile> {
  let data: string;
  try {
    data = await readFile(pathname, 'utf8');
  } catch (err) {
    throw new Error(`read profile ${pathname}: ${errorMessage(err)}`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(data);
  } catch (err) {
    throw new Error(`parse profile ${pathname}: ${errorMessage(err)}`);
  }
  if (raw === null || raw === undefined) {
    raw = {};
  }
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error(`profile ${pathname}: top level must be a JSON object`);
  }
  const obj = raw as Record<string, unknown>;
  const fs = section(obj.filesystem);
  const net = section(obj.network);
  const env = section(obj.environment);
  return {
    filesystem: {
      read: stringArray(fs.read, 'filesystem.read', pathname),
      write: stringArray(fs.write, 'filesystem.write', pathname),
      deny: stringArray(fs.deny, 'filesystem.deny', pathname),
    },
    network: {
      allow_domain: stringArray(net.allow_domain, 'network.allow_domain', pathname),
      deny_domain: stringArray(net.deny_domain, 'network.deny_domain', pathname),
      open_ports: portArray(net.open_ports, 'network.open_ports', pathname),
    },
    environment: {
      allow_vars: stringArray(env.allow_vars, 'environment.allow_vars', pathname),
      deny_vars: stringArray(env.deny_vars, 'environment.deny_vars', pathname),
    },
  };
}

function section(value: unknown): Record<string, unknown> {
  if (value === undefined || value === null) return {};
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('profile sections must be JSON objects');
  }
  return value as Record<string, unknown>;
}

export function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
