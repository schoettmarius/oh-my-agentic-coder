// Orchestration: load the profile, resolve grants, start the filtering
// proxy, translate everything into an MXC ContainerRequest, and relay the
// workload's standard I/O until it exits.
import os from 'node:os';
import {
  MxcError,
  getPlatformSupport,
  spawn,
  type ContainerRequest,
  type NetworkRuleConfig,
} from '@microsoft/mxc-sdk/v1';
import { commandLine } from './command.ts';
import { filterEnv } from './env.ts';
import { resolveGrants } from './grants.ts';
import { loadProfile } from './profile.ts';
import { nodePreflightError } from './preflight.ts';
import { FilteringProxy } from './proxy.ts';

function warn(message: string): void {
  process.stderr.write(`mxc-node: warning: ${message}\n`);
}

export async function runSandboxed(profilePath: string, command: string[]): Promise<number> {
  const nodeError = nodePreflightError(process.platform, process.versions.node);
  if (nodeError !== null) throw new Error(nodeError);

  const profile = await loadProfile(profilePath);
  const { grants, warnings } = await resolveGrants(profile, {
    home: os.homedir(),
    cwd: process.cwd(),
    platform: process.platform,
  });
  for (const w of warnings) warn(w);

  const support = getPlatformSupport();
  if (!support.isSupported) {
    throw new Error(`MXC reports this host as unsupported: ${support.reason ?? 'unknown reason'}`);
  }
  for (const [backend, reason] of Object.entries(support.unavailableReasons ?? {})) {
    warn(`MXC backend ${backend} unavailable: ${reason}`);
  }
  if (
    process.platform === 'linux' &&
    support.bubblewrapNetwork?.proxyEnforcement === 'unsupported'
  ) {
    warn(
      'this host cannot kernel-enforce proxy-only egress for bubblewrap ' +
      `(${support.bubblewrapNetwork.warnings.join('; ')}); ` +
      'HTTP(S) is still filtered through the proxy, but raw sockets are not blocked',
    );
  }

  // The local proxy mediates HTTP(S) and points the sandbox at it via
  // HTTP(S)_PROXY; MXC additionally gets the proxy as runtime config so it
  // can enforce proxy-only egress where the backend supports it.
  const proxy = await FilteringProxy.start({
    allow: grants.allowDomains,
    deny: grants.denyDomains,
  });
  try {
    const environment = filterEnv(
      process.env,
      profile.environment.allow_vars,
      profile.environment.deny_vars,
      proxy.envVars(),
      process.platform,
    );

    const allow: NetworkRuleConfig[] = [
      { to: [{ cidr: '127.0.0.0/8' }, { cidr: '::1/128' }] },
      ...grants.openPorts.map((port) => ({
        to: [{ cidr: '0.0.0.0/0' }, { cidr: '::/0' }],
        ports: [{ protocol: 'tcp' as const, port }],
      })),
    ];
    // MXC's ingress policy cannot be limited to specific ports, so open_ports
    // degrades to "all listening allowed" (a superset of the Go original's
    // per-port bind grants); without open_ports nothing may listen.
    if (grants.openPorts.length > 0) {
      warn('MXC cannot restrict listening to specific ports; ingress is fully allowed because open_ports is set');
    }

    const request: ContainerRequest = {
      command: commandLine(command, process.platform),
      // 'process' is the portable containment choice the official MXC
      // samples use; MXC maps it to the platform default backend
      // (bubblewrap on Linux, Seatbelt on macOS, ProcessContainer on Windows).
      containment: { type: 'process' },
      workingDirectory: grants.workdir,
      filesystem: {
        readonlyPaths: grants.readPaths,
        readwritePaths: grants.writePaths,
        deniedPaths: grants.protectedPaths,
      },
      network: {
        egress: { default: 'deny', allow },
        ingress: {
          default: grants.openPorts.length > 0 ? 'allow' : 'deny',
          // The sandboxed workload must be able to reach the host-side proxy.
          hostLoopback: 'allow',
        },
        runtimeConfig: { networkProxy: `http://127.0.0.1:${proxy.port}` },
      },
      environment,
      inheritDefaultEnvironment: false,
    };

    const child = await spawn(request);
    for (const w of child.warnings) warn(w);

    // The MXC API exposes only kill(), not per-signal delivery: relaying
    // SIGINT/SIGTERM terminates the workload instead of merely signaling it.
    const forward = () => child.kill();
    process.once('SIGINT', forward);
    process.once('SIGTERM', forward);
    if (process.platform !== 'win32') process.once('SIGHUP', forward);

    child.standardOutput?.pipe(process.stdout);
    child.standardError?.pipe(process.stderr);
    if (child.standardInput !== null) process.stdin.pipe(child.standardInput);

    const result = await child.wait();
    return result.exitCode;
  } finally {
    await proxy.close();
  }
}

export { MxcError };
