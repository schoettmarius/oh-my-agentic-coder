// Environment allowlisting, ported from env.go in the parent directory: the
// child only sees the operational minimum plus explicitly allowed variables;
// ambient proxy variables are always stripped and only ever set by the
// filtered-mode proxy injection.
const baseAllowEnv = [
  'HOME', 'PATH', 'SHELL', 'TERM', 'TMPDIR',
  'LANG', 'LC_*', 'USER', 'LOGNAME', 'HOSTNAME',
  'PWD', 'XDG_RUNTIME_DIR',
];

// Windows operational minimum: cmd.exe and typical toolchains fail without
// these. None of them are secrets.
const windowsAllowEnv = [
  'SYSTEMROOT', 'SYSTEMDRIVE', 'COMSPEC', 'PATHEXT',
  'TEMP', 'TMP', 'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA',
  'PROGRAMFILES', 'COMMONPROGRAMFILES', 'WINDIR',
  'USERNAME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH',
  'OS', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE',
];

// Always stripped from the ambient environment; only the filtered-mode
// proxy injection ever sets them. Ambient proxy variables would otherwise
// route the sandboxed agent's traffic somewhere unexpected.
const proxyEnvNames = new Set([
  'HTTP_PROXY', 'http_proxy',
  'HTTPS_PROXY', 'https_proxy',
  'NO_PROXY', 'no_proxy',
]);

export function defaultAllowEnv(platform: NodeJS.Platform = process.platform): string[] {
  return platform === 'win32' ? [...baseAllowEnv, ...windowsAllowEnv] : [...baseAllowEnv];
}

// Reports whether name matches the list: exact entries, or trailing-* prefix
// globs (e.g. LC_*). Windows environment variable names are case-insensitive.
export function envVarAllowed(
  name: string,
  patterns: string[],
  caseInsensitive = false,
): boolean {
  for (const pattern of patterns) {
    const [n, p] = caseInsensitive
      ? [name.toLowerCase(), pattern.toLowerCase()]
      : [name, pattern];
    if (n === p) return true;
    if (p.endsWith('*') && n.startsWith(p.slice(0, -1))) return true;
  }
  return false;
}

// Builds the child environment: keep only allowed variables, drop denied
// ones, then overlay the injected values (the proxy variables). Deny wins
// over allow, mirroring env.go's FilterEnv.
export function filterEnv(
  env: Record<string, string | undefined>,
  allow: string[],
  deny: string[],
  injected: Record<string, string>,
  platform: NodeJS.Platform = process.platform,
): Record<string, string> {
  const caseInsensitive = platform === 'win32';
  const allowed = [...defaultAllowEnv(platform), ...allow];
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined) continue;
    const isProxyName = caseInsensitive
      ? proxyEnvNames.has(name.toUpperCase())
      : proxyEnvNames.has(name);
    if (isProxyName) continue;
    if (!envVarAllowed(name, allowed, caseInsensitive)) continue;
    if (envVarAllowed(name, deny, caseInsensitive)) continue;
    out[name] = value;
  }
  return { ...out, ...injected };
}
