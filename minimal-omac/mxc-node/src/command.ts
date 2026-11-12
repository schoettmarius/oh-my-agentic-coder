// MXC's ContainerRequest carries the workload command as a single string
// that the backend splits again, so the argument vector must be quoted in
// the platform's native convention.

export function commandLine(args: string[], platform: NodeJS.Platform = process.platform): string {
  const quote = platform === 'win32' ? quoteWindows : quotePosix;
  return args.map(quote).join(' ');
}

function quotePosix(arg: string): string {
  return `'${arg.replaceAll("'", "'\\''")}'`;
}

// The standard Windows argv convention: double quotes, backslashes doubled
// before a quote or at the end of the argument.
function quoteWindows(arg: string): string {
  if (arg.length === 0) return '""';
  if (!/[\s"]/.test(arg)) return arg;
  let out = '"';
  let backslashes = 0;
  for (const ch of arg) {
    if (ch === '"') {
      out += '\\'.repeat(backslashes * 2 + 1) + '"';
      backslashes = 0;
    } else if (ch === '\\') {
      backslashes++;
    } else {
      out += '\\'.repeat(backslashes) + ch;
      backslashes = 0;
    }
  }
  out += '\\'.repeat(backslashes * 2) + '"';
  return out;
}
