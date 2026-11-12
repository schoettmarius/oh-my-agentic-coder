// Command minimal-omac's Node sibling: it runs a command inside an
// MXC-contained sandbox (bubblewrap on Linux, Seatbelt on macOS,
// ProcessContainer on Windows), mediating HTTP(S) network access through a
// local filtering proxy. The recreated mechanisms and the deliberate
// omissions are documented in README.md.
import process from 'node:process';
import { MxcError, runSandboxed } from './run.ts';

const prog = 'mxc-node';

function usage(w: NodeJS.WriteStream): void {
  w.write(`usage: ${prog} run --profile PATH -- command [args...]

Run COMMAND inside an MXC sandbox, configured entirely by a JSON
profile (format in README.md).

  --profile PATH         load a JSON sandbox profile (required)

Examples:
  ${prog} run --profile profile.json -- bash
`);
}

async function main(argv: string[]): Promise<number> {
  if (argv.length === 0) {
    usage(process.stderr);
    return 2;
  }
  switch (argv[0]) {
    case 'run':
      return cmdRun(argv.slice(1));
    default:
      usage(process.stderr);
      return 2;
  }
}

async function cmdRun(args: string[]): Promise<number> {
  let profilePath = '';
  const command: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? '';
    if (arg === '--') {
      command.push(...args.slice(i + 1));
      break;
    }
    if (arg === '--profile') {
      const value = args[++i];
      if (value === undefined) {
        process.stderr.write(`${prog}: --profile needs an argument\n`);
        return 2;
      }
      profilePath = value;
    } else if (arg.startsWith('--profile=')) {
      profilePath = arg.slice('--profile='.length);
    } else if (arg.startsWith('--')) {
      process.stderr.write(`${prog}: unknown flag: ${arg}\n`);
      usage(process.stderr);
      return 2;
    } else {
      command.push(...args.slice(i));
      break;
    }
  }
  if (profilePath === '') {
    process.stderr.write(
      `${prog}: --profile is required (see: ${prog} run --profile profile.json -- <command>)\n`,
    );
    return 2;
  }
  if (command.length === 0) {
    process.stderr.write(
      `${prog}: no command after the flags (see: ${prog} run --profile profile.json -- <command>)\n`,
    );
    return 2;
  }
  try {
    return await runSandboxed(profilePath, command);
  } catch (err) {
    if (err instanceof MxcError) {
      process.stderr.write(`${prog}: MXC error [${err.code}]: ${err.message}\n`);
      if (err.remediation !== undefined) {
        process.stderr.write(`${prog}: ${err.remediation}\n`);
      }
    } else {
      process.stderr.write(`${prog}: ${err instanceof Error ? err.message : String(err)}\n`);
    }
    return 1;
  }
}

try {
  process.exitCode = await main(process.argv.slice(2));
} catch (err) {
  process.stderr.write(`${prog}: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
}
