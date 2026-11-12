# mxc-node

A minimal, cross-platform (Linux, macOS, Windows) recreation of the sandbox
of [omac (oh-my-agentic-coder)](https://github.com/TNG/oh-my-agentic-coder)
— the Node sibling of the Linux-only Go implementation in the parent
directory. Instead of driving bubblewrap, Landlock, and seccomp directly,
it delegates containment to
[MXC (Microsoft eXecution Container)](https://github.com/microsoft/mxc):
policy-driven isolation that picks the platform-appropriate backend —
bubblewrap on Linux, Seatbelt on macOS, ProcessContainer on Windows — and
mediates HTTP(S) network access through a local filtering proxy, just like
the Go version.

## Requirements

- **Node.js**: the MXC SDK's native stdio gate requires a **stable**
  (non-prerelease) Node — on Linux/macOS Node.js >= 24.0.0, on Windows
  24.21.0+ within 24 or >= 26.8.0. Alpha/beta builds (e.g.
  `27.0.0-alpha...`) are rejected by the SDK's semver check. Node 24+
  also runs the TypeScript sources directly, so there is no build step.
  The SDK's native runtime is bundled with the npm package — no Rust
  toolchain needed.
- Platform backend prerequisites from the
  [MXC docs](https://github.com/microsoft/mxc/blob/main/docs/backends/):
  - Linux: `bubblewrap` installed (on Debian/Ubuntu: the parent
    directory's `setup-linux.sh` covers it). For kernel-enforced
    proxy-only egress also install `slirp4netns` — MXC needs it for the
    bubblewrap `runtimeConfig.networkProxy`; without it mxc-node prints a
    warning and relies on the proxy environment variables alone.
  - macOS: Seatbelt (built into the OS)
  - Windows: Windows 11 with the ProcessContainer prerequisites described
    by MXC

```bash
npm install
```

## Usage

```bash
node src/cli.ts run --profile profile.json -- command [args...]

# interactive shell in the sandbox (profile below: network filtered)
node src/cli.ts run --profile profile.json -- bash
```

`--profile` is the only flag and is required: all configuration lives in
the JSON profile (see below). Run with no arguments for the short usage
text. The command always runs in the current working directory, granted
read+write.

## How it works

1. **MXC containment** — the workload runs through a `ContainerRequest`
   with the portable `process` containment choice (the one the official
   MXC samples use); MXC validates the request and launches it with the
   platform default backend.
2. **Filesystem policy** — profile `filesystem.read/write/deny` map to
   MXC `readonlyPaths`, `readwritePaths`, and `deniedPaths`. The working
   directory and the home directory are always granted read+write; the
   toolchain roots (`/usr`, `/bin`, … on Linux/macOS) are granted
   read-only; non-existent grants are dropped with a warning.
3. **Network** — egress is denied by default; only host loopback (the
   proxy) and `network.open_ports` are allowed out. A local HTTP proxy
   runs host-side; `HTTP(S)_PROXY` points the agent at it and MXC also
   receives the proxy as `runtimeConfig.networkProxy`, so backends that
   support proxy-only egress (see MXC's `proxyEnforcement`) enforce it in
   the kernel. Hosts must be on the allow list
   (`network.allow_domain`); deny entries win; loopback is always
   allowed; everything else gets 403. DNS for allowed hosts happens
   host-side, so the sandbox needs no UDP.
4. **Protected paths** (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`,
   `~/.docker`, `~/.config/gcloud`, and the shell startup files) are
   always on the deny list even when the whole home directory is granted.
   `filesystem.deny` adds paths. Where a backend cannot express denied
   paths, MXC reports a warning.
5. **Environment allowlisting** — the child sees only `HOME`, `PATH`,
   `SHELL`, `TERM`, `LC_*` and a few operational defaults (plus a Windows
   operational set); ambient proxy variables are always stripped and only
   ever set by the proxy injection. Extend with `environment.allow_vars`.

## JSON profile

Identical to the Go implementation — profiles are interchangeable:

```json
{
  "filesystem": { "read": ["~/go"], "write": [], "deny": [] },
  "network": {
    "allow_domain": ["github.com"],
    "deny_domain": [],
    "open_ports": []
  },
  "environment": { "allow_vars": ["EDITOR"], "deny_vars": [] }
}
```

Absent fields default to empty lists.

## Differences from the Go minimal-omac

- **No Landlock/seccomp plumbing** — MXC's backend applies the kernel
  mechanisms; on hosts where bubblewrap proxy-only egress cannot be
  enforced, mxc-node prints a warning and relies on the proxy environment
  variables alone (raw sockets are then not blocked).
- **No denial markers** — the Go version masks protected paths with inert
  marker files so the agent sees *why* a path is hidden; MXC expresses
  this as `deniedPaths` (a bare denial) where the backend supports it.
- **Signal relay** — the MXC API exposes only `kill()`, so SIGINT/SIGTERM
  terminate the workload instead of being delivered as signals.
- **Ingress ports** — MXC cannot limit listening to specific ports, so
  `network.open_ports` degrades to "all listening allowed"; without it
  nothing may listen.
- **Windows** — new territory: env allowlisting adds a Windows operational
  set (`SYSTEMROOT`, `COMSPEC`, …), and granting read access to the
  system directories is left to MXC's ProcessContainer defaults (the
  official samples run `cmd.exe` with user grants only).

## Tests

```bash
npm test        # unit tests for the pure logic: env filter, proxy policy, live proxy, grants, profile
npm run typecheck
```

The two live-proxy tests bind loopback listeners; they skip themselves in
environments that forbid binding (such as inside an outer omac sandbox).
The unit tests do not launch MXC containers; smoke-test the sandbox
itself with:

```bash
node src/cli.ts run --profile profile.json -- sh -c 'echo inside: $(hostname)'
node src/cli.ts run --profile profile.json -- sh -c 'echo x > ~/.ssh/proof'   # must fail
node src/cli.ts run --profile profile.json -- sh -c 'curl -sI https://github.com | head -1'
node src/cli.ts run --profile profile.json -- sh -c 'curl -sI https://example.com | head -1'  # 403
```

## Deliberately NOT recreated from omac

Keychain/Secret Service integration, skills and sidecars, the REST facade,
harness detection, interactive network-approval dialogs (filtered mode uses
a static allow list instead), audit logging, learn mode, intent registry,
tool-cache redirects, and the TUI/PTY terminal relay (standard pipes are
relayed directly instead).

## Known limitations

- Non-HTTP(S) egress is not domain-filtered: `network.open_ports` grants
  raw TCP on that port to any address, and DNS inside the sandbox is
  subject to the backend's own rules (the proxy does host-side DNS only
  for HTTP(S)).
- Clients that ignore `HTTP(S)_PROXY` bypass the domain allow list; the
  kernel-level egress deny (where the backend supports it) is what turns
  that bypass into a connection failure.
- On Windows, loopback reachability of the proxy relies on MXC's
  ProcessContainer proxy-peer support (`networkProxy` runtime config).

## License

Same as the enclosing repository.
