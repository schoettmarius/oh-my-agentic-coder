# minimal-omac

A minimal, from-scratch recreation of the Linux sandbox of
[omac (oh-my-agentic-coder)](https://github.com/TNG/oh-my-agentic-coder):
it runs a command inside a kernel-enforced sandbox — bubblewrap for
filesystem/process isolation, Landlock for TCP rules, seccomp to close
the non-TCP bypass — with a small filtering proxy mediating internet
access. Linux only.

## Setup (Debian / Ubuntu)

```bash
./setup-linux.sh
```

Installs the apt dependencies (bubblewrap plus the omac-quick-start
extras).

## Usage

```bash
./minimal-omac run --profile profile.json -- command [args...]

# interactive shell in the sandbox (profile below: network filtered)
./minimal-omac run --profile profile.json -- bash

# no network at all, enforced by the kernel ("mode": "blocked")
./minimal-omac run --profile blocked.json -- go test ./...
```

`--profile` is the only flag and is required: all configuration lives in
the JSON profile (see below). Run `./minimal-omac` with no arguments for
the short usage text.

## How it works

1. **bubblewrap** builds the sandbox: new mount/PID/IPC/UTS namespaces,
   only granted paths are mounted (read-only or read-write), a fresh
   `/proc`, `/dev`, and private tmpfs `/tmp`. bwrap's `--new-session`
   blocks TIOCSTI keystroke injection into the host terminal.
2. Inside the namespace, bwrap execs `minimal-omac stage2`, which applies
   **Landlock TCP rules** (connect/bind allowlist, irreversible via
   `NO_NEW_PRIVS` + `LANDLOCK_RESTRICT_SELF`, needs kernel 6.7+) and a
   **seccomp-BPF allowlist** over `socket(2)` — AF_UNIX and TCP only —
   so UDP, ICMP, and raw sockets cannot bypass the TCP filter.
3. In `--network filtered` mode (profile: `"mode": "filtered"`) a local
   HTTP proxy runs on loopback;
   Landlock grants only the proxy port, and `HTTP(S)_PROXY` points the
   agent at it. Hosts must be on the allow list
   (`network.allow_domain`); deny entries win; loopback is always
   allowed; everything else gets 403. DNS for allowed hosts happens
   host-side, so the sandbox needs no UDP.
4. **Protected paths** (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`,
   `~/.docker`, `~/.config/gcloud`, and the shell startup files) are
   masked with inert denial-marker files even when the whole home
   directory is granted, so the agent sees *why* a path is hidden
   instead of a bare error. `filesystem.deny` adds paths,
   `filesystem.no_default_deny` drops the built-in set.
5. The child's **environment is allowlisted**: only `HOME`, `PATH`,
   `TERM`, `LC_*`, and a few operational defaults pass through;
   ambient proxy variables are always stripped. Extend with
   `environment.allow_vars`.

## JSON profile

`--profile file.json` is required and holds the entire configuration:

```json
{
  "workdir": "~/project",
  "filesystem": { "read": ["~/go"], "write": [], "deny": [] },
  "network": {
    "mode": "filtered",
    "allow_domain": ["github.com"],
    "deny_domain": [],
    "open_ports": []
  },
  "environment": { "allow_vars": ["EDITOR"], "deny_vars": [] }
}
```

Defaults for absent fields: `workdir` is the current directory,
`network.mode` is `filtered`, and `filesystem.no_default_deny` is
`false` (the built-in protected set stays on).

## Deliberately NOT recreated from omac

Keychain/Secret Service integration, skills and sidecars, the REST
facade, harness detection, interactive network-approval dialogs
(filtered mode uses a static allow list instead), learned page policy,
audit logging, learn mode, intent registry, tool-cache redirects,
macOS (Seatbelt) support, and the TUI/PTY terminal relay (signals are
forwarded directly instead, which can behave imperfectly with
full-screen TUI programs).

## Known limitations

- Landlock net-port rules grant a port on **every** host address, not
  just loopback (a kernel rule-engine limitation; omac records the
  same accepted gap).
- Non-HTTP(S) egress is not mediated: `network.open_ports` grants raw
  TCP on that port to any address.
- A denial marker replaces the whole protected file, so a program
  reading one gets the marker text, not a permission error.

## License

Apache-2.0 (see [LICENSE](./LICENSE)). This is a derived recreation of
omac's sandbox design; see [NOTICE](./NOTICE) for attribution.
