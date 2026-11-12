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
extras, and `golang-go` if you have no Go toolchain), verifies bwrap
can create user namespaces (granting an AppArmor exception on
Ubuntu 23.10+ if needed), checks the kernel for Landlock (6.7+), and
builds `./minimal-omac`.

## Usage

```bash
./minimal-omac run [flags] -- command [args...]

# interactive shell in the sandbox (network filtered by default)
./minimal-omac run -- bash

# no network at all, enforced by the kernel
./minimal-omac run --network blocked -- go test ./...

# filtered internet: only github.com (and subdomains) reachable
./minimal-omac run --network filtered --allow-domain github.com -- git fetch

# extra access grants
./minimal-omac run --read ~/go --write /data --open-port 8080 -- ./my-server
```

Run `./minimal-omac` with no arguments for the full flag list.

## How it works

1. **bubblewrap** builds the sandbox: new mount/PID/IPC/UTS namespaces,
   only granted paths are mounted (read-only or read-write), a fresh
   `/proc`, `/dev`, and private tmpfs `/tmp`. `--new-session` blocks
   TIOCSTI keystroke injection into the host terminal.
2. Inside the namespace, bwrap execs `minimal-omac stage2`, which applies
   **Landlock TCP rules** (connect/bind allowlist, irreversible via
   `NO_NEW_PRIVS` + `LANDLOCK_RESTRICT_SELF`, needs kernel 6.7+) and a
   **seccomp-BPF allowlist** over `socket(2)` — AF_UNIX and TCP only —
   so UDP, ICMP, and raw sockets cannot bypass the TCP filter.
3. In `--network filtered` mode a local HTTP proxy runs on loopback;
   Landlock grants only the proxy port, and `HTTP(S)_PROXY` points the
   agent at it. Hosts must be on the allow list (`--allow-domain`);
   deny entries win; loopback is always allowed; everything else gets
   403. DNS for allowed hosts happens host-side, so the sandbox needs
   no UDP.
4. **Protected paths** (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`,
   `~/.docker`, `~/.config/gcloud`, and the shell startup files) are
   masked with inert denial-marker files even when the whole home
   directory is granted, so the agent sees *why* a path is hidden
   instead of a bare error. `--deny` adds paths, `--no-default-deny`
   drops the built-in set.
5. The child's **environment is allowlisted**: only `HOME`, `PATH`,
   `TERM`, `LC_*`, and a few operational defaults pass through;
   ambient proxy variables are always stripped. Extend with
   `--allow-env`.

## JSON profile

`--profile file.json` persists a configuration; flags extend it:

```json
{
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
- Non-HTTP(S) egress is not mediated: `--open-port` grants raw TCP on
  that port to any address.
- A denial marker replaces the whole protected file, so a program
  reading one gets the marker text, not a permission error.

## License

Apache-2.0 (see [LICENSE](./LICENSE)). This is a derived recreation of
omac's sandbox design; see [NOTICE](./NOTICE) for attribution.
