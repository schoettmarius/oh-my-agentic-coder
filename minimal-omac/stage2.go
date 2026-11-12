package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"

	"golang.org/x/sys/unix"
)

// Stage2Args serializes the network rules for the stage2 re-exec:
// repeated --connect-tcp N / --bind-tcp N flags, then --enforce so the
// kernel restricts TCP to the granted ports.
func Stage2Args(g *Grants) []string {
	connect := map[int]bool{}
	bind := map[int]bool{}
	if g.ProxyPort > 0 {
		connect[g.ProxyPort] = true
	}
	for _, p := range g.OpenPorts {
		connect[p] = true
		bind[p] = true
	}
	var args []string
	for _, p := range sortedInts(connect) {
		args = append(args, "--connect-tcp", strconv.Itoa(p))
	}
	for _, p := range sortedInts(bind) {
		args = append(args, "--bind-tcp", strconv.Itoa(p))
	}
	return append(args, "--enforce")
}

func sortedInts(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// RunStage2 is the entry point for the hidden `minimal-omac stage2`
// subcommand, executed by bwrap inside the mount/PID namespaces. It parses
// the serialized network rules, applies the Landlock net ruleset and the
// datagram seccomp filter when --enforce is present, and execs the inner
// command. Returns only on error.
func RunStage2(args []string) error {
	var connect, bind []int
	enforce := false
	var inner []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--connect-tcp", "--bind-tcp":
			if i+1 >= len(args) {
				return fmt.Errorf("stage2: %s requires a value", args[i])
			}
			port, err := strconv.Atoi(args[i+1])
			if err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("stage2: invalid port %q", args[i+1])
			}
			if args[i] == "--connect-tcp" {
				connect = append(connect, port)
			} else {
				bind = append(bind, port)
			}
			i++
		case "--enforce":
			enforce = true
		case "--":
			inner = args[i+1:]
			i = len(args)
		default:
			return fmt.Errorf("stage2: unknown flag %q", args[i])
		}
	}
	if len(inner) == 0 {
		return errors.New("stage2: no inner command after --")
	}
	if enforce {
		if err := ApplyLandlockNet(connect, bind); err != nil {
			return fmt.Errorf("stage2: %w", err)
		}
		// ApplyLandlockNet already set no_new_privs; block datagrams now
		// so UDP/ICMP cannot bypass the Landlock TCP filter.
		if err := applyDatagramSeccomp(); err != nil {
			return fmt.Errorf("stage2: %w", err)
		}
	}
	return ExecInner(inner)
}

// ExecInner replaces the current process with the inner command (stage2
// tail call). Landlock and seccomp restrictions survive execve.
//
// This runs inside the bwrap mount namespace, so a binary that exists on
// the host but whose directory was not bound into the namespace is simply
// absent here. The bare execve error for that case gives the user no idea
// which file or how to fix it, so wrap it.
func ExecInner(argv []string) error {
	requested := argv[0]
	path := requested
	if p, err := exec.LookPath(path); err == nil {
		path = p
	}
	err := unix.Exec(path, argv, os.Environ())
	// unix.Exec only returns on failure.
	if errors.Is(err, unix.ENOENT) || errors.Is(err, exec.ErrNotFound) {
		return fmt.Errorf(
			"cannot run %q inside the sandbox: %q not found in the sandbox filesystem.\n"+
				"This usually means the binary lives in a directory that was not\n"+
				"mounted into the sandbox. Add that directory to filesystem.read\n"+
				"in your profile, e.g.:\n"+
				"    \"filesystem\": { \"read\": [ \"$(dirname \"$(command -v %s)\")\" ] }\n"+
				"underlying error: %w",
			requested, path, requested, err)
	}
	return fmt.Errorf("exec %q (resolved to %q): %w", requested, path, err)
}
