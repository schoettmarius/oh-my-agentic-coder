// Command minimal-omac is a minimal, from-scratch recreation of the Linux
// sandbox of omac (oh-my-agentic-coder): it runs a command inside a
// bubblewrap mount/PID/IPC/UTS namespace, applies Landlock TCP rules and a
// seccomp socket allowlist inside it, and can mediate network access
// through a local filtering proxy.
//
// Linux only. The recreated mechanisms and the deliberate omissions are
// documented in README.md.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr, "minimal-omac")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		os.Exit(cmdRun(os.Args[2:]))
	case "stage2":
		if err := RunStage2(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "minimal-omac stage2: %v\n", err)
			os.Exit(1)
		}
		// RunStage2 execs on success and never returns.
	default:
		usage(os.Stderr, "minimal-omac")
		os.Exit(2)
	}
}

func usage(w *os.File, prog string) {
	fmt.Fprintf(w, `usage: %[1]s run [flags] -- command [args...]

Run COMMAND inside a bubblewrap + Landlock sandbox.

  --profile PATH         load a JSON sandbox profile (see README.md);
                         the flags below extend or override it
  --read PATH            grant PATH read-only (repeatable)
  --write PATH           grant PATH read+write (repeatable)
  --deny PATH            protect PATH: mask it with a denial marker even
                         under broader grants (repeatable; adds to the
                         built-in protected set)
  --no-default-deny      drop the built-in protected set (~/.ssh, ~/.gnupg,
                         shell configs, ...)
  --workdir DIR          working directory, granted read+write (default: cwd)
  --network MODE         open | blocked | filtered (default: filtered)
  --allow-domain DOMAIN  filtered mode: allow HTTP(S) to DOMAIN and its
                         subdomains through the proxy (repeatable)
  --deny-domain DOMAIN   filtered mode: always block DOMAIN, even if
                         allowed (repeatable)
  --open-port N          allow the sandbox to bind and connect to TCP
                         port N (repeatable)
  --allow-env VAR        pass environment variable VAR into the sandbox
                         (repeatable; adds to the built-in allowlist)
  --deny-env VAR         strip VAR even if otherwise allowed (repeatable)

Examples:
  %[1]s run -- bash
  %[1]s run --network blocked -- go test ./...
  %[1]s run --network filtered --allow-domain github.com -- git fetch
`, prog)
}

// strList and intList are repeatable flag values.
type strList []string

func (l *strList) String() string     { return strings.Join(*l, ",") }
func (l *strList) Set(v string) error { *l = append(*l, v); return nil }

type intList []int

func (l *intList) String() string {
	parts := make([]string, len(*l))
	for i, n := range *l {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ",")
}

func (l *intList) Set(v string) error {
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port %q (want 1..65535)", v)
	}
	*l = append(*l, n)
	return nil
}

// runFlags mirrors every run flag; MergeConfig combines it with a profile.
type runFlags struct {
	profile       string
	reads         strList
	writes        strList
	denies        strList
	noDefaultDeny bool
	workdir       string
	network       string
	allowDomains  strList
	denyDomains   strList
	openPorts     intList
	allowEnv      strList
	denyEnv       strList
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	f := runFlags{}
	fs.StringVar(&f.profile, "profile", "", "JSON sandbox profile")
	fs.Var(&f.reads, "read", "grant read-only path (repeatable)")
	fs.Var(&f.writes, "write", "grant read+write path (repeatable)")
	fs.Var(&f.denies, "deny", "protect path with a denial marker (repeatable)")
	fs.BoolVar(&f.noDefaultDeny, "no-default-deny", false, "drop the built-in protected set")
	fs.StringVar(&f.workdir, "workdir", "", "working directory (default: cwd)")
	fs.StringVar(&f.network, "network", "", "open | blocked | filtered")
	fs.Var(&f.allowDomains, "allow-domain", "filtered mode: allow HTTP(S) to domain (repeatable)")
	fs.Var(&f.denyDomains, "deny-domain", "filtered mode: always block domain (repeatable)")
	fs.Var(&f.openPorts, "open-port", "allow bind+connect on TCP port (repeatable)")
	fs.Var(&f.allowEnv, "allow-env", "pass environment variable into the sandbox (repeatable)")
	fs.Var(&f.denyEnv, "deny-env", "strip environment variable even if allowed (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	inner := fs.Args()
	if len(inner) == 0 {
		fmt.Fprintln(os.Stderr, "minimal-omac: no command after the flags (see: minimal-omac run -- <command>)")
		return 2
	}

	fail := func(format string, args ...any) int {
		fmt.Fprintf(os.Stderr, "minimal-omac: "+format+"\n", args...)
		return 1
	}

	profile, err := LoadProfile(f.profile)
	if err != nil {
		return fail("%v", err)
	}
	cfg := MergeConfig(profile, f)

	grants, warnings, err := ResolveGrants(cfg)
	if err != nil {
		return fail("%v", err)
	}
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "minimal-omac: warning: %s\n", w)
	}

	// Filtered mode runs a local proxy and points the sandbox at it via
	// HTTP(S)_PROXY; Landlock then only ever grants the proxy port.
	injected := map[string]string{}
	var proxy *Proxy
	if grants.NetworkMode == ModeFiltered {
		proxy, err = StartProxy(ProxyPolicy{Allow: grants.AllowDomains, Deny: grants.DenyDomains})
		if err != nil {
			return fail("start filtering proxy: %v", err)
		}
		defer proxy.Close()
		grants.ProxyPort = proxy.Port()
		for k, v := range proxy.EnvVars() {
			injected[k] = v
		}
	}

	// Denial markers must outlive the bwrap launch: cleanup only after the
	// child has exited (this function returns after runChild waits).
	markerCleanup, err := grants.prepareMarkers()
	if err != nil {
		return fail("prepare denial markers: %v", err)
	}
	defer markerCleanup()

	childArgv, err := BuildChildArgv(grants, inner)
	if err != nil {
		return fail("%v", err)
	}

	env := FilterEnv(os.Environ(), cfg.AllowEnv, cfg.DenyEnv, injected)
	code, err := runChild(childArgv, env)
	if err != nil {
		return fail("%v", err)
	}
	return code
}

// runChild starts the bwrap child with the filtered environment, relays
// termination signals to it, waits for it, and returns its exit code.
func runChild(argv, env []string) (int, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start sandbox: %w", err)
	}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sigs:
				_ = cmd.Process.Signal(s)
			case <-done:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal()), nil
		}
		return exitErr.ExitCode(), nil
	}
	return 0, fmt.Errorf("wait for sandbox child: %w", err)
}
