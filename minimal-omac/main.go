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
	fmt.Fprintf(w, `usage: %[1]s run --profile PATH -- command [args...]

Run COMMAND inside a bubblewrap + Landlock sandbox, configured
entirely by a JSON profile (format in README.md).

  --profile PATH         load a JSON sandbox profile (required)

Examples:
  %[1]s run --profile profile.json -- bash
`, prog)
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	profilePath := ""
	fs.StringVar(&profilePath, "profile", "", "JSON sandbox profile (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	inner := fs.Args()
	if profilePath == "" {
		fmt.Fprintln(os.Stderr, "minimal-omac: --profile is required (see: minimal-omac run --profile profile.json -- <command>)")
		return 2
	}
	if len(inner) == 0 {
		fmt.Fprintln(os.Stderr, "minimal-omac: no command after the flags (see: minimal-omac run --profile profile.json -- <command>)")
		return 2
	}

	fail := func(format string, args ...any) int {
		fmt.Fprintf(os.Stderr, "minimal-omac: "+format+"\n", args...)
		return 1
	}

	profile, err := LoadProfile(profilePath)
	if err != nil {
		return fail("%v", err)
	}
	cfg := ConfigFromProfile(profile)

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
