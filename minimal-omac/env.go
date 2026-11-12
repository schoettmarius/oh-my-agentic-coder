package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// defaultAllowEnv is the built-in environment allowlist: the operational
// minimum a shell and the usual toolchain need. Everything else (provider
// tokens, credentials, ambient secrets) is stripped unless explicitly
// allowed via environment.allow_vars in the profile.
func defaultAllowEnv() []string {
	return []string{
		"HOME", "PATH", "SHELL", "TERM", "TMPDIR",
		"LANG", "LC_*", "USER", "LOGNAME", "HOSTNAME",
		"PWD", "XDG_RUNTIME_DIR",
	}
}

// proxyEnvNames are always stripped from the ambient environment and only
// ever set by the filtered-mode proxy injection. Ambient proxy variables
// would otherwise route the sandboxed agent's traffic somewhere unexpected.
var proxyEnvNames = []string{
	"HTTP_PROXY", "http_proxy",
	"HTTPS_PROXY", "https_proxy",
	"NO_PROXY", "no_proxy",
}

// FilterEnv builds the child environment: keep only allowed variables,
// drop denied ones, then overlay the injected values.
func FilterEnv(environ, allow, deny []string, injected map[string]string) []string {
	allowed := append(slices.Clone(defaultAllowEnv()), allow...)
	out := map[string]string{}
	for _, kv := range environ {
		name, val, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if slices.Contains(proxyEnvNames, name) {
			continue
		}
		if !envVarAllowed(name, allowed) || envVarAllowed(name, deny) {
			continue
		}
		out[name] = val
	}
	for k, v := range injected {
		out[k] = v
	}
	names := make([]string, 0, len(out))
	for k := range out {
		names = append(names, k)
	}
	slices.Sort(names)
	env := make([]string, 0, len(out))
	for _, k := range names {
		env = append(env, k+"="+out[k])
	}
	return env
}

// envVarAllowed reports whether name matches the list: exact entries, or
// trailing-* prefix globs (e.g. LC_*).
func envVarAllowed(name string, patterns []string) bool {
	for _, p := range patterns {
		if p == name {
			return true
		}
		if strings.HasSuffix(p, "*") && strings.HasPrefix(name, strings.TrimSuffix(p, "*")) {
			return true
		}
	}
	return false
}

// prepareMarkers creates the bind sources that mask protected paths with
// an explanatory denial marker: a read-only file bound over protected
// files, and a directory holding a single .minimal-denied file bound over
// protected directories.
//
// The marker text is written in inert form, one '#' comment per line: the
// protected set includes shell startup files, and a marker of plain prose
// bound over ~/.profile would be executed by every login shell inside the
// sandbox. Cleanup must be deferred until after the child has exited:
// bwrap reads bind sources at launch, not at argv-construction time.
func (g *Grants) prepareMarkers() (func(), error) {
	noop := func() {}
	if len(g.ProtectedPaths) == 0 {
		return noop, nil
	}
	tmp, err := os.MkdirTemp("", "minimal-omac-markers-")
	if err != nil {
		return noop, fmt.Errorf("create marker dir: %w", err)
	}
	cleanup := func() { os.RemoveAll(tmp) }
	markerFile := filepath.Join(tmp, "denied-file")
	markerDir := filepath.Join(tmp, "denied-dir")
	text := defaultDenialText()
	if err := os.WriteFile(markerFile, []byte(text), 0o444); err != nil {
		cleanup()
		return noop, fmt.Errorf("write file marker: %w", err)
	}
	if err := os.Mkdir(markerDir, 0o755); err != nil {
		cleanup()
		return noop, fmt.Errorf("create dir marker: %w", err)
	}
	if err := os.WriteFile(filepath.Join(markerDir, ".minimal-denied"), []byte(text), 0o444); err != nil {
		cleanup()
		return noop, fmt.Errorf("write dir marker notice: %w", err)
	}
	g.markerFile = markerFile
	g.markerDir = markerDir
	return cleanup, nil
}

// defaultDenialText explains a masked path to the agent. Every line is a
// comment so binding it over a shell config cannot execute anything.
func defaultDenialText() string {
	return "# This file or directory is protected by minimal-omac.\n" +
		"# The real content exists on the host but is deliberately hidden from\n" +
		"# the sandbox. If the agent needs access, adjust the deny list in the\n" +
		"# sandbox profile (filesystem.deny).\n"
}
