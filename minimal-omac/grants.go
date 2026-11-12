package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Grants is the fully resolved input to the bwrap backend: absolute,
// existing path grants, the protected set to mask, and the network rules.
type Grants struct {
	Workdir        string
	ReadPaths      []string // read-only
	WritePaths     []string // read+write
	ProtectedPaths []string // masked with denial markers; not filtered for existence

	ProxyPort    int   // set once the filtering proxy is running
	OpenPorts    []int // bind+connect grants
	AllowDomains []string
	DenyDomains  []string

	// markerFile and markerDir are the bind sources used to mask
	// protected paths; empty means "fall back to /dev/null + tmpfs".
	// Populated by prepareMarkers.
	markerFile string
	markerDir  string
}

// baselineReadPaths are granted read-only so the sandboxed command finds
// its toolchain and the C library.
func baselineReadPaths() []string {
	return []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"}
}

// defaultDenyRelPaths are protected by default even when the whole home
// directory is granted: credentials and the shell startup files (which
// exist to be executed, so their denial markers must stay inert).
func defaultDenyRelPaths() []string {
	return []string{
		".ssh", ".gnupg", ".aws", ".kube", ".docker", ".config/gcloud",
		".bashrc", ".bash_profile", ".profile",
		".zshenv", ".zshrc", ".zprofile", ".zlogin",
		".config/fish/config.fish",
	}
}

func ResolveGrants(cfg Config) (*Grants, []string, error) {
	var warnings []string
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, fmt.Errorf("resolve home directory: %w", err)
	}
	workdir := expandPath(cfg.Workdir)
	if info, err := os.Stat(workdir); err != nil || !info.IsDir() {
		return nil, nil, fmt.Errorf("workdir %s is not an existing directory", workdir)
	}
	g := &Grants{
		Workdir:      workdir,
		OpenPorts:    cfg.OpenPorts,
		AllowDomains: cfg.AllowDomains,
		DenyDomains:  cfg.DenyDomains,
	}

	var read []string
	read = append(read, baselineReadPaths()...)
	read = append(read, cfg.Read...)
	g.ReadPaths = filterExisting(expandAll(read), &warnings)

	var write []string
	write = append(write, home, workdir)
	write = append(write, cfg.Write...)
	g.WritePaths = filterExisting(expandAll(write), &warnings)

	// Protected paths are NOT existence-filtered: a missing ~/.ssh today
	// may exist tomorrow, and masking is idempotent either way.
	var deny []string
	for _, rel := range defaultDenyRelPaths() {
		deny = append(deny, filepath.Join(home, rel))
	}
	deny = append(deny, cfg.Deny...)
	for _, p := range expandAll(deny) {
		if !slices.Contains(g.ProtectedPaths, p) {
			g.ProtectedPaths = append(g.ProtectedPaths, p)
		}
	}
	return g, warnings, nil
}

// expandPath resolves ~ and makes the path absolute and clean.
func expandPath(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return filepath.Clean(p)
}

func expandAll(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, expandPath(p))
	}
	return out
}

// filterExisting drops paths that do not exist on the host with a
// warning: bwrap aborts the whole launch on a missing bind source.
func filterExisting(paths []string, warnings *[]string) []string {
	var out []string
	for _, p := range paths {
		if _, err := os.Lstat(p); err != nil {
			*warnings = append(*warnings, fmt.Sprintf("grant %s does not exist on the host; dropped", p))
			continue
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}
