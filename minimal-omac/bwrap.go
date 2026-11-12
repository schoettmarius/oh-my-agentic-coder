package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// BuildChildArgv wraps the inner command in bwrap + the stage2 re-exec:
// it grants the minimal-omac binary and the inner binary's directories
// read-only (bwrap must be able to exec both inside the namespace),
// rewrites argv[0] to the symlink-resolved binary so exec does not have
// to follow symlink chains inside the sandbox, and validates the network
// enforcement prerequisites up front.
func BuildChildArgv(g *Grants, innerArgv []string) ([]string, error) {
	if len(innerArgv) == 0 {
		return nil, errors.New("no inner command")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		return nil, fmt.Errorf("bubblewrap (bwrap) not found on PATH — install it with your package manager (e.g. sudo apt install bubblewrap): %w", err)
	}
	needsLandlock := g.NetworkMode == ModeFiltered || g.NetworkMode == ModeBlocked
	if needsLandlock && !LandlockNetSupported() {
		return nil, fmt.Errorf(
			"minimal-omac can't enforce network rules on this kernel, so it won't start.\n"+
				"\n"+
				"Network enforcement uses Landlock TCP rules, which need Landlock ABI 4\n"+
				"(Linux kernel 6.7 or newer). This kernel is %s (Landlock ABI %d).\n"+
				"Use --network open to launch without network rules, or upgrade the kernel.",
			kernelVersionString(), LandlockABI())
	}
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve minimal-omac executable: %w", err)
	}
	// Bind the real file: a symlink bind would dangle if its target
	// directory is not in the namespace.
	if resolved, rerr := filepath.EvalSymlinks(self); rerr == nil {
		self = resolved
	}

	gz := *g
	gz.ReadPaths = slices.Clone(g.ReadPaths)
	gz.ReadPaths = append(gz.ReadPaths, self)

	inner, binDirs := resolveInnerCommand(innerArgv)
	gz.ReadPaths = append(gz.ReadPaths, binDirs...)

	stage2 := append([]string{self, "stage2"}, Stage2Args(g)...)
	stage2 = append(stage2, "--")
	stage2 = append(stage2, inner...)
	return BuildBwrapArgv(&gz, stage2)
}

// resolveInnerCommand looks the inner binary up on the host PATH and
// returns its argv with argv[0] rewritten to the symlink-resolved real
// path, plus the directories to grant read-only: the directory containing
// the resolved binary (so PATH lookup works) and the directory of the real
// file (so a version-manager shim reaches its target).
func resolveInnerCommand(innerArgv []string) ([]string, []string) {
	name := innerArgv[0]
	resolved := name
	if !strings.ContainsRune(name, '/') {
		p, err := exec.LookPath(name)
		if err != nil {
			// Not resolvable now; stage2 reports the informative error.
			return innerArgv, nil
		}
		resolved = p
	} else {
		resolved = expandPath(name)
	}
	real := resolved
	if r, err := filepath.EvalSymlinks(resolved); err == nil {
		real = r
	}
	var dirs []string
	for _, d := range []string{filepath.Dir(resolved), filepath.Dir(real)} {
		if !slices.Contains(dirs, d) {
			dirs = append(dirs, d)
		}
	}
	out := slices.Clone(innerArgv)
	out[0] = real
	return out, dirs
}

// mount is one bwrap bind entry.
type mount struct {
	path string
	rw   bool
}

// BuildBwrapArgv constructs the bubblewrap invocation for the grant set:
//   - --ro-bind for read grants, --bind for write grants
//   - fresh --proc /proc and --dev /dev
//   - --tmpfs /tmp unless /tmp itself is granted (subpath binds layer
//     over the tmpfs)
//   - --unshare-pid --unshare-ipc --unshare-uts (NOT --unshare-net: the
//     network namespace stays shared so the proxy on loopback is
//     reachable; confinement comes from Landlock instead)
//   - --new-session so confined code cannot inject keystrokes into the
//     host terminal via TIOCSTI
//   - protected paths inside granted trees masked with the denial markers
func BuildBwrapArgv(g *Grants, stage2Argv []string) ([]string, error) {
	if len(stage2Argv) == 0 {
		return nil, errors.New("bwrap: empty stage2 argv")
	}
	argv := []string{
		"bwrap",
		"--die-with-parent",
		"--new-session",
		"--unshare-pid",
		"--unshare-ipc",
		"--unshare-uts",
	}
	rootGranted := slices.Contains(g.WritePaths, "/")
	if rootGranted {
		argv = append(argv, "--bind", "/", "/")
	}
	argv = append(argv, "--proc", "/proc", "--dev", "/dev")

	// Dedupe with rw winning over ro for the same path.
	mounts := map[string]*mount{}
	add := func(p string, rw bool) {
		if p == "/" || p == "/proc" || p == "/dev" {
			return
		}
		if m, ok := mounts[p]; ok {
			m.rw = m.rw || rw
			return
		}
		mounts[p] = &mount{path: p, rw: rw}
	}
	for _, p := range g.ReadPaths {
		add(p, false)
	}
	for _, p := range g.WritePaths {
		add(p, true)
	}

	// Sort parents before children so nested binds layer correctly (a
	// path and its prefix make lexicographic order parent-first).
	ordered := make([]*mount, 0, len(mounts))
	for _, m := range mounts {
		ordered = append(ordered, m)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].path < ordered[j].path })

	tmpGranted := rootGranted
	var tmpSub []*mount
	for _, m := range ordered {
		if m.path == "/tmp" {
			tmpGranted = true
			argv = append(argv, bindFlag(m), m.path, m.path)
			continue
		}
		if rootGranted {
			continue
		}
		// Defer /tmp subpath binds: they must layer over --tmpfs /tmp.
		if strings.HasPrefix(m.path, "/tmp/") {
			tmpSub = append(tmpSub, m)
			continue
		}
		argv = append(argv, bindFlag(m), m.path, m.path)
	}
	if !tmpGranted {
		argv = append(argv, "--tmpfs", "/tmp")
	}
	for _, m := range tmpSub {
		argv = append(argv, bindFlag(m), m.path, m.path)
	}

	// Protected-path masking must come after the binds they shadow. With
	// the whole root granted every protected path is covered; otherwise
	// only those inside a grant are masked.
	for _, prot := range g.ProtectedPaths {
		if !rootGranted && !coveredByAny(prot, ordered) {
			continue
		}
		fi, err := os.Lstat(prot)
		if err != nil {
			continue // does not exist; nothing to mask
		}
		if fi.IsDir() {
			if g.markerDir != "" {
				argv = append(argv, "--ro-bind", g.markerDir, prot)
			} else {
				argv = append(argv, "--tmpfs", prot)
			}
		} else {
			if g.markerFile != "" {
				argv = append(argv, "--ro-bind", g.markerFile, prot)
			} else {
				argv = append(argv, "--ro-bind", "/dev/null", prot)
			}
		}
	}

	argv = append(argv, "--chdir", g.Workdir, "--")
	return append(argv, stage2Argv...), nil
}

func bindFlag(m *mount) string {
	if m.rw {
		return "--bind"
	}
	return "--ro-bind"
}

// isUnder reports whether path equals root or lies below it.
func isUnder(path, root string) bool {
	return path == root || root == "/" || strings.HasPrefix(path, root+string(filepath.Separator))
}

func coveredByAny(path string, mounts []*mount) bool {
	for _, m := range mounts {
		if isUnder(path, m.path) {
			return true
		}
	}
	return false
}

// kernelVersionString returns the running kernel version from /proc/version
// (e.g. "6.1.0-28-amd64"), or "unknown" when unreadable.
func kernelVersionString() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "unknown"
	}
	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		return fields[2]
	}
	return strings.TrimSpace(string(data))
}
