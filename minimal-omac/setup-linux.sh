#!/usr/bin/env bash
# setup-linux.sh — install every apt dependency of minimal-omac
# (Debian/Ubuntu) and verify the sandbox prerequisites:
#
#   1. apt packages: bubblewrap (the sandbox backend, required to run)
#      plus the omac-quick-start extras (zenity, libnotify-bin,
#      libsecret-1-0, jq) for parity with the full omac setup; and
#      golang-go if no Go toolchain is present yet (required to build).
#   2. a bubblewrap smoke test; if it fails because AppArmor restricts
#      unprivileged user namespaces (Ubuntu 23.10+ default), grant bwrap
#      a permanent userns exception and retest.
#   3. a kernel/Landlock check: --network blocked and filtered need
#      Landlock ABI 4 (kernel 6.7 or newer).
#   4. build ./minimal-omac.
#
# Re-run safely at any time: every step is idempotent.
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v apt-get >/dev/null 2>&1; then
	echo "error: this script targets Debian/Ubuntu (apt-get not found)." >&2
	echo "       On Fedora, install the equivalents with: sudo dnf install bubblewrap zenity libnotify libsecret jq golang" >&2
	exit 1
fi

echo "==> Installing apt packages (sudo required)"
sudo apt-get update
sudo apt-get install -y bubblewrap zenity libnotify-bin libsecret-1-0 jq
# Only install the distro Go when none is present, so a newer manual or
# Homebrew-style toolchain is never shadowed by the distro one.
if ! command -v go >/dev/null 2>&1; then
	sudo apt-get install -y golang-go
fi

echo "==> Verifying bubblewrap"
bwrap_smoke() { bwrap --ro-bind / / true >/dev/null 2>&1; }
if ! bwrap_smoke; then
	restrict=0
	[ -r /proc/sys/kernel/apparmor_restrict_unprivileged_userns ] \
		&& restrict=$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns)
	if [ "$restrict" = "1" ]; then
		echo "    bwrap cannot create user namespaces: AppArmor restricts unprivileged"
		echo "    userns (Ubuntu 23.10+ default). Granting bwrap a permanent exception"
		echo "    in /etc/apparmor.d/bwrap; it survives reboots."
		sudo tee /etc/apparmor.d/bwrap > /dev/null <<'EOF'
abi <abi/4.0>,
/usr/bin/bwrap flags=(unconfined) {
  userns,
}
EOF
		sudo apparmor_parser -r /etc/apparmor.d/bwrap
	fi
	if ! bwrap_smoke; then
		echo "error: bwrap is installed but cannot sandbox (user namespaces blocked?" >&2
		echo "       check /proc/sys/kernel/unprivileged_userns_clone and AppArmor)." >&2
		exit 1
	fi
fi
echo "    bubblewrap OK ($(bwrap --version))"

echo "==> Checking the kernel for Landlock network enforcement"
kernel=$(uname -r)
major=${kernel%%.*}
minor=$(echo "$kernel" | cut -d. -f2)
if [ "$major" -lt 6 ] || { [ "$major" -eq 6 ] && [ "$minor" -lt 7 ]; }; then
	echo "    warning: kernel $kernel is older than 6.7 (Landlock ABI 4):"
	echo "    --network blocked and --network filtered will refuse to start."
	echo "    Use --network open, or upgrade the kernel."
	if grep -qi microsoft /proc/version 2>/dev/null; then
		echo "    hint: this is WSL — run 'wsl --update' from Windows PowerShell."
	fi
else
	echo "    kernel $kernel OK"
fi

echo "==> Building minimal-omac"
go build -o minimal-omac .
echo "    built $(pwd)/minimal-omac"

echo
echo "All done. Try it out:"
echo "  ./minimal-omac run --network filtered --allow-domain example.com -- curl -sI https://example.com"
