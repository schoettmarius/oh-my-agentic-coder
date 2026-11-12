package main

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// applyDatagramSeccomp installs a seccomp-BPF filter that confines
// socket(2) creation to an allowlist and denies the io_uring syscall
// family, closing the non-TCP egress path that Landlock (TCP-only) cannot
// express: ICMP, SCTP, raw sockets, and unrestricted netlink. Must be
// called after no_new_privs is set (ApplyLandlockNet does this).
//
// The allowlist:
//   - AF_UNIX is unrestricted
//   - AF_NETLINK is limited to SOCK_RAW / NETLINK_ROUTE
//   - AF_INET and AF_INET6 are limited to SOCK_STREAM with protocol 0,
//     IPPROTO_TCP, or IPPROTO_MPTCP, and to SOCK_DGRAM with protocol 0 or
//     IPPROTO_UDP (net-tools ifconfig enumerates addresses over such a
//     socket; protocol 0 selects UDP)
//   - io_uring_setup / io_uring_enter / io_uring_register are denied, so
//     no socket can be created via IORING_OP_SOCKET, which never reaches
//     socket(2)
//   - every other syscall passes through untouched
//
// Allowing SOCK_DGRAM also leaves UDP egress open; Landlock has no UDP
// rules, so the filtering proxy can be bypassed for UDP. This is an
// accepted gap, recorded in README.md.
//
// seccomp_data field offsets (kernel uapi/linux/seccomp.h):
//
//	0:  nr        (u32) — syscall number
//	16: args[0]   (u64) — socket domain
//	24: args[1]   (u64) — socket type
//	32: args[2]   (u64) — socket protocol
const (
	offNR   = 0
	offArg0 = 16 // domain
	offArg1 = 24 // type
	offArg2 = 32 // protocol

	bpfLD  = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
	bpfJEQ = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
	bpfRET = unix.BPF_RET | unix.BPF_K

	// sockTypeMask strips SOCK_CLOEXEC (0x80000) and SOCK_NONBLOCK
	// (0x800) from the type argument so comparisons hit the base type.
	sockTypeMask = 0xf

	retAllow = unix.SECCOMP_RET_ALLOW
	retEPERM = unix.SECCOMP_RET_ERRNO | uint32(syscall.EPERM)
)

// datagramSeccompFilter returns the program installed by
// applyDatagramSeccomp. It is a separate function so the regression
// suite can load the exact production program into a userspace BPF
// walker and assert the action for every (domain, type, protocol) the
// allowlist must cover — without depending on kernel enforcement being
// available on the test host.
//
// Program layout (jt/jf are skips counted from the next instruction):
//
//	 0: load nr
//	 1-3: nr == io_uring_setup/enter/register → deny
//	 4: nr == socket → 5; else → allow (26)
//	 5: load domain
//	 6: AF_UNIX → allow (26)
//	 7: AF_NETLINK → 10 (netlink check); else fall through
//	 8: AF_INET → 15 (inet check); else fall through
//	 9: AF_INET6 → 15 (inet check); else → deny (27)
//	10-12: netlink: type==SOCK_RAW → 13; else → deny
//	13-14: protocol==NETLINK_ROUTE → allow; else → deny
//	15-17: inet: type==SOCK_STREAM → 18; else → 22 (dgram check)
//	18-21: stream protocol in {0, IPPROTO_TCP, IPPROTO_MPTCP} → allow; else → deny
//	22: type==SOCK_DGRAM → 23; else → deny
//	23-25: dgram protocol in {0, IPPROTO_UDP} → allow; else → deny
//	26: allow
//	27: deny
func datagramSeccompFilter() []unix.SockFilter {
	return []unix.SockFilter{
		{Code: bpfLD, K: offNR},
		{Code: bpfJEQ, Jt: 25, K: uint32(unix.SYS_IO_URING_SETUP)},
		{Code: bpfJEQ, Jt: 24, K: uint32(unix.SYS_IO_URING_ENTER)},
		{Code: bpfJEQ, Jt: 23, K: uint32(unix.SYS_IO_URING_REGISTER)},
		{Code: bpfJEQ, Jt: 0, Jf: 21, K: uint32(unix.SYS_SOCKET)},
		{Code: bpfLD, K: offArg0},
		{Code: bpfJEQ, Jt: 19, K: uint32(syscall.AF_UNIX)},
		{Code: bpfJEQ, Jt: 2, K: uint32(syscall.AF_NETLINK)},
		{Code: bpfJEQ, Jt: 6, K: uint32(syscall.AF_INET)},
		{Code: bpfJEQ, Jt: 5, Jf: 17, K: uint32(syscall.AF_INET6)},
		{Code: bpfLD, K: offArg1},
		{Code: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, K: sockTypeMask},
		{Code: bpfJEQ, Jt: 0, Jf: 14, K: unix.SOCK_RAW},
		{Code: bpfLD, K: offArg2},
		{Code: bpfJEQ, Jt: 11, Jf: 12, K: uint32(unix.NETLINK_ROUTE)},
		{Code: bpfLD, K: offArg1},
		{Code: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, K: sockTypeMask},
		{Code: bpfJEQ, Jt: 0, Jf: 4, K: unix.SOCK_STREAM},
		{Code: bpfLD, K: offArg2},
		{Code: bpfJEQ, Jt: 6, K: 0},
		{Code: bpfJEQ, Jt: 5, K: uint32(unix.IPPROTO_TCP)},
		{Code: bpfJEQ, Jt: 4, Jf: 5, K: uint32(unix.IPPROTO_MPTCP)},
		{Code: bpfJEQ, Jt: 0, Jf: 4, K: unix.SOCK_DGRAM},
		{Code: bpfLD, K: offArg2},
		{Code: bpfJEQ, Jt: 1, K: 0},
		{Code: bpfJEQ, Jt: 0, Jf: 1, K: uint32(unix.IPPROTO_UDP)},
		{Code: bpfRET, K: retAllow},
		{Code: bpfRET, K: retEPERM},
	}
}

func applyDatagramSeccomp() error {
	filter := datagramSeccompFilter()
	prog := &unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}
	// no_new_privs is already set by ApplyLandlockNet; lock the OS thread
	// so the syscall is issued from the thread that will exec.
	runtime.LockOSThread()
	if _, _, errno := unix.Syscall(unix.SYS_PRCTL,
		unix.PR_SET_SECCOMP,
		unix.SECCOMP_MODE_FILTER,
		uintptr(unsafe.Pointer(prog)),
	); errno != 0 {
		return fmt.Errorf("seccomp(FILTER): %w", errno)
	}
	return nil
}
