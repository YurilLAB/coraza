//go:build linux && (amd64 || arm64)

// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"errors"
	"fmt"
	"math"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// What a process that has just been taken over needs, and a Go service that does its job never calls: start a program,
// look into or control another process, change the system, load kernel code, build a way around a file permission,
// create namespaces, use the kernel's less-tested interfaces. Each one ends the process (SECCOMP_RET_KILL_PROCESS): an
// attacker stopped at that call has no second try, and the kernel writes an audit record that names the call.
//
// It is a deny list, not an allow list, on purpose. The Go runtime changes its system calls between releases, and a
// service killed by its own runtime is an outage the attacker did not have to cause. The list is the calls that
// matter for getting from "running code in the service" to "owning the machine".
//
// The names are resolved to numbers by the arch-specific files.
var killSyscalls = []struct {
	nr   uint32
	name string
}{
	{unix.SYS_PTRACE, "ptrace"}, {unix.SYS_PROCESS_VM_READV, "process_vm_readv"}, {unix.SYS_PROCESS_VM_WRITEV, "process_vm_writev"},
	{unix.SYS_KCMP, "kcmp"}, {unix.SYS_PIDFD_GETFD, "pidfd_getfd"},
	{unix.SYS_MOUNT, "mount"}, {unix.SYS_UMOUNT2, "umount2"}, {unix.SYS_PIVOT_ROOT, "pivot_root"}, {unix.SYS_CHROOT, "chroot"},
	{unix.SYS_MOVE_MOUNT, "move_mount"}, {unix.SYS_OPEN_TREE, "open_tree"}, {unix.SYS_FSOPEN, "fsopen"}, {unix.SYS_FSCONFIG, "fsconfig"},
	{unix.SYS_FSMOUNT, "fsmount"}, {unix.SYS_FSPICK, "fspick"}, {unix.SYS_MOUNT_SETATTR, "mount_setattr"},
	{unix.SYS_SETNS, "setns"}, {unix.SYS_UNSHARE, "unshare"},
	{unix.SYS_BPF, "bpf"}, {unix.SYS_PERF_EVENT_OPEN, "perf_event_open"}, {unix.SYS_USERFAULTFD, "userfaultfd"},
	{unix.SYS_IO_URING_SETUP, "io_uring_setup"}, {unix.SYS_IO_URING_ENTER, "io_uring_enter"}, {unix.SYS_IO_URING_REGISTER, "io_uring_register"},
	{unix.SYS_KEXEC_LOAD, "kexec_load"}, {unix.SYS_KEXEC_FILE_LOAD, "kexec_file_load"},
	{unix.SYS_INIT_MODULE, "init_module"}, {unix.SYS_FINIT_MODULE, "finit_module"}, {unix.SYS_DELETE_MODULE, "delete_module"},
	{unix.SYS_REBOOT, "reboot"}, {unix.SYS_SWAPON, "swapon"}, {unix.SYS_SWAPOFF, "swapoff"}, {unix.SYS_ACCT, "acct"},
	{unix.SYS_QUOTACTL, "quotactl"}, {unix.SYS_SETTIMEOFDAY, "settimeofday"}, {unix.SYS_CLOCK_SETTIME, "clock_settime"},
	{unix.SYS_CLOCK_ADJTIME, "clock_adjtime"}, {unix.SYS_ADJTIMEX, "adjtimex"}, {unix.SYS_SETHOSTNAME, "sethostname"},
	{unix.SYS_SETDOMAINNAME, "setdomainname"}, {unix.SYS_VHANGUP, "vhangup"}, {unix.SYS_PERSONALITY, "personality"},
	{unix.SYS_ADD_KEY, "add_key"}, {unix.SYS_REQUEST_KEY, "request_key"}, {unix.SYS_KEYCTL, "keyctl"},
	{unix.SYS_NAME_TO_HANDLE_AT, "name_to_handle_at"}, {unix.SYS_OPEN_BY_HANDLE_AT, "open_by_handle_at"},
	// Running code that was never a file on disk.
	{unix.SYS_MEMFD_CREATE, "memfd_create"},
}

var execSyscalls = []struct {
	nr   uint32
	name string
}{{unix.SYS_EXECVE, "execve"}, {unix.SYS_EXECVEAT, "execveat"}}

// The namespace flags of clone(2). Go creates its threads without any of them.
const cloneNewFlags = unix.CLONE_NEWNS | unix.CLONE_NEWCGROUP | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC | unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET

// Socket families the proxy uses: UNIX, IPv4, IPv6, and netlink for the routing table (the standard library reads the
// machine's own addresses that way). Packet sockets, the kernel crypto API (AF_ALG, behind several recent local
// privilege escalations), vsock, and the rarely-used protocol families are not among them.
var allowedFamilies = []uint32{unix.AF_UNIX, unix.AF_INET, unix.AF_INET6}

const (
	seccompRetKillProcess = 0x80000000
	seccompRetAllow       = 0x7fff0000
	seccompRetErrnoBase   = 0x00050000

	seccompSetModeFilter   = 1
	seccompFilterFlagTsync = 1

	// struct seccomp_data
	offNr   = 0
	offArch = 4
	offArg0 = 16

	bpfLdWAbs  = 0x20
	bpfAluAndK = 0x54
	bpfJeqK    = 0x15
	bpfJsetK   = 0x45
	bpfRetK    = 0x06
	bpfJmpJa   = 0x05
)

// asm is a small BPF assembler with labels: a jump is eight bits, so the program is built with names and the offsets
// are worked out at the end.
type asm struct {
	ins    []unix.SockFilter
	labels map[string]int
	fixups []fixup
}

type fixup struct {
	at      int
	t, f    string // targets for a conditional jump; t only for an unconditional one
	isJump  bool
	isUncnd bool
}

func newAsm() *asm { return &asm{labels: map[string]int{}} }

func (a *asm) emit(code uint16, k uint32) int {
	a.ins = append(a.ins, unix.SockFilter{Code: code, K: k})
	return len(a.ins) - 1
}

func (a *asm) load(off uint32)   { a.emit(bpfLdWAbs, off) }
func (a *asm) and(mask uint32)   { a.emit(bpfAluAndK, mask) }
func (a *asm) ret(action uint32) { a.emit(bpfRetK, action) }
func (a *asm) label(name string) { a.labels[name] = len(a.ins) }
func (a *asm) jeq(k uint32, t, f string) {
	a.fixups = append(a.fixups, fixup{at: a.emit(bpfJeqK, k), t: t, f: f, isJump: true})
}
func (a *asm) jset(k uint32, t, f string) {
	a.fixups = append(a.fixups, fixup{at: a.emit(bpfJsetK, k), t: t, f: f, isJump: true})
}
func (a *asm) jump(to string) {
	a.fixups = append(a.fixups, fixup{at: a.emit(bpfJmpJa, 0), t: to, isUncnd: true})
}

// program resolves the labels. It fails if a conditional jump does not fit in eight bits.
func (a *asm) program() ([]unix.SockFilter, error) {
	for _, f := range a.fixups {
		target := func(name string) (int, error) {
			to, ok := a.labels[name]
			if !ok {
				return 0, fmt.Errorf("seccomp: label %q is not defined", name)
			}
			if to <= f.at {
				return 0, errors.New("seccomp: a jump goes backwards")
			}
			return to - f.at - 1, nil
		}
		t, err := target(f.t)
		if err != nil {
			return nil, err
		}
		if f.isUncnd {
			if t < 0 || t > math.MaxUint32 {
				return nil, errors.New("seccomp: an unconditional jump exceeds 32 bits")
			}
			a.ins[f.at].K = uint32(t)
			continue
		}
		fo, err := target(f.f)
		if err != nil {
			return nil, err
		}
		if t < 0 || fo < 0 || t > 255 || fo > 255 {
			return nil, errors.New("seccomp: a conditional jump is further than 255 instructions")
		}
		a.ins[f.at].Jt, a.ins[f.at].Jf = uint8(t), uint8(fo)
	}
	return a.ins, nil
}

// buildFilter assembles the filter. Order matters only for speed: the calls a running service makes all the time are
// not in the list, so most calls cost one pass over the list and are allowed.
func buildFilter(allowExec bool) ([]unix.SockFilter, error) {
	a := newAsm()

	// The architecture must be the one the numbers below are for, or a call made through a different entry
	// (32-bit compatibility on x86-64) would be numbered differently and slip past.
	a.load(offArch)
	a.jeq(auditArch, "arch-ok", "kill")
	a.label("arch-ok")
	a.load(offNr)
	if auditArch == auditArchX8664 {
		// The x32 ABI sets this bit on every call number and shares the architecture value.
		a.jset(0x40000000, "kill", "not-x32")
		a.label("not-x32")
	}

	deny := killSyscalls
	if !allowExec {
		deny = append(append(deny[:0:0], deny...), execSyscalls...)
	}
	for i, s := range deny {
		next := fmt.Sprintf("next-%d", i)
		a.jeq(s.nr, "kill", next)
		a.label(next)
	}

	// clone with a namespace flag (an unprivileged user namespace is how most kernel privilege escalations start).
	a.jeq(unix.SYS_CLONE, "check-clone", "after-clone")
	a.label("check-clone")
	a.load(offArg0)
	a.jset(cloneNewFlags, "kill", "reload-nr")
	a.label("reload-nr")
	a.load(offNr)
	a.label("after-clone")

	// socket(domain, type, protocol) and socketpair: only the families listed above, and netlink only for routing.
	a.jeq(unix.SYS_SOCKET, "check-socket", "after-socket")
	a.label("check-socket")
	a.load(offArg0)
	for _, fam := range allowedFamilies {
		target := "allow"
		if fam == unix.AF_INET || fam == unix.AF_INET6 {
			target = "inet-proto"
		}
		a.jeq(fam, target, fmt.Sprintf("fam-%d", fam))
		a.label(fmt.Sprintf("fam-%d", fam))
	}
	a.jeq(unix.AF_NETLINK, "netlink-proto", "kill")
	a.label("netlink-proto")
	a.load(offArg0 + 16) // the third argument, protocol: NETLINK_ROUTE is 0
	a.jeq(unix.NETLINK_ROUTE, "allow", "kill")
	// IPv4 and IPv6: TCP and UDP only. Landlock's port rules cover TCP alone, so another transport (Multipath TCP, which
	// can speak ordinary TCP, or SCTP, which a sequenced-packet socket gets by default) would reach any port. Refuse with
	// an unsupported-protocol error rather than end the process: Go then falls back from Multipath TCP to TCP.
	a.label("inet-proto")
	a.load(offArg0 + 8) // the second argument, type, without SOCK_NONBLOCK and SOCK_CLOEXEC
	a.and(0xf)
	a.jeq(unix.SOCK_STREAM, "inet-protocol", "type-dgram")
	a.label("type-dgram")
	a.jeq(unix.SOCK_DGRAM, "inet-protocol", "no-proto")
	a.label("inet-protocol")
	a.load(offArg0 + 16)
	a.jeq(0, "allow", "proto-tcp")
	a.label("proto-tcp")
	a.jeq(unix.IPPROTO_TCP, "allow", "proto-udp")
	a.label("proto-udp")
	a.jeq(unix.IPPROTO_UDP, "allow", "no-proto")
	a.label("after-socket")
	a.load(offNr)

	// sendto, sendmsg and sendmmsg with MSG_FASTOPEN: on a new TCP socket that connects, sending the SYN itself, without
	// the connect(2) that Landlock's port rule is checked on. Go never sets the flag. Refuse it with the error a kernel
	// with client Fast Open switched off gives.
	for _, send := range []struct{ nr, flagsArg uint32 }{{unix.SYS_SENDTO, 3}, {unix.SYS_SENDMSG, 2}, {unix.SYS_SENDMMSG, 3}} {
		check := fmt.Sprintf("check-send-%d", send.nr)
		after := fmt.Sprintf("after-send-%d", send.nr)
		a.jeq(send.nr, check, after)
		a.label(check)
		a.load(offArg0 + 8*send.flagsArg) // the low half of the flags, all the kernel reads
		a.jset(unix.MSG_FASTOPEN, "no-fastopen", "allow")
		a.label(after)
	}

	a.jeq(unix.SYS_SOCKETPAIR, "check-pair", "allow")
	a.label("check-pair")
	a.load(offArg0)
	a.jeq(unix.AF_UNIX, "allow", "kill")

	a.label("no-fastopen")
	a.ret(seccompRetErrnoBase | uint32(unix.EOPNOTSUPP))
	a.label("no-proto")
	a.ret(seccompRetErrnoBase | uint32(unix.EPROTONOSUPPORT))
	a.label("allow")
	a.ret(seccompRetAllow)
	a.label("kill")
	a.ret(seccompRetKillProcess)
	return a.program()
}

// applySeccomp installs the filter on every thread (SECCOMP_FILTER_FLAG_TSYNC), which is why the call is made once
// and from here: a filter loaded without TSYNC covers only the calling thread, and the goroutines that matter would
// run on the others.
func applySeccomp(allowExec bool) error {
	prog, err := buildFilter(allowExec)
	if err != nil {
		return err
	}
	if len(prog) == 0 || len(prog) > 4096 {
		return fmt.Errorf("seccomp program length %d exceeds kernel bounds", len(prog))
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]} // #nosec G115 -- The preceding check bounds program length to 1..4096.
	// #nosec G103 -- Existing kernel ABI binding using unix.SockFprog and a live 1..4096-entry filter; conversion occurs directly in the syscall argument.
	tid, _, errno := syscall.Syscall(unix.SYS_SECCOMP, seccompSetModeFilter, seccompFilterFlagTsync, uintptr(unsafe.Pointer(&fprog)))
	if errno != 0 {
		return fmt.Errorf("seccomp: %w", errno)
	}
	// A thread that cannot take the filter (it has one of its own) is named by its id, and then no thread has it.
	if tid != 0 {
		return fmt.Errorf("seccomp: thread %d could not take the filter, so no thread has it", tid)
	}
	return nil
}
