//go:build linux && (amd64 || arm64)

package sandbox

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ---- the filter, without a kernel: a small classic-BPF interpreter evaluates it for made-up system calls ----

func evalBPF(t *testing.T, prog []unix.SockFilter, data [64]byte) uint32 {
	t.Helper()
	var acc uint32
	pc := 0
	for steps := 0; steps < 10000; steps++ {
		if pc >= len(prog) {
			t.Fatal("ran off the end of the program")
		}
		in := prog[pc]
		switch in.Code {
		case bpfLdWAbs:
			acc = binary.LittleEndian.Uint32(data[in.K : in.K+4])
			pc++
		case bpfAluAndK:
			acc &= in.K
			pc++
		case bpfJeqK:
			if acc == in.K {
				pc += 1 + int(in.Jt)
			} else {
				pc += 1 + int(in.Jf)
			}
		case bpfJsetK:
			if acc&in.K != 0 {
				pc += 1 + int(in.Jt)
			} else {
				pc += 1 + int(in.Jf)
			}
		case bpfJmpJa:
			pc += 1 + int(in.K)
		case bpfRetK:
			return in.K
		default:
			t.Fatalf("unknown opcode %#x", in.Code)
		}
	}
	t.Fatal("the program does not end")
	return 0
}

func seccompData(arch uint32, nr uint32, args ...uint64) [64]byte {
	var d [64]byte
	binary.LittleEndian.PutUint32(d[0:], nr)
	binary.LittleEndian.PutUint32(d[4:], arch)
	for i, a := range args {
		binary.LittleEndian.PutUint64(d[16+8*i:], a)
	}
	return d
}

func TestTheFilterDecidesEachCallAsIntended(t *testing.T) {
	block, err := buildFilter(false)
	if err != nil {
		t.Fatal(err)
	}
	allowExec, err := buildFilter(true)
	if err != nil {
		t.Fatal(err)
	}
	const (
		allow      = seccompRetAllow
		kill       = seccompRetKillProcess
		noProto    = seccompRetErrnoBase | uint32(unix.EPROTONOSUPPORT)
		noFastOpen = seccompRetErrnoBase | uint32(unix.EOPNOTSUPP)
	)
	tests := []struct {
		name string
		prog []unix.SockFilter
		data [64]byte
		want uint32
	}{
		{"read", block, seccompData(auditArch, unix.SYS_READ), allow},
		{"write", block, seccompData(auditArch, unix.SYS_WRITE), allow},
		{"futex", block, seccompData(auditArch, unix.SYS_FUTEX), allow},
		{"epoll_wait or epoll_pwait", block, seccompData(auditArch, unix.SYS_EPOLL_PWAIT), allow},
		{"mmap", block, seccompData(auditArch, unix.SYS_MMAP), allow},
		{"clone3 (thread creation in newer runtimes)", block, seccompData(auditArch, unix.SYS_CLONE3), allow},
		{"execve", block, seccompData(auditArch, unix.SYS_EXECVE), kill},
		{"execveat", block, seccompData(auditArch, unix.SYS_EXECVEAT), kill},
		{"execve when starting programs is allowed", allowExec, seccompData(auditArch, unix.SYS_EXECVE), allow},
		{"ptrace", block, seccompData(auditArch, unix.SYS_PTRACE), kill},
		{"mount", block, seccompData(auditArch, unix.SYS_MOUNT), kill},
		{"unshare", block, seccompData(auditArch, unix.SYS_UNSHARE), kill},
		{"bpf", block, seccompData(auditArch, unix.SYS_BPF), kill},
		{"io_uring_setup", block, seccompData(auditArch, unix.SYS_IO_URING_SETUP), kill},
		{"memfd_create", block, seccompData(auditArch, unix.SYS_MEMFD_CREATE), kill},
		{"finit_module", block, seccompData(auditArch, unix.SYS_FINIT_MODULE), kill},
		{"keyctl", block, seccompData(auditArch, unix.SYS_KEYCTL), kill},
		{"a plain clone", block, seccompData(auditArch, unix.SYS_CLONE, unix.CLONE_VM|unix.CLONE_FS|unix.CLONE_FILES|unix.CLONE_SIGHAND|unix.CLONE_THREAD), allow},
		{"clone into a new user namespace", block, seccompData(auditArch, unix.SYS_CLONE, unix.CLONE_NEWUSER|uint64(unix.SIGCHLD)), kill},
		{"clone into a new network namespace", block, seccompData(auditArch, unix.SYS_CLONE, unix.CLONE_NEWNET), kill},
		{"socket: IPv4", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM, 0), allow},
		{"socket: IPv6", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET6, unix.SOCK_STREAM, 0), allow},
		{"socket: explicit TCP", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP), allow},
		{"socket: UDP", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP), allow},
		{"socket: MPTCP IPv4", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_MPTCP), noProto},
		{"socket: MPTCP IPv6 with flags", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_MPTCP), noProto},
		{"socket: MPTCP when starting programs is allowed", allowExec, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_MPTCP), noProto},
		{"socket: MPTCP high argument bits", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM, 1<<40|unix.IPPROTO_MPTCP), noProto},
		{"socket: TCP with flags", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0), allow},
		{"socket: UDP with flags", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0), allow},
		{"socket: SCTP stream", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_SCTP), noProto},
		{"socket: SCTP one-to-many IPv6", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET6, unix.SOCK_SEQPACKET, unix.IPPROTO_SCTP), noProto},
		{"socket: sequenced packets with no protocol (SCTP)", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_SEQPACKET, 0), noProto},
		{"socket: sequenced packets, high type bits", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET, 1<<40|unix.SOCK_SEQPACKET, 0), noProto},
		{"socket: DCCP", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET6, unix.SOCK_DCCP, unix.IPPROTO_DCCP), noProto},
		{"socket: UDP-Lite", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDPLITE), noProto},
		{"socket: ICMP echo", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP), noProto},
		{"socket: raw IP", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW), noProto},
		{"socket: SCTP when starting programs is allowed", allowExec, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_SCTP), noProto},
		{"socket: UNIX", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_UNIX, unix.SOCK_STREAM, 0), allow},
		{"socket: netlink, routing", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE), allow},
		{"socket: netlink, audit", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_AUDIT), kill},
		{"socket: netlink, netfilter", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER), kill},
		{"socket: packet", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_PACKET, unix.SOCK_RAW, 0), kill},
		{"socket: kernel crypto", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_ALG, unix.SOCK_SEQPACKET, 0), kill},
		{"socket: vsock", block, seccompData(auditArch, unix.SYS_SOCKET, unix.AF_VSOCK, unix.SOCK_STREAM, 0), kill},
		// TCP Fast Open connects without connect(2), where Landlock checks the port.
		{"sendto with TCP Fast Open", block, seccompData(auditArch, unix.SYS_SENDTO, 3, 0, 1, unix.MSG_FASTOPEN, 0, 16), noFastOpen},
		{"sendto with TCP Fast Open among other flags", block, seccompData(auditArch, unix.SYS_SENDTO, 3, 0, 1, unix.MSG_FASTOPEN|unix.MSG_NOSIGNAL|unix.MSG_DONTWAIT, 0, 16), noFastOpen},
		{"sendto with ordinary flags", block, seccompData(auditArch, unix.SYS_SENDTO, 3, 0, 1, unix.MSG_NOSIGNAL|unix.MSG_DONTWAIT, 0, 0), allow},
		{"sendto with the flag only in the high half, which the kernel ignores", block, seccompData(auditArch, unix.SYS_SENDTO, 3, 0, 1, uint64(unix.MSG_FASTOPEN)<<32, 0, 0), allow},
		{"sendto with TCP Fast Open when starting programs is allowed", allowExec, seccompData(auditArch, unix.SYS_SENDTO, 3, 0, 1, unix.MSG_FASTOPEN, 0, 16), noFastOpen},
		{"sendmsg with TCP Fast Open", block, seccompData(auditArch, unix.SYS_SENDMSG, 3, 0, unix.MSG_FASTOPEN), noFastOpen},
		{"sendmsg with ordinary flags", block, seccompData(auditArch, unix.SYS_SENDMSG, 3, 0, unix.MSG_NOSIGNAL), allow},
		{"sendmmsg with TCP Fast Open", block, seccompData(auditArch, unix.SYS_SENDMMSG, 3, 0, 1, unix.MSG_FASTOPEN), noFastOpen},
		{"sendmmsg with ordinary flags", block, seccompData(auditArch, unix.SYS_SENDMMSG, 3, 0, 1, 0), allow},
		{"recvfrom with the same bit set", block, seccompData(auditArch, unix.SYS_RECVFROM, 3, 0, 1, unix.MSG_FASTOPEN), allow},
		{"socketpair: UNIX", block, seccompData(auditArch, unix.SYS_SOCKETPAIR, unix.AF_UNIX, unix.SOCK_STREAM, 0), allow},
		{"socketpair: INET", block, seccompData(auditArch, unix.SYS_SOCKETPAIR, unix.AF_INET, unix.SOCK_STREAM, 0), kill},
		{"a different architecture", block, seccompData(0x40000003, unix.SYS_READ), kill},
		{"a high bit in the argument that is not the family", block, seccompData(auditArch, unix.SYS_SOCKET, 1<<40|unix.AF_PACKET, 0, 0), kill},
	}
	if auditArch == auditArchX8664 {
		tests = append(tests, struct {
			name string
			prog []unix.SockFilter
			data [64]byte
			want uint32
		}{"the x32 ABI", block, seccompData(auditArch, 0x40000000|unix.SYS_READ), kill})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := evalBPF(t, tt.prog, tt.data); got != tt.want {
				t.Fatalf("action %#x, want %#x", got, tt.want)
			}
		})
	}
}

// A thread with a filter of its own cannot take the process-wide one, and the kernel then installs it on no thread. It says
// so with the thread's id as the return value, not with an error number. It runs in a child process: a filter cannot be
// taken off again.
func TestAFilterThatReachesNoThreadIsAnError(t *testing.T) {
	if os.Getenv("CARNICAL_SANDBOX_TSYNC_CHILD") == "1" {
		tsyncChild(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestAFilterThatReachesNoThreadIsAnError$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "CARNICAL_SANDBOX_TSYNC_CHILD=1")
	out, err := cmd.CombinedOutput()
	if bytes.Contains(out, []byte("--- SKIP")) {
		t.Skipf("the child could not set the case up:\n%s", out)
	}
	if err != nil || !bytes.Contains(out, []byte("--- PASS")) {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

func tsyncChild(t *testing.T) {
	ready, stop := make(chan error), make(chan struct{})
	defer close(stop)
	go func() {
		runtime.LockOSThread() // this thread keeps a filter of its own until the process ends
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			ready <- err
			return
		}
		prog := []unix.SockFilter{{Code: bpfRetK, K: seccompRetAllow}}
		fprog := unix.SockFprog{Len: 1, Filter: &prog[0]}
		if _, _, errno := syscall.Syscall(unix.SYS_SECCOMP, seccompSetModeFilter, 0, uintptr(unsafe.Pointer(&fprog))); errno != 0 {
			ready <- errno
			return
		}
		ready <- nil
		<-stop
	}()
	if err := <-ready; err != nil {
		t.Skipf("a filter for one thread: %v", err)
	}
	// The thread that installs the filter needs no_new_privs itself; the kernel gives it to the others.
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Skipf("no_new_privs: %v", err)
	}
	err := applySeccomp(false)
	if err == nil || !strings.Contains(err.Error(), "could not take the filter") {
		t.Fatalf("applySeccomp returned %v, want the thread that could not take the filter", err)
	}
	ts, terr := Threads()
	if terr != nil {
		t.Fatal(terr)
	}
	filtered := 0
	for _, th := range ts {
		if th.Seccomp == 2 {
			filtered++
		}
	}
	if filtered != 1 {
		t.Fatalf("%d of %d threads have a filter, want only the one that installed its own", filtered, len(ts))
	}
}

func TestEveryJumpFitsAndNoneGoesBackwards(t *testing.T) {
	prog, err := buildFilter(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(prog) < 20 || len(prog) > 400 {
		t.Fatalf("a filter of %d instructions", len(prog))
	}
	if last := prog[len(prog)-1]; last.Code != bpfRetK || last.K != seccompRetKillProcess {
		t.Fatal("the program does not end by refusing")
	}
	for _, tc := range []struct {
		name                                       string
		distance                                   int
		unconditional, missing, backwards, wantErr bool
	}{
		{name: "conditional jump at byte limit", distance: 255},
		{name: "conditional jump beyond byte limit", distance: 256, wantErr: true},
		{name: "unconditional jump beyond byte limit", distance: 256, unconditional: true},
		{name: "unconditional jump beyond 32 bits", unconditional: true, wantErr: true},
		{name: "undefined target", missing: true, wantErr: true},
		{name: "backwards target", backwards: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newAsm()
			if tc.unconditional {
				a.jump("target")
			} else {
				a.jeq(1, "target", "target")
			}
			for i := 0; i < tc.distance; i++ {
				a.ret(seccompRetAllow)
			}
			if !tc.missing {
				a.label("target")
			}
			if tc.backwards {
				a.labels["target"] = 0
			}
			if tc.unconditional && tc.distance == 0 {
				a.labels["target"] = math.MaxInt
			}
			a.ret(seccompRetKillProcess)
			assembled, err := a.program()
			if (err != nil) != tc.wantErr {
				t.Fatalf("program returned %v, want error %t", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			data := [64]byte{}
			binary.NativeEndian.PutUint32(data[:], 1)
			if got := evalBPF(t, assembled, data); got != seccompRetKillProcess {
				t.Fatalf("jump changed decision: %x", got)
			}
		})
	}
}

// ---- the real thing, on this kernel: the probe runs each action in a confined child process ----

func buildProbe(t *testing.T) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command to build the probe with")
	}
	bin := filepath.Join(t.TempDir(), "carnical-confine")
	cmd := exec.Command(goBin, "build", "-o", bin, "./cmd/carnical-confine")
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0") // the confinement cannot reach every thread of a cgo binary
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the probe: %v\n%s", err, out)
	}
	return bin
}

type probeResult struct {
	Confined bool `json:"confined"`
	ABI      int  `json:"landlock_abi"`
	Results  []struct {
		Action string `json:"action"`
		Want   string `json:"want"`
		Got    string `json:"got"`
		OK     bool   `json:"ok"`
		Detail string `json:"detail"`
	} `json:"results"`
	Failures int `json:"failures"`
}

func runProbe(t *testing.T, bin string, args ...string) probeResult {
	t.Helper()
	out, err := exec.Command(bin, append([]string{"check", "-json"}, args...)...).Output()
	var res probeResult
	if jerr := json.Unmarshal(out, &res); jerr != nil {
		t.Fatalf("no result from the probe (%v): %s", err, out)
	}
	return res
}

func TestConfinementHoldsOnThisKernel(t *testing.T) {
	bin := buildProbe(t)
	confined := runProbe(t, bin)
	if confined.ABI < 1 {
		t.Skip("this kernel has no Landlock")
	}
	if len(confined.Results) < 30 {
		t.Fatalf("only %d actions were tried", len(confined.Results))
	}
	for _, r := range confined.Results {
		if !r.OK {
			t.Errorf("confined: %s: wanted %s, got %s (%s)", r.Action, r.Want, r.Got, r.Detail)
		}
	}
	killed := 0
	for _, r := range confined.Results {
		if r.Got == "killed" {
			killed++
		}
	}
	if killed < 10 {
		t.Errorf("only %d actions were ended by the filter", killed)
	}

	t.Run("failed report output is not a successful check", func(t *testing.T) {
		full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
		if err != nil {
			t.Skip("no failing output device: " + err.Error())
		}
		var stderr bytes.Buffer
		cmd := exec.Command(bin, "check", "-json")
		cmd.Stdout, cmd.Stderr = full, &stderr
		err = cmd.Run()
		if closeErr := full.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 2 || stderr.Len() == 0 {
			t.Fatalf("failed report returned %v, stderr %q", err, stderr.String())
		}
	})

	// The control: the same actions with no confinement all go through. If they did not, the confined run would
	// be showing a broken probe and not a working restriction.
	control := runProbe(t, bin, "-unconfined")
	for _, r := range control.Results {
		if !r.OK {
			t.Errorf("control: %s: wanted %s, got %s", r.Action, r.Want, r.Got)
		}
		if r.Got == "killed" || r.Got == "refused" && r.Want == "allowed" {
			t.Errorf("control: %s was stopped with no confinement (%s)", r.Action, r.Got)
		}
	}
}

func TestTheCheckNoticesAWeakenedConfinement(t *testing.T) {
	bin := buildProbe(t)
	if runProbe(t, bin).ABI < 1 {
		t.Skip("this kernel has no Landlock")
	}
	tests := []struct {
		weaken string
		// actions that must now be reported as failing
		failing []string
	}{
		{"seccomp", []string{"start a program (execve)", "ptrace another process", "create an anonymous executable file (memfd_create)", "open a raw packet socket"}},
		{"landlock", []string{"read a file outside the allowed directories", "create a file outside the allowed directories", "make a symbolic link in the allowed directory"}},
	}
	for _, tt := range tests {
		t.Run("without "+tt.weaken, func(t *testing.T) {
			res := runProbe(t, bin, "-weaken", tt.weaken)
			if tt.weaken == "landlock" && res.ABI >= 4 {
				tt.failing = append(tt.failing, "connect to a port that is not allowed", "listen on a port that is not allowed")
			}
			if tt.weaken == "seccomp" {
				control := runProbe(t, bin, "-unconfined")
				for _, r := range control.Results {
					// Only where the kernel has them: unconfined, the socket must be one that opens.
					if (r.Action == "open a Multipath TCP socket" || r.Action == "open an SCTP socket") && r.Got == "allowed" {
						tt.failing = append(tt.failing, r.Action)
					}
				}
			}
			if res.Failures == 0 {
				t.Fatalf("a confinement without %s passed the check", tt.weaken)
			}
			failed := map[string]bool{}
			for _, r := range res.Results {
				if !r.OK {
					failed[r.Action] = true
				}
			}
			for _, name := range tt.failing {
				if !failed[name] {
					t.Errorf("%q was not reported as failing without %s", name, tt.weaken)
				}
			}
			// Layers that were kept still hold.
			for _, r := range res.Results {
				if strings.HasPrefix(r.Action, "read an allowed") && !r.OK {
					t.Errorf("the positive control %q failed", r.Action)
				}
			}
		})
	}
}
