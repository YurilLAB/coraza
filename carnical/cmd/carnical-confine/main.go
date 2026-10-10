//go:build linux && (amd64 || arm64)

// Command carnical-confine checks that the confinement in package sandbox does what it says, by trying from inside it
// the things an attacker who has taken over the proxy would try.
//
//	carnical-confine check                  # confined: every forbidden action must be refused, every allowed one must work
//	carnical-confine check -unconfined      # the control: the same actions with no confinement, every one must go through
//
// Each action runs in a child process of its own, because the actions that the seccomp filter refuses end the process.
// A check that passes confined and passes unconfined for the same action proves nothing, so the control run is part of
// the evidence: the check is only believed when the two differ in exactly the places they should.
//
// Build with CGO_ENABLED=0; the confinement cannot reach every thread of a cgo binary.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/YurilLAB/coraza/carnical/sandbox"
)

// outcome is what happened when an action was tried.
type outcome string

const (
	allowed outcome = "allowed" // the action worked
	refused outcome = "refused" // the action failed with an error (the file system or network restriction)
	killed  outcome = "killed"  // the process was ended by the system-call filter
)

type env struct {
	ro, rw, other            string
	allowedPort              uint16
	forbiddenPort            uint16
	bindOK, bindNo, httpPort uint16
	abstract                 string
	parentPID                int
	landlockABI              int
	confine                  bool
	reportPath               string
}

type action struct {
	name string
	// confined and control are what must happen with and without the confinement. "" for confined means "skip".
	confined func(abi int) outcome
	control  outcome
	run      func(e *env) error
}

func always(o outcome) func(int) outcome { return func(int) outcome { return o } }
func ifABI(min int, o outcome) func(int) outcome {
	return func(abi int) outcome {
		if abi >= min {
			return o
		}
		return allowed // the kernel is too old for this restriction; the report says so
	}
}

var actions = []action{
	// What must keep working.
	{"read an allowed file", always(allowed), allowed, func(e *env) error {
		_, err := os.ReadFile(filepath.Join(e.ro, "hello.txt"))
		return err
	}},
	{"write in an allowed directory", always(allowed), allowed, func(e *env) error {
		p := filepath.Join(e.rw, "upload.tmp")
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			return err
		}
		return os.Remove(p)
	}},
	{"open a TCP connection to an allowed port", always(allowed), allowed, func(e *env) error {
		return dial(e.allowedPort)
	}},
	{"listen on an allowed port", always(allowed), allowed, func(e *env) error { return listen(e.bindOK) }},
	{"look up a name and talk HTTP", always(allowed), allowed, func(e *env) error { return httpRoundTrip(e.httpPort) }},
	{"read the machine's own addresses (netlink)", always(allowed), allowed, func(e *env) error {
		_, err := net.InterfaceAddrs()
		return err
	}},
	{"start many threads", always(allowed), allowed, func(e *env) error {
		var wg sync.WaitGroup
		for i := 0; i < 40; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); runtime.LockOSThread(); time.Sleep(50 * time.Millisecond) }()
		}
		wg.Wait()
		return nil
	}},

	// Files.
	{"read a file outside the allowed directories", always(refused), allowed, func(e *env) error {
		_, err := os.ReadFile(filepath.Join(e.other, "secret.txt"))
		return err
	}},
	{"create a file outside the allowed directories", always(refused), allowed, func(e *env) error {
		return os.WriteFile(filepath.Join(e.other, "planted"), []byte("x"), 0o600)
	}},
	{"write in a read-only directory", always(refused), allowed, func(e *env) error {
		return os.WriteFile(filepath.Join(e.ro, "planted"), []byte("x"), 0o600)
	}},
	{"make a symbolic link in the allowed directory", always(refused), allowed, func(e *env) error {
		return os.Symlink("/etc/passwd", filepath.Join(e.rw, "link"))
	}},
	{"make a named pipe in the allowed directory", always(refused), allowed, func(e *env) error {
		return unix.Mkfifo(filepath.Join(e.rw, "fifo"), 0o600)
	}},
	{"read another process's environment", always(refused), allowed, func(e *env) error {
		_, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", e.parentPID))
		return err
	}},
	{"read another process's memory map", always(refused), allowed, func(e *env) error {
		f, err := os.Open(fmt.Sprintf("/proc/%d/maps", e.parentPID))
		if err == nil {
			// #nosec G104 -- The probe measures whether Open succeeded; cleanup cannot change the established access result.
			f.Close()
		}
		return err
	}},

	// Network.
	{"open a Multipath TCP socket", always(refused), refusedOrErr, func(e *env) error {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_MPTCP)
		if err != nil {
			return err
		}
		return unix.Close(fd)
	}},
	// A sequenced-packet socket with no protocol named is SCTP, which Landlock's port rules do not cover either.
	{"open an SCTP socket", always(refused), refusedOrErr, func(e *env) error {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		return unix.Close(fd)
	}},
	{"connect to a port that is not allowed", ifABI(4, refused), allowed, func(e *env) error { return dial(e.forbiddenPort) }},
	// TCP Fast Open connects from sendto(2), without the connect(2) that Landlock's port rule is checked on. Unconfined it
	// works, or fails where the machine has client Fast Open switched off.
	{"connect to a port that is not allowed with TCP Fast Open", always(refused), refusedOrErr, func(e *env) error {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		err = unix.Sendto(fd, []byte("x"), unix.MSG_FASTOPEN, &unix.SockaddrInet4{Port: int(e.forbiddenPort), Addr: [4]byte{127, 0, 0, 1}})
		// #nosec G104 -- The probe measures whether the send connected; cleanup cannot change that result.
		unix.Close(fd)
		return err
	}},
	{"listen on a port that is not allowed", ifABI(4, refused), allowed, func(e *env) error { return listen(e.bindNo) }},
	{"connect to another process's abstract socket", ifABI(6, refused), allowed, func(e *env) error {
		c, err := net.Dial("unix", "@"+e.abstract)
		if err == nil {
			// #nosec G104 -- The probe measures Dial reachability; cleanup must not turn an established connection into an apparent denial.
			c.Close()
		}
		return err
	}},
	{"signal a process outside the confinement", ifABI(6, refused), allowed, func(e *env) error {
		return syscall.Kill(e.parentPID, syscall.Signal(0))
	}},

	// System calls that end the process.
	{"start a program (execve)", always(killed), allowed, func(e *env) error { return syscall.Exec("/bin/true", []string{"true"}, nil) }},
	// The child that tries to exec is the one the filter ends; this process sees its command fail.
	{"start a program from a child process", always(refused), allowed, func(e *env) error { return exec.Command("/bin/true").Run() }},
	{"ptrace another process", always(killed), refusedOrErr, func(e *env) error { return rawErr(unix.SYS_PTRACE, unix.PTRACE_SEIZE, uintptr(e.parentPID), 0) }},
	{"mount a file system", always(killed), refusedOrErr, func(e *env) error { return unix.Mount("none", e.rw, "tmpfs", 0, "") }},
	{"create a user namespace", always(killed), refusedOrErr, func(e *env) error { return unix.Unshare(unix.CLONE_NEWUSER) }},
	{"load the BPF interface", always(killed), refusedOrErr, func(e *env) error { return rawErr(unix.SYS_BPF, 0, 0, 0) }},
	{"open an io_uring", always(killed), refusedOrErr, func(e *env) error { return rawErr(unix.SYS_IO_URING_SETUP, 1, 0, 0) }},
	{"open a perf event", always(killed), refusedOrErr, func(e *env) error { return rawErr(unix.SYS_PERF_EVENT_OPEN, 0, 0, 0) }},
	{"create a userfaultfd", always(killed), refusedOrErr, func(e *env) error { return rawErr(unix.SYS_USERFAULTFD, 0, 0, 0) }},
	{"create an anonymous executable file (memfd_create)", always(killed), allowed, func(e *env) error {
		fd, err := unix.MemfdCreate("x", 0)
		if err == nil {
			// #nosec G104 -- The probe measures successful descriptor creation; cleanup cannot change that result.
			unix.Close(fd)
		}
		return err
	}},
	{"load a kernel module", always(killed), refusedOrErr, func(e *env) error { return rawErr(unix.SYS_FINIT_MODULE, 0, 0, 0) }},
	{"open a raw packet socket", always(killed), refusedOrErr, func(e *env) error { return sock(unix.AF_PACKET) }},
	{"open a kernel crypto socket (AF_ALG)", always(killed), refusedOrErr, func(e *env) error { return sock(unix.AF_ALG) }},
	{"open a vsock socket", always(killed), refusedOrErr, func(e *env) error { return sock(unix.AF_VSOCK) }},

	// The process itself.
	{"is not dumpable", always(allowed), refusedOrErr, func(e *env) error {
		if v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err != nil || v != 0 {
			return fmt.Errorf("dumpable=%d", v)
		}
		return nil
	}},
	{"every thread has no_new_privs and the filter", always(allowed), refusedOrErr, func(e *env) error {
		ts, err := sandbox.Threads()
		if err != nil {
			return err
		}
		for _, t := range ts {
			if !t.NoNewPrivs || t.Seccomp != 2 {
				return fmt.Errorf("thread %d: no_new_privs=%v seccomp=%d", t.TID, t.NoNewPrivs, t.Seccomp)
			}
		}
		return nil
	}},
}

// landlockABI is the Landlock version the kernel supports, 0 if none.
func landlockABI() int {
	abi, _, errno := syscall.Syscall(444, 0, 0, 1)
	if errno != 0 {
		return 0
	}
	return int(abi)
}

// refusedOrErr is the control outcome of an action that, unconfined, either works or fails with an ordinary error
// (the caller has no privilege): anything but being killed.
const refusedOrErr outcome = "not killed"

func rawErr(trap, a1, a2, a3 uintptr) error {
	if _, _, errno := syscall.Syscall(trap, a1, a2, a3); errno != 0 {
		return errno
	}
	return nil
}

func sock(domain int) error {
	fd, err := unix.Socket(domain, unix.SOCK_RAW, 0)
	if err == nil {
		// #nosec G104 -- The probe measures socket creation; cleanup cannot turn successful creation into an apparent denial.
		unix.Close(fd)
	}
	return err
}

func dial(port uint16) error {
	d := net.Dialer{Timeout: 2 * time.Second}
	d.SetMultipathTCP(true)
	c, err := d.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err == nil {
		// #nosec G104 -- The probe measures Dial reachability; cleanup cannot change that result.
		c.Close()
	}
	return err
}

func listen(port uint16) error {
	var lc net.ListenConfig
	lc.SetMultipathTCP(true)
	l, err := lc.Listen(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err == nil {
		// #nosec G104 -- The probe measures successful Listen; cleanup cannot change the established access result.
		l.Close()
	}
	return err
}

// httpRoundTrip is what the proxy does all day: resolve a name, listen, accept, answer, connect, read.
func httpRoundTrip(port uint16) error {
	if _, err := net.LookupHost("localhost"); err != nil {
		return err
	}
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	srv := &http.Server{
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       2 * time.Second,
		WriteTimeout:      2 * time.Second,
		IdleTimeout:       2 * time.Second,
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }),
	}
	go srv.Serve(l)
	defer srv.Close()
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		return errors.New("unexpected body")
	}
	return nil
}

func listenerPort(l net.Listener) (uint16, error) {
	p := l.Addr().(*net.TCPAddr).Port
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid probe listener port %d", p)
	}
	return uint16(p), nil
}

// Reserve all three ports together so the kernel cannot return the same port
// twice. Release them only after selection; the child must bind them itself.
func bindPorts() (ports [3]uint16, err error) {
	var listeners []net.Listener
	defer func() {
		for _, l := range listeners {
			err = errors.Join(err, l.Close())
		}
	}()
	for i := range ports {
		l, listenErr := net.Listen("tcp", "127.0.0.1:0")
		if listenErr != nil {
			return ports, listenErr
		}
		listeners = append(listeners, l)
		ports[i], err = listenerPort(l)
		if err != nil {
			return ports, err
		}
	}
	return ports, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: carnical-confine check [-unconfined] [-json] | run <number> [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "check":
		os.Exit(check(os.Args[2:]))
	case "run":
		os.Exit(run(os.Args[2:]))
	}
	fmt.Fprintln(os.Stderr, "carnical-confine: unknown command", os.Args[1])
	os.Exit(2)
}

// check is the parent: it prepares what the actions need, runs each in a child, and compares.
func check(args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	unconfined := fs.Bool("unconfined", false, "the control run: no confinement")
	asJSON := fs.Bool("json", false, "print the results as JSON")
	weaken := fs.String("weaken", "", "apply the confinement without one layer (landlock or seccomp), to show that this check notices")
	fs.Parse(args) // #nosec G104 -- This FlagSet uses ExitOnError; invalid flags terminate with status 2 instead of returning an error.

	dir, err := os.MkdirTemp("", "carnical-confine-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer os.RemoveAll(dir)
	e := &env{ro: filepath.Join(dir, "ro"), rw: filepath.Join(dir, "rw"), other: filepath.Join(dir, "other"), parentPID: os.Getpid(), confine: !*unconfined}
	for _, d := range []string{e.ro, e.rw, e.other} {
		if err := os.Mkdir(d, 0o700); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}
	if err := os.WriteFile(filepath.Join(e.ro, "hello.txt"), []byte("hello"), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := os.WriteFile(filepath.Join(e.other, "secret.txt"), []byte("secret"), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	// Things outside the confinement that the child tries to reach.
	var keep []io.Closer
	serve := func() (uint16, error) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return 0, err
		}
		keep = append(keep, l)
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				// #nosec G104 -- Terminal cleanup of the local probe acceptor connection; it carries no application request or response.
				c.Close()
			}
		}()
		return listenerPort(l)
	}
	if e.allowedPort, err = serve(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if e.forbiddenPort, err = serve(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ports, err := bindPorts()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	e.bindOK, e.bindNo, e.httpPort = ports[0], ports[1], ports[2]
	e.abstract = fmt.Sprintf("carnical-confine-%d", os.Getpid())
	if l, err := net.Listen("unix", "@"+e.abstract); err == nil {
		keep = append(keep, l)
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				// #nosec G104 -- Terminal cleanup of the local probe acceptor connection; it carries no application request or response.
				c.Close()
			}
		}()
	}
	defer func() {
		for _, c := range keep {
			// #nosec G104 -- Terminal cleanup of local probe listeners when the check exits; no outstanding result can be recovered.
			c.Close()
		}
	}()

	self, _ := os.Executable()
	type result struct {
		Action string  `json:"action"`
		Want   outcome `json:"want"`
		Got    outcome `json:"got"`
		OK     bool    `json:"ok"`
		Detail string  `json:"detail,omitempty"`
	}
	var results []result
	abi := landlockABI()
	bad := 0
	for i, a := range actions {
		// #nosec G204 -- self is os.Executable; fixed probe actions and separate argv are generated by this local CLI. No shell is used.
		cmd := exec.Command(self, "run", strconv.Itoa(i),
			"-ro", e.ro, "-rw", e.rw, "-other", e.other, "-allowed-port", strconv.Itoa(int(e.allowedPort)), "-forbidden-port", strconv.Itoa(int(e.forbiddenPort)),
			"-bind-ok", strconv.Itoa(int(e.bindOK)), "-bind-no", strconv.Itoa(int(e.bindNo)), "-http-port", strconv.Itoa(int(e.httpPort)), "-abstract", e.abstract, "-parent", strconv.Itoa(e.parentPID),
			"-confine="+strconv.FormatBool(e.confine), "-weaken", *weaken)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		got, detail := allowed, strings.TrimSpace(out.String())
		if ee := (*exec.ExitError)(nil); errors.As(err, &ee) {
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() && ws.Signal() == syscall.SIGSYS {
				got, detail = killed, "ended by the system-call filter (SIGSYS)"
			} else if ee.ExitCode() == 3 {
				got = refused
			} else {
				got, detail = "failed", fmt.Sprintf("exit %d: %s", ee.ExitCode(), detail)
			}
		} else if err != nil {
			got, detail = "failed", err.Error()
		}
		results = append(results, result{Action: a.name, Got: got, Detail: detail})
	}
	for i, a := range actions {
		want := a.control
		if e.confine {
			want = a.confined(abi)
		}
		r := &results[i]
		r.Want = want
		r.OK = r.Got == want || (want == refusedOrErr && r.Got != killed && r.Got != "failed")
		if want == refusedOrErr && r.Got == killed {
			r.OK = false
		}
		if !r.OK {
			bad++
		}
	}
	if *asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(struct {
			Confined bool     `json:"confined"`
			ABI      int      `json:"landlock_abi"`
			Results  []result `json:"results"`
			Failures int      `json:"failures"`
		}{e.confine, abi, results, bad}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	} else {
		mode := "confined"
		if !e.confine {
			mode = "unconfined (control)"
		}
		fmt.Printf("%s, Landlock ABI %d\n", mode, abi)
		for _, r := range results {
			mark := "ok  "
			if !r.OK {
				mark = "FAIL"
			}
			fmt.Printf("%s  %-52s want %-10s got %s", mark, r.Action, r.Want, r.Got)
			if !r.OK && r.Detail != "" {
				fmt.Printf("   (%s)", r.Detail)
			}
			fmt.Println()
		}
		fmt.Printf("%d of %d as expected\n", len(results)-bad, len(results))
	}
	if bad > 0 {
		return 1
	}
	return 0
}

// run is the child: confine (or not), do one action, say what happened.
func run(args []string) int {
	if len(args) < 1 {
		return 2
	}
	idx, err := strconv.Atoi(args[0])
	if err != nil || idx < 0 || idx >= len(actions) {
		return 2
	}
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	e := &env{}
	fs.StringVar(&e.ro, "ro", "", "")
	fs.StringVar(&e.rw, "rw", "", "")
	fs.StringVar(&e.other, "other", "", "")
	for _, port := range []struct {
		name string
		dst  *uint16
	}{
		{"allowed-port", &e.allowedPort}, {"forbidden-port", &e.forbiddenPort},
		{"bind-ok", &e.bindOK}, {"bind-no", &e.bindNo}, {"http-port", &e.httpPort},
	} {
		fs.Func(port.name, "probe port (1..65535)", func(value string) error {
			n, err := strconv.ParseUint(value, 10, 16)
			if err != nil || n == 0 {
				return fmt.Errorf("invalid probe port %q", value)
			}
			*port.dst = uint16(n)
			return nil
		})
	}
	fs.StringVar(&e.abstract, "abstract", "", "")
	fs.IntVar(&e.parentPID, "parent", 0, "")
	fs.BoolVar(&e.confine, "confine", true, "")
	weaken := fs.String("weaken", "", "")
	fs.Parse(args[1:]) // #nosec G104 -- This FlagSet uses ExitOnError; invalid flags terminate before any probe runs.
	seen := make(map[uint16]bool)
	for _, port := range []uint16{e.allowedPort, e.forbiddenPort, e.bindOK, e.bindNo, e.httpPort} {
		if port == 0 || seen[port] {
			fmt.Fprintln(os.Stderr, "probe ports must be nonzero and distinct")
			return 2
		}
		seen[port] = true
	}

	// Threads that exist before the confinement is applied: it must reach them too.
	var ready, hold sync.WaitGroup
	release := make(chan struct{})
	for i := 0; i < 8; i++ {
		ready.Add(1)
		hold.Add(1)
		go func() {
			runtime.LockOSThread()
			ready.Done()
			<-release
			hold.Done()
		}()
	}
	ready.Wait()

	if e.confine {
		rep, err := sandbox.Apply(sandbox.Policy{
			ReadOnly:   []string{e.ro},
			ReadWrite:  []string{e.rw},
			BindTCP:    []uint16{e.bindOK, e.httpPort},
			ConnectTCP: []uint16{e.allowedPort, e.httpPort},
			Require:    false,
			Skip:       strings.FieldsFunc(*weaken, func(r rune) bool { return r == ',' }),
		})
		if err != nil {
			fmt.Printf("abi=0 could not confine: %v\n", err)
			return 4
		}
		fmt.Printf("abi=%d notes=%v\n", rep.LandlockABI, rep.Notes)
	} else {
		abi := 0
		if _, _, errno := syscall.Syscall(444, 0, 0, 1); errno == 0 {
			r, _, _ := syscall.Syscall(444, 0, 0, 1)
			abi = int(r)
		}
		fmt.Printf("abi=%d unconfined\n", abi)
	}
	err = actions[idx].run(e)
	close(release)
	hold.Wait()
	if err != nil {
		fmt.Printf("%v\n", err)
		return 3
	}
	return 0
}
