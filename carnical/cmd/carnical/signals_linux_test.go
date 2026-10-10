//go:build linux

package main

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// A hang-up drains like SIGTERM (the proxy has nothing to reload), and once the proxy is draining a second signal ends it at
// once instead of being swallowed for the whole shutdown budget.
func TestSignalsDrainAndASecondOneEndsTheProxyAtOnce(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "carnical")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer app.Close()

	start := func(t *testing.T, extra ...string) (*exec.Cmd, *lockedLog, chan error) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		ln.Close()
		logs := &lockedLog{}
		cmd := exec.Command(bin, append([]string{"-listen", addr, "-upstream", app.URL, "-origin-allow", "127.0.0.0/8"}, extra...)...)
		cmd.Stdout, cmd.Stderr = logs, logs
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		exited := make(chan error, 1)
		go func() { exited <- cmd.Wait() }()
		t.Cleanup(func() {
			cmd.Process.Kill()
			<-exited
		})
		logs.waitFor(t, `"msg":"listening"`, exited)
		return cmd, logs, exited
	}

	t.Run("a hang-up drains and exits cleanly", func(t *testing.T) {
		cmd, logs, exited := start(t)
		if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-exited:
			exited <- err // for the cleanup
			if err != nil {
				t.Fatalf("exit after a hang-up: %v\n%s", err, logs)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("still running 10 s after a hang-up\n%s", logs)
		}
		for _, want := range []string{`"msg":"draining"`, `"msg":"shutdown complete"`} {
			if !strings.Contains(logs.String(), want) {
				t.Errorf("no %s after a hang-up\n%s", want, logs)
			}
		}
	})

	t.Run("a second signal while draining ends the proxy", func(t *testing.T) {
		cmd, logs, exited := start(t, "-drain-delay", "50s", "-shutdown-timeout", "1m")
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		logs.waitFor(t, `"msg":"draining"`, exited)
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-exited:
			exited <- err
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGTERM {
				t.Fatalf("after a second SIGTERM: %v, want death by that signal\n%s", err, logs)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("a second SIGTERM did not end a draining proxy within 5 s\n%s", logs)
		}
	})
}

// lockedLog collects a child's output while the test reads it.
type lockedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *lockedLog) waitFor(t *testing.T, want string, exited chan error) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(l.String(), want) {
		select {
		case err := <-exited:
			exited <- err
			t.Fatalf("the proxy exited (%v) before logging %s\n%s", err, want, l)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s within 20 s\n%s", want, l)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
