// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

type lifecycleOptions struct {
	healthAddress string
	drain         time.Duration
	shutdown      time.Duration
	details       bool // client addresses in net/http's own error lines
}

// serverErrors takes the lines a server's net/http writes about connections ("TLS handshake error from 192.0.2.1:5678: EOF")
// into the JSON log. Each kind of line is logged at most once a second, with a count of the rest, and cut to a bounded length,
// so a scanner can neither flood the log nor hide a handler's panic or a failing accept behind its handshake errors. Addresses
// and what the client sent (quoted in the line) are left out unless details are asked for, as everywhere else.
type serverErrors struct {
	log     *slog.Logger
	details bool
	windows [3]errorWindow // indexed by errorKinds
	now     func() time.Time
}

type errorWindow struct{ second, dropped atomic.Int64 }

var errorKinds = [3]string{"connection", "panic", "accept"}

const (
	maxErrorLine = 512     // a connection or accept error
	maxPanicLine = 8 << 10 // a panic, with enough of its stack to find where
)

func newServerErrors(logger *slog.Logger, details bool) *serverErrors {
	return &serverErrors{log: logger, details: details, now: time.Now}
}

// errorKind tells the lines apart by how net/http begins them: what a client sends only ever comes after that.
func errorKind(line []byte) int {
	switch {
	case bytes.HasPrefix(line, []byte("http: panic serving ")) || bytes.HasPrefix(line, []byte("http2: panic serving ")):
		return 1
	case bytes.HasPrefix(line, []byte("http: Accept error: ")):
		return 2
	}
	return 0
}

func (s *serverErrors) Write(p []byte) (int, error) {
	kind := errorKind(bytes.TrimSpace(p))
	w := &s.windows[kind]
	second := s.now().Unix()
	if previous := w.second.Load(); second == previous || !w.second.CompareAndSwap(previous, second) {
		w.dropped.Add(1) // counted before anything is copied, so a flood costs little
		return len(p), nil
	}
	line := strings.TrimSpace(string(p))
	if !s.details {
		line = redactAddresses(clientDataRe.ReplaceAllString(line, `"[client data]"`))
	}
	limit, cut := maxErrorLine, 0
	if kind == 1 {
		limit = maxPanicLine
	}
	if len(line) > limit { // cut after redaction, so no part of an address is left
		end := limit
		for end > 0 && !utf8.RuneStart(line[end]) {
			end--
		}
		line, cut = line[:end], len(line)-end
	}
	s.log.Warn("server error", "kind", errorKinds[kind], "error", line, "dropped", w.dropped.Swap(0), "cut_bytes", cut)
	return len(p), nil
}

// flush reports what was counted but not yet logged, as the server stops.
func (s *serverErrors) flush() {
	for i := range s.windows {
		if n := s.windows[i].dropped.Swap(0); n > 0 {
			s.log.Warn("server errors not logged", "kind", errorKinds[i], "dropped", n)
		}
	}
}

// clientDataRe is a Go-quoted string: in net/http's and crypto/tls's lines that is what the client sent (the protocols it
// asked for, a greeting that was not HTTP/2).
var clientDataRe = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

// addressRe finds what may be an address: a bracketed IPv6 address with or without a port, or a run of the characters
// addresses, zones and ports are written with. A connection error names both ends as one word ("read tcp
// 192.0.2.1:443->198.51.100.7:5678: i/o timeout"), so words are not enough. Each candidate is parsed before it is replaced.
var addressRe = regexp.MustCompile(`\[[0-9A-Za-z:.%_-]+\](?::\d+)?|[0-9A-Za-z:.%_]+`)

func redactAddresses(line string) string {
	return addressRe.ReplaceAllStringFunc(line, func(w string) string {
		// An IPv6 address can end in a colon ("2001:db8::"), so a trailing ':' or '.' that belongs to the sentence is set
		// aside one at a time: the word whole, then without its last character, and so on.
		for core := w; core != ""; core = core[:len(core)-1] {
			_, errPort := netip.ParseAddrPort(core)
			_, errAddr := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(core, "["), "]"))
			if errPort == nil || errAddr == nil {
				return "[address]" + w[len(core):]
			}
			if last := core[len(core)-1]; last != ':' && last != '.' {
				break
			}
		}
		return w
	})
}

// validate runs in both check and serving modes. Health is deliberately confined
// to a numeric loopback address; it is never mounted on the visitor listener.
func (o lifecycleOptions) validate() error {
	if o.shutdown < 100*time.Millisecond || o.shutdown > 10*time.Minute {
		return errors.New("-shutdown-timeout must be between 100ms and 10m")
	}
	if o.drain < 0 || o.drain > time.Minute || o.drain >= o.shutdown {
		return errors.New("-drain-delay must be between 0 and 1m and less than -shutdown-timeout")
	}
	if o.healthAddress != "" {
		if _, err := loopbackHealthAddress(o.healthAddress); err != nil {
			return err
		}
	}
	return nil
}

func loopbackHealthAddress(value string) (string, error) {
	address, err := netip.ParseAddrPort(value)
	if err != nil || !address.Addr().IsLoopback() || address.Addr().Zone() != "" || address.Port() == 0 {
		return "", errors.New("-health-listen must be a numeric loopback address with a nonzero port")
	}
	return netip.AddrPortFrom(address.Addr().Unmap(), address.Port()).String(), nil
}

type runtimeHealth struct {
	started  atomic.Bool
	draining atomic.Bool
	// available checks only local state, never origin or LAPI network I/O.
	available func() bool
}

func (h *runtimeHealth) server(address string) *http.Server {
	return &http.Server{
		Addr: address, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second,
		WriteTimeout: 2 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4 << 10,
		DisableGeneralOptionsHandler: true,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			if r.Host != address {
				http.Error(w, "invalid health host", http.StatusForbidden)
				return
			}
			if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
				r.Close = true
				w.Header().Set("Connection", "close")
				http.Error(w, "health requests must not have a body", http.StatusBadRequest)
				return
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			switch r.RequestURI {
			case "/livez":
				w.WriteHeader(http.StatusOK)
			case "/readyz":
				if !h.started.Load() || h.draining.Load() || (h.available != nil && !h.available()) {
					http.Error(w, "not ready", http.StatusServiceUnavailable)
					return
				}
				w.WriteHeader(http.StatusOK)
			default:
				http.NotFound(w, r)
			}
		}),
	}
}

// probeHealth is also usable in images without a shell or curl. It cannot use an
// environment proxy, follow redirects, resolve a hostname or inspect a website.
func probeHealth(kind, address string) error {
	if kind != "live" && kind != "ready" {
		return errors.New("-probe must be live or ready")
	}
	if address == "" {
		return errors.New("-probe requires -health-listen")
	}
	address, err := loopbackHealthAddress(address)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, "http://"+address+"/"+kind+"z", nil)
	if err != nil {
		return errors.New("cannot construct health probe")
	}
	transport := &http.Transport{Proxy: nil, MaxResponseHeaderBytes: 4 << 10, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	response, err := transport.RoundTrip(request)
	if err != nil {
		return errors.New("health probe unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health probe returned HTTP %d", response.StatusCode)
	}
	return nil
}

type servingListener struct {
	net.Listener
	once   sync.Once
	health *runtimeHealth
}

func (l *servingListener) Accept() (net.Conn, error) {
	// ServeTLS has validated its TLS configuration and initialized HTTP/2 before
	// it enters Accept. No readiness is published merely because net.Listen ran.
	l.once.Do(func() { l.health.started.Store(true) })
	return l.Listener.Accept()
}

type serveResult struct {
	listener string
	err      error
}

// serveRuntime owns all serving goroutines and closes both listeners on any
// failure. The shutdown budget includes the readiness withdrawal delay.
func serveRuntime(ctx context.Context, server *http.Server, listener net.Listener, healthListener net.Listener,
	health *runtimeHealth, options lifecycleOptions, log *slog.Logger) (err error) {
	done := make(chan serveResult, 2)
	count, received := 1, 0
	// net/http's own lines go to the JSON log, each server's under its name.
	serverLogs := []*serverErrors{newServerErrors(log.With("server", "visitor"), options.details)}
	server.ErrorLog = stdlog.New(serverLogs[0], "", 0)
	var healthServer *http.Server
	if healthListener != nil {
		count++
		healthServer = health.server(healthListener.Addr().String())
		serverLogs = append(serverLogs, newServerErrors(log.With("server", "health"), options.details))
		healthServer.ErrorLog = stdlog.New(serverLogs[1], "", 0)
		go func() { done <- serveResult{"health", healthServer.Serve(healthListener)} }()
	}
	// Close aborts ordinary active requests when Shutdown exhausts its budget.
	// Explicitly opted-in upgraded connections terminate when the CLI exits.
	defer func() {
		defer func() {
			for _, l := range serverLogs {
				l.flush()
			}
		}()
		health.draining.Store(true)
		err = errors.Join(err, server.Close())
		if healthServer != nil {
			err = errors.Join(err, healthServer.Close())
		}
		for _, ln := range []net.Listener{listener, healthListener} {
			if ln != nil {
				if closeErr := ln.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
					err = errors.Join(err, closeErr)
				}
			}
		}
		for received < count {
			<-done
			received++
		}
	}()
	go func() {
		ln := &servingListener{Listener: listener, health: health}
		if server.TLSConfig != nil {
			done <- serveResult{"visitor", server.ServeTLS(ln, "", "")}
		} else {
			done <- serveResult{"visitor", server.Serve(ln)}
		}
	}()
	unexpected := func(result serveResult) error {
		if result.err == nil {
			result.err = errors.New("listener stopped without an error")
		}
		return fmt.Errorf("%s listener stopped: %w", result.listener, result.err)
	}
	select {
	case result := <-done:
		received++
		return unexpected(result)
	case <-ctx.Done():
	}
	health.draining.Store(true)
	shutdown, cancel := context.WithTimeout(context.Background(), options.shutdown)
	defer cancel()
	log.Info("draining", "delay", options.drain.String(), "shutdown_timeout", options.shutdown.String())
	if options.drain > 0 {
		delay := time.NewTimer(options.drain)
		defer delay.Stop()
		select {
		case <-delay.C:
		case result := <-done:
			received++
			return unexpected(result)
		case <-shutdown.Done():
		}
	}
	// Requests reaching the edge during load-balancer propagation still use the
	// complete WAF. Shutdown then stops accepting and waits for active requests.
	if err := server.Shutdown(shutdown); err != nil {
		log.Warn("shutdown incomplete", "deadline_exceeded", errors.Is(err, context.DeadlineExceeded))
		return err
	}
	log.Info("shutdown complete")
	return nil
}
