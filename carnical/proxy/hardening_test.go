// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/YurilLAB/coraza/carnical/crowdsec"
	"github.com/YurilLAB/coraza/carnical/crs"
)

// Everything here that says so runs with the rule set OFF. These protections must hold without it: they are the part
// that does not depend on a rule recognising an attack.
func ruleSetOff(c *Config) { c.CRS.Mode = crs.ModeOff }

type refusals struct {
	mu  sync.Mutex
	ids []int
}

func (r *refusals) record(m Match) { r.mu.Lock(); r.ids = append(r.ids, m.RuleID); r.mu.Unlock() }
func (r *refusals) last() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.ids) == 0 {
		return 0
	}
	return r.ids[len(r.ids)-1]
}

func TestPathPolicy(t *testing.T) {
	strict := PathPolicy{}
	tests := []struct {
		name, path string
		policy     PathPolicy
		ok         bool
	}{
		{"root", "/", strict, true},
		{"nested", "/a/b/c", strict, true},
		{"a file", "/index.php", strict, true},
		{"unreserved characters", "/a.b-c_d~e", strict, true},
		{"a segment of dots that is not a dot segment", "/a/.../b", strict, true},
		{"dots inside a name", "/a/b..c", strict, true},
		{"an escaped multibyte character", "/caf%C3%A9", strict, true},
		{"an escaped space", "/a%20b", strict, true},
		{"an escaped tilde", "/a%7Eb", strict, true},
		{"an encoded slash", "/a%2fb", strict, false},
		{"an encoded slash in capitals", "/a%2Fb", strict, false},
		{"an encoded backslash", "/a%5cb", strict, false},
		{"an encoded question mark", "/a%3fb", strict, false},
		{"an encoded hash", "/a%23b", strict, false},
		{"an encoded NUL", "/a%00b", strict, false},
		{"an encoded percent (double decoding)", "/a%25b", strict, false},
		{"an encoded newline", "/a%0ab", strict, false},
		{"an encoded DEL", "/a%7fb", strict, false},
		{"an escaped letter", "/%77p-admin/", strict, false},
		{"an escaped dot", "/a%2Eb", strict, false},
		{"encoded dot segments", "/%2e%2e/etc/passwd", strict, false},
		{"a dot segment", "/a/./b", strict, false},
		{"a parent segment", "/a/../b", strict, false},
		{"a trailing parent segment", "/a/..", strict, false},
		{"a path parameter", "/a;jsessionid=1", strict, false},
		{"a backslash", "/a" + string(rune(92)) + "b", strict, false},
		{"a truncated escape", "/a%", strict, false},
		{"a half escape", "/a%2", strict, false},
		{"a malformed escape", "/a%zz", strict, false},
		{"a space", "/a b", strict, false},
		{"a non-ASCII byte", "/é", strict, false},
		{"an encoded slash, allowed", "/a%2fb", PathPolicy{AllowEncodedSlash: true}, true},
		{"an encoded backslash, allowed", "/a%5Cb", PathPolicy{AllowEncodedSlash: true}, true},
		{"an encoded NUL stays refused when slashes are allowed", "/a%00b", PathPolicy{AllowEncodedSlash: true}, false},
		{"a path parameter, allowed", "/a;x=1", PathPolicy{AllowPathParams: true}, true},
		{"dot segments stay refused when parameters are allowed", "/a/../b", PathPolicy{AllowPathParams: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.policy.check(tt.path); (err == nil) != tt.ok {
				t.Fatalf("check(%q) = %v, want ok=%v", tt.path, err, tt.ok)
			}
		})
	}
}

func TestRefusalsHoldWithTheRuleSetOffAndAreRecorded(t *testing.T) {
	tests := []struct {
		name    string
		request string
		change  func(*Config)
		want    int
		id      int
	}{
		{"an ordinary request", get("/page"), nil, 200, 0},
		{"an encoded slash", get("/a%2fb"), nil, 400, idPathNotCanon},
		{"a dot segment", get("/a/../admin"), nil, 400, idPathNotCanon},
		{"a name the site does not answer to", get("/page"), func(c *Config) { c.AllowedHosts = []string{"www.other.test"} }, 421, idHostNotAllowed},
		{"a name it does answer to", get("/page"), func(c *Config) { c.AllowedHosts = []string{"SHOP.example.test."} }, 200, 0},
		{"a name with a port", "GET /page HTTP/1.1\r\nHost: shop.example.test:8443\r\nConnection: close\r\n\r\n", func(c *Config) { c.AllowedHosts = []string{"shop.example.test"} }, 200, 0},
		{"a gzip request body", get("/page", "Content-Encoding: gzip\r\n"), nil, 415, idRequestEncoding},
		{"an identity request encoding", get("/page", "Content-Encoding: identity\r\n"), nil, 200, 0},
		{"two Content-Type headers", get("/page", "Content-Type: text/plain\r\n", "Content-Type: application/json\r\n"), nil, 400, idAmbiguousType},
		{"a header the site does not accept", get("/page", "Next-Action: abc\r\n"), func(c *Config) { c.DenyHeaders = []string{"next-action"} }, 400, idInternalHeader},
		{"the same header with underscores", get("/page", "Next_Action: abc\r\n"), func(c *Config) { c.DenyHeaders = []string{"Next-Action"} }, 400, idInternalHeader},
		{"that header on a site that did not ask", get("/page", "Next-Action: abc\r\n"), nil, 200, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var seen refusals
			s := start(t, func(c *Config) {
				ruleSetOff(c)
				c.OnMatch = seen.record
				if tt.change != nil {
					tt.change(c)
				}
			})
			status, _ := s.raw(t, tt.request)
			if status != tt.want {
				t.Fatalf("status %d, want %d", status, tt.want)
			}
			if got := len(s.up.requests()) > 0; got != (tt.want == 200) {
				t.Fatalf("reached the application: %v", got)
			}
			if seen.last() != tt.id {
				t.Fatalf("recorded id %d, want %d", seen.last(), tt.id)
			}
		})
	}
	// The existing refusal table owns policy wiring. CrowdSec requires an
	// external decision stream and verified client identity, not a SecLang profile.
	t.Run("CrowdSec verified visitors", func(t *testing.T) {
		cases := []struct {
			name, scope, value, forwarded string
			trusted, sync                 bool
			status, id                    int
		}{
			{"direct ban", "Range", "127.0.0.0/8", "", false, true, 403, idCrowdSecBan},
			{"clean direct visitor", "Ip", "192.0.2.9", "", false, true, 200, 0},
			{"untrusted claimed banned address", "Ip", "192.0.2.9", "192.0.2.9", false, true, 200, 0},
			{"untrusted claimed clean address", "Range", "127.0.0.0/8", "198.51.100.9", false, true, 403, idCrowdSecBan},
			{"trusted IPv4 visitor", "Ip", "192.0.2.9", "192.0.2.9", true, true, 403, idCrowdSecBan},
			{"trusted IPv6 visitor", "Range", "2001:db8::/64", "2001:db8::9", true, true, 403, idCrowdSecBan},
			{"trusted clean visitor", "Ip", "192.0.2.9", "198.51.100.9", true, true, 200, 0},
			{"ban covers peer but not visitor", "Range", "127.0.0.0/8", "198.51.100.9", true, true, 200, 0},
			{"spoofed left entry", "Ip", "192.0.2.9", "198.51.100.9, 192.0.2.9", true, true, 403, idCrowdSecBan},
			{"missing snapshot", "Ip", "192.0.2.9", "", false, false, 503, idCrowdSecUnavailable},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintf(w, `{"new":[{"id":1,"scope":%q,"value":%q,"type":"ban","duration":"1h"}],"deleted":[]}`, tc.scope, tc.value)
				}))
				defer api.Close()
				cs, err := crowdsec.New(crowdsec.Config{URL: api.URL, APIKey: "proxy-test-bouncer-key"})
				if err != nil {
					t.Fatal(err)
				}
				defer cs.Close()
				if tc.sync {
					if err := cs.Sync(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				var seen refusals
				s := start(t, func(c *Config) {
					ruleSetOff(c)
					c.CrowdSec = cs
					c.OnMatch = seen.record
					if tc.trusted {
						c.TrustedProxies = loopback.Allow
					}
				})
				headers := []string{}
				if tc.forwarded != "" {
					headers = append(headers, "X-Forwarded-For: "+tc.forwarded+"\r\n")
				}
				status, _ := s.raw(t, get("/page", headers...))
				if status != tc.status || seen.last() != tc.id || (len(s.up.requests()) > 0) != (tc.status == 200) {
					t.Fatalf("status %d id %d reached origin %v", status, seen.last(), len(s.up.requests()) > 0)
				}
			})
		}
	})
}

func TestFrameworkControlHeadersNeverReachTheApplication(t *testing.T) {
	names := []struct {
		name     string
		override bool
	}{
		{"X-Middleware-Subrequest", false}, {"X_Middleware_Subrequest", false}, {"X-Middleware-Prefetch", false},
		{"X-Invoke-Path", false}, {"X-Invoke-Status", false}, {"X-Matched-Path", false}, {"X-Now-Route-Matches", false},
		{"X-HTTP-Method-Override", true}, {"X_HTTP_Method_Override", true}, {"X-Method-Override", true},
		{"X-HTTP-Method", true}, {"X_HTTP_Method", true}, {"X-Nextjs-Data", false},
	}
	for _, tc := range names {
		t.Run(tc.name, func(t *testing.T) {
			var seen matches
			s := start(t, func(c *Config) { ruleSetOff(c); c.OnMatch = seen.record })
			status, _ := s.raw(t, get("/page", tc.name+": middleware:middleware:middleware\r\n", "X-Application-Token: keep\r\n"))
			got := s.up.requests()
			if tc.override {
				if status != 400 || len(got) != 0 || len(seen.all()) != 1 || seen.all()[0].RuleID != idMethodOverride {
					t.Fatalf("override refusal: status %d, origin %d, findings %+v", status, len(got), seen.all())
				}
				return
			}
			if status != 200 || len(got) != 1 {
				t.Fatalf("status %d, %d requests", status, len(got))
			}
			dashed := strings.ReplaceAll(strings.ToLower(tc.name), "_", "-")
			for header := range got[0].Header {
				if strings.ReplaceAll(strings.ToLower(header), "_", "-") == dashed {
					t.Fatalf("%s reached the application", header)
				}
			}
			if got[0].Header.Get("X-Application-Token") == "" {
				t.Fatal("an ordinary header was dropped with them")
			}
		})
	}
}

func TestAHeaderNamedInConnectionCannotRemoveTheProxysOwn(t *testing.T) {
	s := start(t, ruleSetOff)
	status, _ := s.raw(t, get("/page", "Connection: close, X-Forwarded-For, X-Real-IP, X-Forwarded-Proto\r\n"))
	got := s.up.requests()
	if status != 200 || len(got) != 1 {
		t.Fatalf("status %d, %d requests", status, len(got))
	}
	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip", "X-Forwarded-Proto"} {
		if got[0].Header.Get(h) == "" {
			t.Errorf("%s was removed because the client listed it in Connection", h)
		}
	}
}

// The classic smuggling shapes. The proxy re-serialises every request it forwards and the engine inspects each one it
// parses, so whatever is hidden in a body either stays inert body text or is parsed as a request of its own and
// inspected like any other. What must never happen is an attack reaching the application as a request without having
// been looked at. Here the hidden request is an attack the rule set blocks, in blocking mode.
func TestSmuggledAttacksAreStillInspected(t *testing.T) {
	hidden := "GET /x?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\nHost: shop.example.test\r\nUser-Agent: Mozilla/5.0 Chrome/120\r\nAccept: text/html\r\n\r\n"
	post := func(headers string, body string) string {
		return "POST /submit HTTP/1.1\r\n" + preamble + "Content-Type: text/plain\r\n" + headers + "\r\n" + body
	}
	chunkedHidden := "0\r\n\r\n" + hidden
	tests := map[string]string{
		"CL.TE":                     post("Content-Length: 4\r\nTransfer-Encoding: chunked\r\n", "5c\r\n"+hidden+"\r\n0\r\n\r\n"),
		"TE.CL":                     post("Content-Length: 4\r\nTransfer-Encoding: chunked\r\n", chunkedHidden),
		"TE.TE obfuscated":          post("Content-Length: 4\r\nTransfer-Encoding: xchunked\r\n", chunkedHidden),
		"TE with a space before :":  post("Content-Length: 4\r\nTransfer-Encoding : chunked\r\n", chunkedHidden),
		"TE tab after :":            post("Content-Length: 4\r\nTransfer-Encoding:\tchunked\r\n", chunkedHidden),
		"two Content-Length":        post("Content-Length: 4\r\nContent-Length: 60\r\n", "a=1&"+hidden),
		"Content-Length with plus":  post("Content-Length: +4\r\n", "a=1&"+hidden),
		"CL.0":                      post("Content-Length: "+strconv.Itoa(len(hidden))+"\r\n", hidden),
		"bare LF in a chunk header": post("Transfer-Encoding: chunked\r\n", "0\n\r\n"+hidden),
	}
	for name, request := range tests {
		t.Run(name, func(t *testing.T) {
			s := start(t, nil) // the rule set on, blocking
			s.raw(t, request)
			for _, got := range s.up.requests() {
				uri := strings.ToLower(got.RequestURI)
				if strings.Contains(uri, "script") || strings.Contains(uri, "%3c") {
					t.Fatalf("an attack hidden in a body reached the application as a request: %q", got.RequestURI)
				}
			}
		})
	}
}

func TestARequestWithABodyDoesNotShareItsApplicationConnection(t *testing.T) {
	var opened, closed atomic.Int32
	app := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	app.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		switch s {
		case http.StateNew:
			opened.Add(1)
		case http.StateClosed:
			closed.Add(1)
		}
	}
	app.Start()
	defer app.Close()
	s := start(t, func(c *Config) {
		ruleSetOff(c)
		c.Upstream = mustURL(app.URL)
	})
	for i := 0; i < 3; i++ {
		s.raw(t, get("/page"))
	}
	if opened.Load() != 1 || closed.Load() != 0 {
		t.Fatalf("three requests without a body: %d connections opened, %d closed; want 1 and 0 (the control: the connection is reused)", opened.Load(), closed.Load())
	}
	for i := 0; i < 3; i++ {
		s.raw(t, post("a=1"))
	}
	deadline := time.Now().Add(3 * time.Second)
	for closed.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if closed.Load() != 3 {
		t.Fatalf("three requests with a body closed %d application connections, want 3 (each one's own, so nothing is left on a reused connection)", closed.Load())
	}
}

func TestResponsePolicy(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		policy ResponsePolicy
		check  func(t *testing.T, h http.Header)
	}{
		{"nosniff is added", "/page", ResponsePolicy{}, func(t *testing.T, h http.Header) {
			if h.Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("X-Content-Type-Options = %q", h.Get("X-Content-Type-Options"))
			}
		}},
		{"banners are removed", "/banner", ResponsePolicy{}, func(t *testing.T, h http.Header) {
			if h.Get("X-Powered-By") != "" || h.Get("Server") != "" {
				t.Fatalf("banners remain: %q %q", h.Get("X-Powered-By"), h.Get("Server"))
			}
		}},
		{"banners are kept when asked", "/banner", ResponsePolicy{KeepBanners: true}, func(t *testing.T, h http.Header) {
			if h.Get("X-Powered-By") == "" {
				t.Fatal("the banner was removed although asked to keep it")
			}
		}},
		{"a cookie makes a response private", "/set-cookie", ResponsePolicy{}, func(t *testing.T, h http.Header) {
			if h.Get("Cache-Control") != "private, no-store" {
				t.Fatalf("Cache-Control = %q", h.Get("Cache-Control"))
			}
		}},
		{"a cookie leaves caching alone when asked", "/set-cookie", ResponsePolicy{KeepCaching: true}, func(t *testing.T, h http.Header) {
			if h.Get("Cache-Control") != "" {
				t.Fatalf("Cache-Control = %q", h.Get("Cache-Control"))
			}
		}},
		{"HTML at a stylesheet's address is not cached", "/account/profile.css", ResponsePolicy{}, func(t *testing.T, h http.Header) {
			if h.Get("Cache-Control") != "private, no-store" {
				t.Fatalf("Cache-Control = %q", h.Get("Cache-Control"))
			}
		}},
		{"an ordinary page is left to the application", "/page", ResponsePolicy{}, func(t *testing.T, h http.Header) {
			if h.Get("Cache-Control") != "" {
				t.Fatalf("Cache-Control = %q on an ordinary page", h.Get("Cache-Control"))
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := start(t, func(c *Config) { ruleSetOff(c); c.Responses = tt.policy })
			_, reply := s.raw(t, get(tt.path))
			resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(reply)), nil)
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, resp.Header)
		})
	}
}

func multipartBody(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString("--XX\r\n" + p + "\r\n")
	}
	b.WriteString("--XX--\r\n")
	return b.String()
}

func filePart(name, content string) string {
	return "Content-Disposition: form-data; name=\"f\"; filename=\"" + name + "\"\r\nContent-Type: application/octet-stream\r\n\r\n" + content
}

func uploadRequest(body string) string {
	return "POST /upload HTTP/1.1\r\n" + preamble + "Content-Type: multipart/form-data; boundary=XX\r\nContent-Length: " + strconv.Itoa(len(body)) +
		"\r\nConnection: close\r\n\r\n" + body
}

func TestUploadPolicy(t *testing.T) {
	jpeg := "\xff\xd8\xff\xe0\x00\x10JFIF\x00 an ordinary picture \xff\xd9"
	shell := "GIF89a<?php system($_GET['c']); ?>"
	tests := []struct {
		name    string
		body    string
		policy  UploadPolicy
		refused int // the id, or 0
	}{
		{"a picture", multipartBody(filePart("photo.jpg", jpeg)), UploadPolicy{}, 0},
		{"a document with a long name", multipartBody(filePart("Quarterly report - final (2).pdf", "%PDF-1.7 text")), UploadPolicy{}, 0},
		{"a text field mentioning php", multipartBody("Content-Disposition: form-data; name=\"comment\"\r\n\r\nuse <?php echo 1; ?> in your template"), UploadPolicy{}, 0},
		{"an XML file", multipartBody(filePart("data.xml", "<?xml version=\"1.0\"?><a/>")), UploadPolicy{}, 0},
		{"a script name", multipartBody(filePart("shell.php", "x")), UploadPolicy{}, idUploadName},
		{"a script name in capitals", multipartBody(filePart("SHELL.PHP", "x")), UploadPolicy{}, idUploadName},
		{"a double extension", multipartBody(filePart("shell.php.jpg", jpeg)), UploadPolicy{}, idUploadName},
		{"a trailing dot", multipartBody(filePart("shell.php.", "x")), UploadPolicy{}, idUploadName},
		{"a trailing space", multipartBody(filePart("shell.php ", "x")), UploadPolicy{}, idUploadName},
		{"a semicolon trick", multipartBody(filePart("shell.asp;.jpg", "x")), UploadPolicy{}, idUploadName},
		{"phtml", multipartBody(filePart("a.phtml", "x")), UploadPolicy{}, idUploadName},
		{"php5", multipartBody(filePart("a.php5", "x")), UploadPolicy{}, idUploadName},
		{"jsp", multipartBody(filePart("a.jsp", "x")), UploadPolicy{}, idUploadName},
		{"a NUL in the name, percent-encoded", multipartBody(filePart("shell.php%00.jpg", jpeg)), UploadPolicy{}, idUploadName},
		{"an NTFS stream", multipartBody(filePart("shell.php::$DATA", "x")), UploadPolicy{}, idUploadName},
		{"htaccess", multipartBody(filePart(".htaccess", "AddType application/x-httpd-php .jpg")), UploadPolicy{}, idUploadName},
		{"web.config", multipartBody(filePart("web.config", "<configuration/>")), UploadPolicy{}, idUploadName},
		{"a path in the name", multipartBody(filePart("..\\..\\shell.php", "x")), UploadPolicy{}, idUploadName},
		{"an RFC 5987 name", multipartBody("Content-Disposition: form-data; name=\"f\"; filename*=UTF-8''%73hell.php\r\n\r\nx"), UploadPolicy{}, idUploadName},
		{"an unquoted name", multipartBody("Content-Disposition: form-data; name=f; filename=shell.php\r\n\r\nx"), UploadPolicy{}, idUploadName},
		{"a picture with a script in it", multipartBody(filePart("photo.jpg", shell)), UploadPolicy{}, idUploadScript},
		{"a script far into a large file", multipartBody(filePart("photo.jpg", jpeg+strings.Repeat("A", 50000)+"<?= `id` ?>")), UploadPolicy{}, idUploadScript},
		{"an asp tag", multipartBody(filePart("photo.jpg", "x<%@ Page Language=\"C#\" %>")), UploadPolicy{}, idUploadScript},
		{"script names allowed", multipartBody(filePart("shell.php", "x")), UploadPolicy{AllowExecutableNames: true}, 0},
		{"script content allowed", multipartBody(filePart("photo.jpg", shell)), UploadPolicy{AllowScriptContent: true}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var seen refusals
			s := start(t, func(c *Config) {
				ruleSetOff(c)
				c.OnMatch = seen.record
				c.Uploads = tt.policy
				c.CRS.RequestBodyLimit = 1 << 20
			})
			status, _ := s.raw(t, uploadRequest(tt.body))
			if tt.refused == 0 {
				if status != 200 || len(s.up.requests()) != 1 {
					t.Fatalf("a harmless upload: status %d, %d requests", status, len(s.up.requests()))
				}
				return
			}
			if status != 403 || len(s.up.requests()) != 0 || seen.last() != tt.refused {
				t.Fatalf("status %d, %d requests, id %d; want 403, none, %d", status, len(s.up.requests()), seen.last(), tt.refused)
			}
		})
	}
}

func TestWordPressPolicy(t *testing.T) {
	on := func(c *Config) { ruleSetOff(c); c.WordPress = WordPressPolicy{Enabled: true, LoginPerMinute: 3} }
	tests := []struct {
		name, path string
		change     func(*Config)
		want       int
	}{
		{"a picture in uploads", "/wp-content/uploads/2026/10/photo.jpg", on, 200},
		{"a script in uploads", "/wp-content/uploads/2026/10/shell.php", on, 403},
		{"a script in uploads, in capitals", "/wp-content/UPLOADS/shell.PHP", on, 403},
		{"a script with a path after it", "/wp-content/uploads/shell.php/x.jpg", on, 403},
		{"phtml in a cache directory", "/wp-content/cache/a.phtml", on, 403},
		{"a script in a backup directory", "/wp-content/backup-db/x.php", on, 403},
		{"a plugin's own script", "/wp-content/plugins/contact-form/handler.php", on, 200},
		{"admin-ajax", "/wp-admin/admin-ajax.php", on, 200},
		{"an empty segment before uploads", "/wp-content//uploads/shell.php", on, 403},
		{"xmlrpc is off by default", "/xmlrpc.php", on, 403},
		{"xmlrpc with a trailing slash", "/xmlrpc.php/", on, 403},
		{"xmlrpc with path info", "/xmlrpc.php/x", on, 403},
		{"xmlrpc after an empty segment", "//xmlrpc.php", on, 400},
		{"xmlrpc with a path parameter", "/xmlrpc.php;v=1", func(c *Config) { on(c); c.Paths.AllowPathParams = true }, 403},
		{"xmlrpc allowed", "/xmlrpc.php", func(c *Config) { on(c); c.WordPress.AllowXMLRPC = true }, 200},
		{"a script in uploads on a site not marked as WordPress", "/wp-content/uploads/shell.php", ruleSetOff, 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := start(t, tt.change)
			if status, _ := s.raw(t, get(tt.path)); status != tt.want {
				t.Fatalf("status %d, want %d", status, tt.want)
			}
		})
	}

	t.Run("login attempts are limited per address", func(t *testing.T) {
		s := start(t, on)
		login := "POST /wp-login.php HTTP/1.1\r\n" + preamble + "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\nConnection: close\r\n\r\nlog=a&pwd=b"
		var statuses []int
		for i := 0; i < 5; i++ {
			status, _ := s.raw(t, login)
			statuses = append(statuses, status)
		}
		if want := []int{200, 200, 200, 429, 429}; !equalInts(statuses, want) {
			t.Fatalf("statuses %v, want %v", statuses, want)
		}
		if status, _ := s.raw(t, get("/wp-login.php")); status != 200 {
			t.Fatalf("reading the login page was limited: %d", status)
		}
	})
	t.Run("login spellings and addresses in one IPv6 /64 share the limit", func(t *testing.T) {
		s := start(t, func(c *Config) { on(c); c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")} })
		var statuses []int
		for i, target := range []string{"/wp-login.php", "/wp-login.php/", "/wp-login.php/x", "/wp-login.php"} {
			login := "POST " + target + " HTTP/1.1\r\n" + preamble + fmt.Sprintf("X-Forwarded-For: 2001:db8:1:2::%x\r\n", i+1) +
				"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\nConnection: close\r\n\r\nlog=a&pwd=b"
			status, _ := s.raw(t, login)
			statuses = append(statuses, status)
		}
		if want := []int{200, 200, 200, 429}; !equalInts(statuses, want) {
			t.Fatalf("statuses %v, want %v", statuses, want)
		}
	})
}

func TestAPIRatePolicy(t *testing.T) {
	on := func(c *Config) { ruleSetOff(c); c.APIRate = APIRatePolicy{PerMinute: 2} }
	tests := []struct {
		name, target string
		change       func(*Config)
		want         []int
	}{
		{"API namespace", "/api/orders", on, []int{200, 200, 429}},
		{"case variant shares quota", "/API/ORDERS", on, []int{200, 200, 429}},
		{"namespace root", "/api", on, []int{200, 200, 429}},
		{"GraphQL namespace", "/graphql", on, []int{200, 200, 429}},
		{"query strings share quota", "/api?q=1", on, []int{200, 200, 429}},
		{"unrelated route", "/page", on, []int{200, 200, 200}},
		{"prefix requires segment boundary", "/apiary", on, []int{200, 200, 200}},
		{"explicit custom prefix", "/internal/orders", func(c *Config) { on(c); c.APIRate.Paths = []string{"/internal"} }, []int{200, 200, 429}},
		{"all routes", "/page", func(c *Config) { on(c); c.APIRate.Paths = []string{"/"} }, []int{200, 200, 429}},
		{"encoded slash allowed by site", "/api%2forders", func(c *Config) { on(c); c.Paths.AllowEncodedSlash = true }, []int{200, 200, 429}},
		{"encoded backslash allowed by site", "/api%5corders", func(c *Config) { on(c); c.Paths.AllowEncodedSlash = true }, []int{200, 200, 429}},
		{"matrix parameters allowed by site", "/api;v=1/orders", func(c *Config) { on(c); c.Paths.AllowPathParams = true }, []int{200, 200, 429}},
		{"nested matrix parameters", "/api;v=1/orders;v=2", func(c *Config) { on(c); c.Paths.AllowPathParams = true; c.APIRate.Paths = []string{"/api/orders"} }, []int{200, 200, 429}},
		{"repeated slash normalization", "/api//orders", func(c *Config) { on(c); c.APIRate.Paths = []string{"/api/orders"} }, []int{200, 200, 429}},
		{"disabled", "/api", ruleSetOff, []int{200, 200, 200}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := start(t, tc.change)
			accepted := 0
			for _, want := range tc.want {
				status, reply := s.raw(t, get(tc.target))
				if status != want {
					t.Fatalf("status %d, want %d", status, want)
				}
				if want == 200 {
					accepted++
				} else if !strings.Contains(reply, "Retry-After: 60\r\n") || !strings.Contains(reply, "Cache-Control: no-store\r\n") {
					t.Fatal("rate refusal lacks retry or cache policy")
				}
			}
			if len(s.up.requests()) != accepted {
				t.Fatal("rate refusal reached the origin")
			}
		})
	}
	t.Run("prefixes share one budget and cannot be changed by the caller", func(t *testing.T) {
		prefixes := []string{"/api", "/graphql"}
		s := start(t, func(c *Config) { on(c); c.APIRate.Paths = prefixes })
		prefixes[0] = "/changed"
		for i, target := range []string{"/api/orders", "/graphql", "/api/users"} {
			want := 200
			if i == 2 {
				want = 429
			}
			if status, _ := s.raw(t, get(target)); status != want {
				t.Fatalf("status %d, want %d", status, want)
			}
		}
	})
	t.Run("untrusted forwarding headers cannot rotate identity", func(t *testing.T) {
		s := start(t, on)
		for i := 1; i <= 3; i++ {
			want := 200
			if i == 3 {
				want = 429
			}
			status, _ := s.raw(t, get("/api", fmt.Sprintf("X-Forwarded-For: 198.51.100.%d\r\nX_Forwarded_For: 203.0.113.%d\r\n", i, i)))
			if status != want {
				t.Fatalf("status %d, want %d", status, want)
			}
		}
	})
	t.Run("trusted chain selects the first untrusted hop", func(t *testing.T) {
		s := start(t, func(c *Config) { on(c); c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")} })
		for i := 1; i <= 3; i++ {
			want := 200
			if i == 3 {
				want = 429
			}
			status, _ := s.raw(t, get("/api", fmt.Sprintf("X-Forwarded-For: 203.0.113.%d, 198.51.100.1\r\n", i)))
			if status != want {
				t.Fatalf("status %d, want %d", status, want)
			}
		}
		if status, _ := s.raw(t, get("/api", "X-Forwarded-For: 198.51.100.2\r\n")); status != 200 {
			t.Fatalf("a separate verified client got %d", status)
		}
	})
	t.Run("addresses in one IPv6 /64 share a budget", func(t *testing.T) {
		s := start(t, func(c *Config) { on(c); c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")} })
		for i := 1; i <= 3; i++ {
			want := 200
			if i == 3 {
				want = 429
			}
			if status, _ := s.raw(t, get("/api", fmt.Sprintf("X-Forwarded-For: 2001:db8:1:2::%x\r\n", i))); status != want {
				t.Fatalf("status %d, want %d", status, want)
			}
		}
		if status, _ := s.raw(t, get("/api", "X-Forwarded-For: 2001:db8:1:3::1\r\n")); status != 200 {
			t.Fatalf("a client in another /64 got %d", status)
		}
	})
	t.Run("state saturation refuses live traffic", func(t *testing.T) {
		s := start(t, on)
		for i := 0; i < rateLimiterKeys; i++ {
			if s.edge.limiter.allow(fmt.Sprintf("api:test-%d", i), 2) != rateAllowed {
				t.Fatal("capacity filled early")
			}
		}
		if status, reply := s.raw(t, get("/api")); status != 503 || !strings.Contains(reply, "Retry-After: 60\r\n") {
			t.Fatalf("capacity response %d", status)
		}
		if len(s.up.requests()) != 0 {
			t.Fatal("untracked request reached origin")
		}
	})
	t.Run("trusted ranges cannot be changed by the caller after construction", func(t *testing.T) {
		trusted := []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}
		s := start(t, func(c *Config) { on(c); c.TrustedProxies = trusted })
		trusted[0] = netip.MustParsePrefix("127.0.0.0/8")
		for i := 1; i <= 3; i++ {
			want := 200
			if i == 3 {
				want = 429
			}
			if status, _ := s.raw(t, get("/api", fmt.Sprintf("X-Forwarded-For: 198.51.100.%d\r\n", i))); status != want {
				t.Fatalf("status %d, want %d", status, want)
			}
		}
	})
	t.Run("invalid configuration refuses construction", func(t *testing.T) {
		for _, p := range []APIRatePolicy{{PerMinute: -1}, {PerMinute: 100001}, {PerMinute: 1, Paths: []string{"api"}}, {PerMinute: 1, Paths: []string{"/api/"}}, {PerMinute: 1, Paths: []string{"/api?x=1"}}, {PerMinute: 1, Paths: []string{"/api%2forders"}}, {PerMinute: 1, Paths: []string{"/api/../"}}, {PerMinute: 1, Paths: []string{"/api;v=1"}}, {PerMinute: 1, Paths: make([]string, 101)}} {
			if _, err := p.normalized(); err == nil {
				t.Fatalf("accepted %+v", p)
			}
		}
	})
}

func TestSlidingRateBudget(t *testing.T) {
	t.Run("exact boundary and denied attempts do not extend it", func(t *testing.T) {
		now := time.Now()
		l := rateLimiter{now: func() time.Time { return now }}
		for i := 0; i < 2; i++ {
			if l.allow("a", 2) != rateAllowed {
				t.Fatal("early refusal")
			}
		}
		now = now.Add(time.Minute - time.Nanosecond)
		if l.allow("a", 2) != rateExceeded {
			t.Fatal("expired early")
		}
		now = now.Add(time.Nanosecond)
		if l.allow("a", 2) != rateAllowed {
			t.Fatal("did not expire at boundary")
		}
	})
	t.Run("concurrent admission does not overshoot", func(t *testing.T) {
		var l rateLimiter
		var accepted atomic.Int64
		var group sync.WaitGroup
		for i := 0; i < 100; i++ {
			group.Add(1)
			go func() {
				defer group.Done()
				if l.allow("same", 7) == rateAllowed {
					accepted.Add(1)
				}
			}()
		}
		group.Wait()
		if accepted.Load() != 7 {
			t.Fatalf("accepted %d", accepted.Load())
		}
	})
	t.Run("event storage is bounded even for one busy client", func(t *testing.T) {
		now := time.Now()
		l := rateLimiter{now: func() time.Time { return now }}
		for i := 0; i < rateLimiterEvents; i++ {
			if l.allow("same", rateLimiterEvents+1) != rateAllowed {
				t.Fatal("early capacity refusal")
			}
		}
		if l.allow("same", rateLimiterEvents+1) != rateFull {
			t.Fatal("event cap bypassed")
		}
		if l.size != rateLimiterEvents || len(l.events) != rateLimiterEvents {
			t.Fatal("event storage grew")
		}
		now = now.Add(time.Minute)
		if l.allow("new", 1) != rateAllowed || len(l.hits) != 1 || l.size != 1 {
			t.Fatal("expired capacity not reclaimed")
		}
	})
}

func FuzzSlidingRateBudget(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0}, uint8(3))
	f.Add([]byte(strings.Repeat("0123456", 20)), uint8(7))
	f.Fuzz(func(t *testing.T, commands []byte, quota uint8) {
		if len(commands) > 4096 {
			return
		}
		now := time.Now()
		base := now
		// A small ring exercises wraparound and capacity under the same algorithm used in production.
		l := rateLimiter{hits: map[string]int{}, events: make([]rateEvent, 16), now: func() time.Time { return now }}
		type event struct {
			key     string
			seconds int64
		}
		var admitted []event
		var elapsed int64
		n := int(quota%8) + 1
		for _, cmd := range commands {
			elapsed += int64(cmd >> 4)
			now = base.Add(time.Duration(elapsed) * time.Second)
			key := string(rune('a' + cmd%7))
			var active []event
			hits := 0
			for _, event := range admitted {
				if elapsed-event.seconds < 60 {
					active = append(active, event)
					if event.key == key {
						hits++
					}
				}
			}
			admitted = active
			want := rateAllowed
			if hits >= n {
				want = rateExceeded
			} else if len(admitted) >= 16 {
				want = rateFull
			}
			if got := l.allow(key, n); got != want {
				t.Fatalf("decision %d, want %d", got, want)
			}
			if want == rateAllowed {
				admitted = append(admitted, event{key, elapsed})
			}
			if l.size != len(admitted) || l.size > len(l.events) {
				t.Fatal("event accounting differs from reference")
			}
		}
	})
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestOneAddressCannotHoldManyConnectionsOpen(t *testing.T) {
	s := start(t, func(c *Config) { ruleSetOff(c); c.MaxConnsPerIP = 3 })
	var held []net.Conn
	for i := 0; i < 3; i++ {
		c, err := net.DialTimeout("tcp", s.addr, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	time.Sleep(100 * time.Millisecond) // let the server see all three

	extra, err := net.DialTimeout("tcp", s.addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	extra.SetDeadline(time.Now().Add(3 * time.Second))
	extra.Write([]byte(get("/page")))
	if _, err := bufio.NewReader(extra).ReadString('\n'); err == nil {
		t.Fatal("a fourth connection from the same address was served")
	}

	held[0].Close() // a place comes free
	time.Sleep(100 * time.Millisecond)
	if status, _ := s.raw(t, get("/page")); status != 200 {
		t.Fatalf("after one was closed, a new connection got %d", status)
	}

	t.Run("addresses in one IPv6 /64 share the cap", func(t *testing.T) {
		l := newConnLimiter(2, nil, nil)
		var open []*limitConn
		for i, addr := range []string{"[2001:db8:1:2::1]:1000", "[2001:db8:1:2::2]:1000", "[2001:db8:1:2::3]:1000", "[2001:db8:1:3::1]:1000"} {
			c := &limitConn{remote: addr}
			l.state(c, http.StateNew)
			if want := i != 2; c.closed == want {
				t.Fatalf("%s: closed %v, want %v", addr, c.closed, !want)
			}
			open = append(open, c)
		}
		l.state(open[0], http.StateClosed)
		again := &limitConn{remote: "[2001:db8:1:2::9]:1000"}
		if l.state(again, http.StateNew); again.closed {
			t.Fatal("a place freed in the /64 was not reused")
		}
	})
}

// limitConn is a connection with only an address, for the connection limiter.
type limitConn struct {
	net.Conn
	remote string
	closed bool
}

func (c *limitConn) RemoteAddr() net.Addr { return limitAddr(c.remote) }
func (c *limitConn) Close() error         { c.closed = true; return nil }

type limitAddr string

func (a limitAddr) Network() string { return "tcp" }
func (a limitAddr) String() string  { return string(a) }

func TestHTTP2LimitsAreAdvertisedToClients(t *testing.T) {
	s := start(t, ruleSetOff)
	srv := httptest.NewUnstartedServer(nil)
	srv.Config = s.edge.Server("")
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "example.com", NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("negotiated %q, want h2", conn.ConnectionState().NegotiatedProtocol)
	}
	conn.Write([]byte(http2.ClientPreface))
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("no SETTINGS frame from the server: %v", err)
		}
		if sf, ok := f.(*http2.SettingsFrame); ok && !sf.IsAck() {
			streams, ok := sf.Value(http2.SettingMaxConcurrentStreams)
			if !ok || streams != 100 {
				t.Fatalf("MAX_CONCURRENT_STREAMS = %d (set: %v), want 100", streams, ok)
			}
			if size, ok := sf.Value(http2.SettingMaxFrameSize); ok && size > 16<<10 {
				t.Fatalf("MAX_FRAME_SIZE = %d, want 16384 or less", size)
			}
			return
		}
	}
}

// stallEdge serves a large response at /big through an edge with the given number of upstream places, over TLS with HTTP/2.
func stallEdge(t *testing.T, places int, active *atomic.Int64) (*httptest.Server, *Edge, *refusals, *x509.CertPool) {
	t.Helper()
	chunk := []byte(strings.Repeat("x", 64<<10)) // /big never ends: more than every socket buffer on the way
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Path == "/big" {
			active.Add(1) // requests at the application with a response it is still sending
			defer active.Add(-1)
			for r.Context().Err() == nil {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
			return
		}
		_, _ = w.Write([]byte("ok")) // nothing to do if the edge has gone
	}))
	t.Cleanup(up.Close)
	rec := &refusals{}
	cfg := Config{Upstream: mustURL(up.URL), Origin: loopback, CRS: crs.DefaultSettings(), MaxUpstreamInFlight: places, OnMatch: rec.record}
	ruleSetOff(&cfg)
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	srv := httptest.NewUnstartedServer(nil)
	srv.Config = e.Server("")
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, e, rec, pool
}

// waitActive waits until the application is sending exactly want large responses.
func waitActive(t *testing.T, active *atomic.Int64, want int64, within time.Duration) {
	t.Helper()
	for deadline := time.Now().Add(within); active.Load() != want; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d requests are being answered by the application, want %d within %v", active.Load(), want, within)
		}
	}
}

// waitStuck waits until n responses are held at a write the client does not take.
func waitStuck(t *testing.T, e *Edge, n int) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; {
		stuck := 0
		e.places.mu.Lock()
		for w := range e.places.held {
			if w.since.Load() != 0 {
				stuck++
			}
		}
		e.places.mu.Unlock()
		if stuck >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d responses stuck, want %d", stuck, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func fetch(t *testing.T, srv *httptest.Server, pool *x509.CertPool) int {
	t.Helper()
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"}}}
	defer c.CloseIdleConnections()
	resp, err := c.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func (r *refusals) count(id int) (n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, x := range r.ids {
		if x == id {
			n++
		}
	}
	return n
}

// A client that opens requests and then reads nothing must not hold the upstream's places, and so the whole site, until
// the write timeout. When no place is free, the response stuck the longest (at least stallGrace) is ended; while places
// are free, a slow reader is left alone.
func TestAClientThatStopsReadingCannotHoldTheUpstream(t *testing.T) {
	t.Run("HTTP/2 streams with a window of zero", func(t *testing.T) {
		t.Parallel()
		var active atomic.Int64
		srv, e, rec, pool := stallEdge(t, 4, &active)
		conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "example.com", NextProtos: []string{"h2"}})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
			t.Fatal(err)
		}
		fr := http2.NewFramer(conn, conn)
		if err := fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0}); err != nil {
			t.Fatal(err)
		}
		var mu sync.Mutex // guards the framer's writes (it is not safe for concurrent use) and the resets seen
		reset := map[uint32]bool{}
		go func() { // the connection itself is read; only the streams are never given room
			for {
				f, err := fr.ReadFrame()
				if err != nil {
					return
				}
				switch f := f.(type) {
				case *http2.SettingsFrame:
					if !f.IsAck() {
						mu.Lock()
						_ = fr.WriteSettingsAck() // the read loop has no one to tell; a failed write ends the test's reads
						mu.Unlock()
					}
				case *http2.RSTStreamFrame:
					mu.Lock()
					reset[f.StreamID] = true
					mu.Unlock()
				}
			}
		}()
		var hb strings.Builder
		open := func(id uint32) {
			hb.Reset()
			enc := hpack.NewEncoder(&hb)
			for _, f := range [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "example.com"}, {":path", "/big"}} {
				if err := enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]}); err != nil {
					t.Fatal(err)
				}
			}
			mu.Lock()
			err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: []byte(hb.String()), EndStream: true, EndHeaders: true})
			mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
		}
		for _, id := range []uint32{1, 3, 5} {
			open(id)
		}
		waitStuck(t, e, 3)
		time.Sleep(stallGrace + 500*time.Millisecond)
		if got := fetch(t, srv, pool); got != http.StatusOK || rec.count(idUpstreamReclaimed) != 0 {
			t.Fatalf("with a place to spare: status %d, %d responses ended", got, rec.count(idUpstreamReclaimed))
		}
		open(7) // now every place is held
		waitStuck(t, e, 4)
		waitActive(t, &active, 4, 5*time.Second)
		if got := fetch(t, srv, pool); got != http.StatusOK || rec.count(idUpstreamReclaimed) != 1 {
			t.Fatalf("with every place held by streams the client does not read: status %d, %d responses ended", got, rec.count(idUpstreamReclaimed))
		}
		waitActive(t, &active, 3, 2*time.Second) // the ended response's request to the application was cancelled with it
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			mu.Lock()
			n, newest := len(reset), reset[7]
			mu.Unlock()
			if n == 1 && !newest {
				break
			}
			if n > 1 || newest || time.Now().After(deadline) {
				t.Fatalf("streams reset: %v, want one of the three stuck longest", reset)
			}
		}
		// Every request that finished has given back what it held: the three responses still stuck hold three places.
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			e.places.mu.Lock()
			ending, held, free := e.places.ending, len(e.places.held), len(e.places.free)
			e.places.mu.Unlock()
			if ending == 0 && held == 3 && free == 3 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%d still ending, %d held, %d places in use (want 0, 3, 3)", ending, held, free)
			}
		}
	})
	t.Run("HTTP/1.1 connections that stop reading", func(t *testing.T) {
		t.Parallel()
		var active atomic.Int64
		srv, e, rec, pool := stallEdge(t, 2, &active)
		for i := 0; i < 2; i++ {
			raw, err := net.Dial("tcp", srv.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			if err := raw.(*net.TCPConn).SetReadBuffer(4 << 10); err != nil {
				t.Fatal(err)
			}
			c := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: "example.com", NextProtos: []string{"http/1.1"}})
			defer c.Close()
			if _, err := c.Write([]byte("GET /big HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
				t.Fatal(err)
			}
		}
		waitStuck(t, e, 2)
		// Control: a response that has only just stopped being read is not ended; the site is busy for the moment.
		if got := fetch(t, srv, pool); got != http.StatusServiceUnavailable || rec.count(idUpstreamReclaimed) != 0 {
			t.Fatalf("with both places held by writes stuck for under %v: status %d, %d responses ended", stallGrace, got, rec.count(idUpstreamReclaimed))
		}
		time.Sleep(stallGrace + 500*time.Millisecond)
		waitActive(t, &active, 2, 5*time.Second)
		if got := fetch(t, srv, pool); got != http.StatusOK || rec.count(idUpstreamReclaimed) != 1 {
			t.Fatalf("with both places held by connections that do not read: status %d, %d responses ended", got, rec.count(idUpstreamReclaimed))
		}
		// The ended response's request to the application stops at once, not after the seconds its TLS connection takes to close.
		waitActive(t, &active, 1, time.Second)
		// The ended response's handler returns within a few seconds (a TLS connection first tries to send its close_notify to
		// the client that is not reading) without giving back the place that went to the new request: one place is still
		// held, by the response that was not ended, which is left to go on.
		for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			e.places.mu.Lock()
			ending, held, free := e.places.ending, len(e.places.held), len(e.places.free)
			e.places.mu.Unlock()
			if ending == 0 && held == 1 && free == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("after the ended response's handler should have returned: %d still ending, %d held, %d places in use (want 0, 1, 1)", ending, held, free)
			}
		}
		e.places.mu.Lock()
		defer e.places.mu.Unlock()
		for w := range e.places.held {
			if w.ended || w.since.Load() == 0 {
				t.Fatal("the response that was not ended is no longer waiting on its client")
			}
		}
	})
}

// The accounting behind the hand-over, without a network: which response is ended, how many may be finishing at once, and that
// a place goes back exactly once.
func TestUpstreamPlacesAreHandedOverWithinTheirLimits(t *testing.T) {
	const n = 16 // at most two ended responses may be finishing at once
	p := newUpstreamPlaces(n)
	var held []*writeWatch
	for i := 0; i < n; i++ {
		w := &writeWatch{ResponseWriter: httptest.NewRecorder()}
		if ok, reclaimed := p.acquire(w); !ok || reclaimed {
			t.Fatalf("place %d of %d: ok %v, reclaimed %v", i+1, n, ok, reclaimed)
		}
		held = append(held, w)
	}
	stuckFor := func(w *writeWatch, d time.Duration) { w.since.Store(monotonic() - int64(d)) }
	acquire := func() (bool, bool, *writeWatch) {
		w := &writeWatch{ResponseWriter: httptest.NewRecorder()}
		ok, reclaimed := p.acquire(w)
		return ok, reclaimed, w
	}

	if ok, _, _ := acquire(); ok {
		t.Fatal("a place was found with nothing writing")
	}
	for _, w := range held {
		stuckFor(w, stallGrace-time.Second)
	}
	if ok, _, _ := acquire(); ok {
		t.Fatalf("a place was taken from a write stuck for under %v", stallGrace)
	}
	for i, w := range held {
		stuckFor(w, time.Duration(30-i)*time.Second) // the first has waited longest
	}
	stuckFor(held[n-1], time.Second) // not yet long enough
	if ok, _, _ := acquire(); !ok {
		t.Fatal("no place was handed over although writes had been stuck for 30 seconds")
	}
	if !held[0].ended || held[1].ended {
		t.Fatalf("ended: first %v, second %v: want the response stuck longest, and only it", held[0].ended, held[1].ended)
	}
	if ok, reclaimed, _ := acquire(); !ok || !reclaimed || !held[1].ended || held[2].ended {
		t.Fatalf("second hand-over: ok %v, reclaimed %v, ended %v %v", ok, reclaimed, held[1].ended, held[2].ended)
	}
	if ok, _, _ := acquire(); ok || held[2].ended {
		t.Fatal("a third response was ended while two were still finishing")
	}
	p.release(held[0]) // the first ended response's handler returns
	if p.ending != 1 || len(p.free) != n {
		t.Fatalf("after one returned: %d finishing, %d places in use (want 1, %d): its place must not be given back twice", p.ending, len(p.free), n)
	}
	if ok, reclaimed, _ := acquire(); !ok || !reclaimed || !held[2].ended {
		t.Fatalf("after one returned: ok %v, reclaimed %v, third ended %v", ok, reclaimed, held[2].ended)
	}
	for _, w := range held[3 : n-1] {
		w.since.Store(0) // not writing: never taken from
	}
	p.release(held[1])
	p.release(held[2])
	if ok, _, _ := acquire(); ok {
		t.Fatal("a place was taken from a response that was not stuck")
	}
	p.release(held[n-1])
	if ok, reclaimed, _ := acquire(); !ok || reclaimed {
		t.Fatalf("a released place: ok %v, reclaimed %v", ok, reclaimed)
	}
}

// Many requests take places, some get stuck and are ended by the others, and every one releases: at no moment do more requests run
// than there are places plus the ended ones still finishing, and every place is back at the end.
func TestUpstreamPlacesHoldTheirLimitsUnderLoad(t *testing.T) {
	const n = 16
	p := newUpstreamPlaces(n)
	var running, ended, peak atomic.Int64
	var wg sync.WaitGroup
	for g := 0; g < 48; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 400; i++ {
				w := &writeWatch{ResponseWriter: httptest.NewRecorder()}
				ok, reclaimed := p.acquire(w)
				if !ok {
					continue
				}
				if reclaimed {
					ended.Add(1)
				}
				now := running.Add(1)
				for {
					seen := peak.Load()
					if now <= seen || peak.CompareAndSwap(seen, now) {
						break
					}
				}
				if i%3 == 0 {
					w.since.Store(monotonic() - int64(time.Hour)) // stuck, for as long as it takes someone to end it
					for spins := 0; spins < 200; spins++ {
						p.mu.Lock()
						done := w.ended
						p.mu.Unlock()
						if done {
							break
						}
						runtime.Gosched()
					}
					w.since.Store(0)
				}
				running.Add(-1)
				p.release(w)
			}
		}()
	}
	wg.Wait()
	if got, limit := peak.Load(), int64(n+p.maxEnding); got > limit {
		t.Fatalf("%d requests ran at once, more than %d places and %d ended ones finishing", got, n, p.maxEnding)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.free) != 0 || p.ending != 0 || len(p.held) != 0 {
		t.Fatalf("after every request returned: %d places in use, %d finishing, %d held (want 0, 0, 0)", len(p.free), p.ending, len(p.held))
	}
	if ended.Load() == 0 {
		t.Fatal("no response was ended: the test did not exercise the hand-over")
	}
}

// stuckClient is a response writer for a client that reads nothing and cannot be given a write deadline: its Write waits.
type stuckClient struct {
	header  http.Header
	in      chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *stuckClient) Header() http.Header { return s.header }
func (s *stuckClient) WriteHeader(int)     {}
func (s *stuckClient) Write(b []byte) (int, error) {
	s.once.Do(func() { close(s.in) })
	<-s.release
	return len(b), nil
}

// Ending a response that cannot be cut by a deadline still stops its request to the application, at once: the guarantee does not
// depend on what the web server does when a client's connection fails.
func TestEndingAResponseAlsoCancelsItsRequestToTheApplication(t *testing.T) {
	started, cancelled, giveUp := make(chan struct{}), make(chan struct{}), make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/slow" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		_, _ = w.Write([]byte("the first of a response that never ends"))
		w.(http.Flusher).Flush()
		close(started)
		select {
		case <-r.Context().Done(): // the edge closing its connection to the application is what ends this
			close(cancelled)
		case <-giveUp: // the test is over, and did not see that happen
		}
	}))
	t.Cleanup(up.Close)
	t.Cleanup(func() { close(giveUp) })
	cfg := Config{Upstream: mustURL(up.URL), Origin: loopback, CRS: crs.DefaultSettings(), MaxUpstreamInFlight: 1}
	ruleSetOff(&cfg)
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	stuck := &stuckClient{header: http.Header{}, in: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() { close(stuck.release) })
	go e.ServeHTTP(stuck, httptest.NewRequest(http.MethodGet, "/slow", nil))
	<-started
	<-stuck.in
	e.places.mu.Lock()
	for w := range e.places.held {
		w.since.Store(monotonic() - int64(time.Minute)) // stuck for long enough
	}
	e.places.mu.Unlock()
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("the request that needed the place: status %d, body %q", rec.Code, rec.Body.String())
	}
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("the request to the application of the ended response was not cancelled")
	}
}

// deadlineBlocker is a response writer whose SetWriteDeadline does not come back until told to.
type deadlineBlocker struct {
	http.ResponseWriter
	in, out chan struct{}
}

func (d deadlineBlocker) SetWriteDeadline(time.Time) error { close(d.in); <-d.out; return nil }

// The call that ends a stuck response may be slow to come back. It must not hold up anything else: other requests take and give
// back places meanwhile, the request that was waiting for a place has it at once, and the ended response's handler does not
// return until the call is done with its writer.
func TestAStuckCallThatEndsAResponseDoesNotStallThePlaces(t *testing.T) {
	within := func(what string, f func()) {
		t.Helper()
		done := make(chan struct{})
		go func() { f(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal(what)
		}
	}
	p := newUpstreamPlaces(2)
	blocker := deadlineBlocker{httptest.NewRecorder(), make(chan struct{}), make(chan struct{})}
	victim := &writeWatch{ResponseWriter: blocker}
	other := &writeWatch{ResponseWriter: httptest.NewRecorder()}
	p.acquire(victim)
	p.acquire(other)
	victim.since.Store(monotonic() - int64(time.Minute))
	newcomer := &writeWatch{ResponseWriter: httptest.NewRecorder()}
	within("the request waiting for a place was held up by the call that ends the response", func() {
		if ok, reclaimed := p.acquire(newcomer); !ok || !reclaimed {
			t.Errorf("acquire: ok %v, reclaimed %v", ok, reclaimed)
		}
	})
	<-blocker.in // the call is under way, and does not return
	within("other requests were held up by the call that ends a response", func() {
		p.release(other)
		again := &writeWatch{ResponseWriter: httptest.NewRecorder()}
		if ok, _ := p.acquire(again); !ok {
			t.Error("a place that was given back was not found")
		}
		p.release(again)
	})
	returned := make(chan struct{})
	go func() { p.release(victim); close(returned) }()
	select {
	case <-returned:
		t.Fatal("the ended response's handler returned while its writer was still in use")
	case <-time.After(100 * time.Millisecond):
	}
	close(blocker.out)
	within("the ended response's handler did not return once the call was done", func() { <-returned })
	p.release(newcomer)
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.free) != 0 || p.ending != 0 || len(p.held) != 0 {
		t.Fatalf("at the end: %d places in use, %d finishing, %d held (want 0, 0, 0)", len(p.free), p.ending, len(p.held))
	}
}

// deadlineCounter counts the write deadlines it is given.
type deadlineCounter struct {
	http.ResponseWriter
	n *atomic.Int32
}

func (d deadlineCounter) SetWriteDeadline(time.Time) error { d.n.Add(1); return nil }

// A response writer may not be used once its handler is returning: ending a response that has finished does nothing.
func TestEndingAResponseWhoseHandlerIsReturningDoesNothing(t *testing.T) {
	var calls atomic.Int32
	w := &writeWatch{ResponseWriter: deadlineCounter{httptest.NewRecorder(), &calls}}
	w.cut()
	if calls.Load() != 1 {
		t.Fatalf("a running response was given %d write deadlines, want 1", calls.Load())
	}
	p := newUpstreamPlaces(1)
	p.acquire(w)
	p.release(w)
	w.cut()
	if calls.Load() != 1 {
		t.Fatalf("a response whose handler had returned was given %d write deadlines, want 1", calls.Load())
	}
}

// flushBlocker is a response writer whose Flush waits to be told to go on, like a socket whose client is not reading.
type flushBlocker struct {
	http.ResponseWriter
	in, out chan struct{}
}

func (b flushBlocker) Flush() { close(b.in); <-b.out }

func TestAWriteWatchSeesAFlushThatIsStuck(t *testing.T) {
	b := flushBlocker{httptest.NewRecorder(), make(chan struct{}), make(chan struct{})}
	w := &writeWatch{ResponseWriter: b}
	done := make(chan struct{})
	go func() { w.Flush(); close(done) }()
	<-b.in
	if w.since.Load() == 0 {
		t.Fatal("a flush in progress was not seen")
	}
	close(b.out)
	<-done
	if w.since.Load() != 0 {
		t.Fatal("a finished flush is still seen as stuck")
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
