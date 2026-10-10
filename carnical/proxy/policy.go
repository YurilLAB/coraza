// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"path"
	"regexp"
	"strings"

	"github.com/YurilLAB/coraza/carnical/shield"
)

// The checks in this file and the next ones do not depend on the rule set. They hold with the rule set off or in
// detection mode, because they protect against things a rule set cannot: a request the proxy and the application read
// differently, a framework's internal headers, and a site that has already been taken over.

// Identifiers for what the proxy itself refuses, in the range kept for it (the rule set uses 9xxxxx, local rules 1 to
// 99999). They appear as Match.RuleID, so one log and one feed carry both.
const (
	idHostNotAllowed      = 5000001
	idPathNotCanon        = 5000002
	idInternalHeader      = 5000003
	idRequestEncoding     = 5000004
	idAmbiguousType       = 5000005
	idUploadName          = 5000010
	idUploadScript        = 5000011
	idWordPressPHP        = 5000020
	idXMLRPC              = 5000021
	idRateLimited         = 5000022
	idTooManyConns        = 5000030
	idAPIRateLimited      = 5000042
	idRateStateFull       = 5000041
	idMethodNotCanon      = 5000043
	idMethodOverride      = 5000044
	idUpstreamFailed      = 5000050
	idUpstreamBindRetry   = 5000051
	idUpstreamReclaimed   = 5000052
	idCrowdSecBan         = 5000060
	idCrowdSecUnavailable = 5000061
)

// PathPolicy says how plain the request path must be. The zero value is the strict default.
//
// The WAF, the proxy and the application each read a path in their own way: one decodes %2f, another does not;
// one stops at a semicolon, another keeps it; one removes dot segments, another passes them. Every difference is a
// way to ask for /wp-admin/ in a form a deny rule does not recognise. A request whose path needs interpreting is
// refused, instead of being passed on in the hope that everyone reads it the same way.
type PathPolicy struct {
	// AllowEncodedSlash allows %2f and %5c, for an application that puts them in identifiers.
	AllowEncodedSlash bool
	// AllowPathParams allows a semicolon in the path (Java's ;jsessionid=, matrix parameters).
	AllowPathParams bool
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}

// check reports why a raw path (no query) is refused, or nil.
func (p PathPolicy) check(path string) error {
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case c < 0x21 || c >= 0x7f:
			return errors.New("a control, space or non-ASCII byte in the path")
		case c == '\\':
			return errors.New("a backslash in the path")
		case c == ';' && !p.AllowPathParams:
			return errors.New("a path parameter (;) in the path")
		case c == '%':
			if i+2 >= len(path) {
				return errors.New("a truncated percent escape")
			}
			if !isHex(path[i+1]) || !isHex(path[i+2]) {
				return errors.New("a malformed percent escape")
			}
			b := unhex(path[i+1])<<4 | unhex(path[i+2])
			switch {
			case b == '/' || b == '\\':
				if !p.AllowEncodedSlash {
					return errors.New("an encoded slash in the path")
				}
			case b == '?' || b == '#' || b == '%' || b == 0:
				return errors.New("an encoded delimiter, percent sign or NUL in the path")
			case b < 0x20 || b == 0x7f:
				return errors.New("an encoded control character in the path")
			case isUnreserved(b) && b != '~':
				// "%77p-admin" is "wp-admin" to the application and something else to a rule that matches the text.
				// A client has no reason to write it: only an attempt to avoid a rule does.
				return errors.New("an unnecessary percent escape of a plain character")
			}
			i += 2
		}
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return errors.New("a dot segment in the path")
		}
	}
	return nil
}

func isUnreserved(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '.' || b == '_' || b == '~'
}

// normHost reduces a Host header to the name it carries: lower case, no port, no trailing dot.
func normHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if strings.HasPrefix(h, "[") {
		if end := strings.Index(h, "]"); end > 0 {
			return h[:end+1]
		}
		return h
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimSuffix(h, ".")
}

// headersThatSteerTheApplication are control headers some frameworks trust. A client may send them to skip a
// middleware or choose a route or method. Method overrides are refused at admission; the rest are removed on forwarding,
// whatever the rule set says.
func isInternalHeader(key string) bool {
	switch key {
	case "x-matched-path", "x-now-route-matches", "x-http-method-override", "x-method-override", "x-http-method":
		return true
	}
	return strings.HasPrefix(key, "x-middleware-") || strings.HasPrefix(key, "x-invoke-") || strings.HasPrefix(key, "x-nextjs-")
}

func isMethodOverrideHeader(key string) bool {
	return key == "x-http-method-override" || key == "x-method-override" || key == "x-http-method"
}

// contentEncoded reports a Content-Encoding other than identity.
func contentEncoded(h http.Header) bool {
	for _, v := range h.Values("Content-Encoding") {
		if enc := strings.ToLower(strings.TrimSpace(v)); enc != "" && enc != "identity" {
			return true
		}
	}
	return false
}

// refuse answers a request the proxy itself will not forward, and records why in the same form as a rule match.
func (e *Edge) refuse(w http.ResponseWriter, r *http.Request, status int, id int, msg string) {
	if e.cfg.OnMatch != nil {
		m := Match{RuleID: id, Severity: "CRITICAL", Message: msg, Disruptive: true}
		if e.cfg.LogDetails {
			m.ClientIP, m.URI = r.RemoteAddr, r.RequestURI
		}
		e.cfg.OnMatch(m)
	}
	http.Error(w, http.StatusText(status), status)
}

// checkRequest applies the request-side policy that does not need the body. It reports whether the request may go on.
func (e *Edge) checkRequest(w http.ResponseWriter, r *http.Request, client netip.Addr) bool {
	// HTTP methods are case-sensitive, but some origins normalize them. Refuse that ambiguity before any inspector runs.
	if r.Method != strings.ToUpper(r.Method) {
		e.refuse(w, r, http.StatusBadRequest, idMethodNotCanon, "a noncanonical HTTP method token")
		return false
	}
	if len(e.hosts) > 0 && !e.hosts[normHost(r.Host)] {
		e.refuse(w, r, http.StatusMisdirectedRequest, idHostNotAllowed, "the Host header is not one of this site's names")
		return false
	}
	rawPath, _, _ := strings.Cut(r.RequestURI, "?")
	if err := e.cfg.Paths.check(rawPath); err != nil {
		e.refuse(w, r, http.StatusBadRequest, idPathNotCanon, "the request path is not in plain form: "+err.Error())
		return false
	}
	if len(r.Header.Values("Content-Type")) > 1 {
		e.refuse(w, r, http.StatusBadRequest, idAmbiguousType, "more than one Content-Type header")
		return false
	}
	// A compressed request body is not something the rules can read, and an application that unpacks it would
	// receive what nothing inspected. Browsers do not compress what they send. ServeHTTP refuses an allowed one that
	// no inspector decompressed.
	for _, v := range r.Header.Values("Content-Encoding") {
		enc := strings.ToLower(strings.TrimSpace(v))
		if e.cfg.AllowRequestEncoding && (enc == "gzip" || enc == "deflate") && len(r.Header.Values("Content-Encoding")) == 1 {
			continue // an inspector decompresses it, within limits
		}
		if enc != "" && enc != "identity" {
			e.refuse(w, r, http.StatusUnsupportedMediaType, idRequestEncoding, "a request body with a content encoding cannot be inspected")
			return false
		}
	}
	for name := range r.Header {
		key := strings.ReplaceAll(strings.ToLower(name), "_", "-")
		if isMethodOverrideHeader(key) {
			e.refuse(w, r, http.StatusBadRequest, idMethodOverride, "a header that overrides the HTTP method")
			return false
		}
		if e.deny[key] {
			e.refuse(w, r, http.StatusBadRequest, idInternalHeader, "a header this site does not accept: "+key)
			return false
		}
	}
	if e.cfg.WordPress.Enabled && !e.checkWordPress(w, r, client) {
		return false
	}
	if e.cfg.APIRate.PerMinute > 0 && e.cfg.APIRate.matches(r.URL.Path) {
		return e.checkRate(w, r, "api:"+clientKey(client), e.cfg.APIRate.PerMinute, idAPIRateLimited, "too many API requests from one address")
	}
	return true
}

// APIRatePolicy gives one client a shared sliding-minute budget across all matching prefixes and HTTP methods.
// Paths are plain paths compared without ASCII case distinctions: /api matches /api and /api/... but not /apiary.
// Empty uses /api and /graphql. Case, slash and matrix normalization are conservative quota matching, not route rewriting.
// PerMinute is 1..100000 when enabled; zero disables the policy. State is local to one Edge and is lost on restart.
type APIRatePolicy struct {
	PerMinute int
	Paths     []string
}

func (p APIRatePolicy) normalized() (APIRatePolicy, error) {
	if p.PerMinute < 0 || p.PerMinute > 100000 {
		return p, errors.New("PerMinute must be zero (disabled) or between 1 and 100000")
	}
	if len(p.Paths) == 0 {
		p.Paths = []string{"/api", "/graphql"}
	} else {
		p.Paths = append([]string(nil), p.Paths...)
	}
	if len(p.Paths) > 100 {
		return p, errors.New("at most 100 path prefixes are allowed")
	}
	for i, prefix := range p.Paths {
		if prefix == "" || len(prefix) > 2048 || prefix[0] != '/' || path.Clean(prefix) != prefix || strings.ContainsAny(prefix, "%?;#\\") || (PathPolicy{}).check(prefix) != nil {
			return p, errors.New("prefixes must be plain absolute paths without query, encoding, parameters or trailing slashes")
		}
		p.Paths[i] = strings.ToLower(prefix)
	}
	return p, nil
}

func (p APIRatePolicy) matches(decoded string) bool {
	decoded = routePath(decoded)
	for _, prefix := range p.Paths {
		if prefix == "/" || decoded == prefix || strings.HasPrefix(decoded, prefix+"/") {
			return true
		}
	}
	return false
}

// routePath is a decoded path as an application is likely to route it: empty segments, a trailing slash and path
// parameters removed, backslashes as slashes, in lower case. It accounts conservatively for sites that permit encoded
// slashes or matrix parameters.
func routePath(decoded string) string {
	parts := strings.Split(strings.ReplaceAll(decoded, "\\", "/"), "/")
	for i := range parts {
		parts[i], _, _ = strings.Cut(parts[i], ";")
	}
	return strings.ToLower(path.Clean(strings.Join(parts, "/")))
}

// clientKey is what the per-client limits count: an IPv4 address or an IPv6 /64, as the shield does, so a client
// cannot get a fresh budget by changing the low bits of its IPv6 address.
func clientKey(a netip.Addr) string { return shield.SourceKey(a).String() }

func (e *Edge) checkRate(w http.ResponseWriter, r *http.Request, key string, n, rule int, message string) bool {
	switch e.limiter.allow(key, n) {
	case rateAllowed:
		return true
	case rateFull:
		w.Header().Set("Retry-After", "60")
		w.Header().Set("Cache-Control", "no-store")
		e.refuse(w, r, http.StatusServiceUnavailable, idRateStateFull, "rate-limit state capacity exhausted")
	default:
		w.Header().Set("Retry-After", "60")
		w.Header().Set("Cache-Control", "no-store")
		e.refuse(w, r, http.StatusTooManyRequests, rule, message)
	}
	return false
}

// WordPressPolicy is the protection for a WordPress site. WordPress and its plugins are most of what is hacked:
// in 2025 more than half of the new vulnerabilities were broken access control, and the exploited ones were used
// within hours of disclosure, so the useful protection is to take away what an attacker needs next.
type WordPressPolicy struct {
	Enabled bool
	// AllowXMLRPC leaves xmlrpc.php reachable (Jetpack and the mobile app use it). By default it is refused: it
	// allows many password guesses in one request.
	AllowXMLRPC bool
	// LoginPerMinute is how many POSTs to wp-login.php one address may make a minute (default 10).
	LoginPerMinute int
}

var (
	// Executable files under the directories WordPress writes to. Nothing legitimate is run from there.
	wpWritable = regexp.MustCompile(`(?i)^/wp-content/(uploads|cache|upgrade|backup[^/]*|backups[^/]*|ai1wm-backups|updraft|wc-logs|wflogs|et-cache|litespeed)(/|$)`)
	wpScript   = regexp.MustCompile(`(?i)\.(php[0-9]?|phtml|pht|phps|phar|shtml?)(/|$)`)
)

func (e *Edge) checkWordPress(w http.ResponseWriter, r *http.Request, client netip.Addr) bool {
	// Empty segments, a trailing slash, path parameters and path info do not change which script PHP runs.
	p := routePath(r.URL.Path)
	if wpWritable.MatchString(p) && wpScript.MatchString(p) {
		e.refuse(w, r, http.StatusForbidden, idWordPressPHP, "a script is requested from a directory WordPress only writes data to")
		return false
	}
	if runsScript(p, "/xmlrpc.php") && !e.cfg.WordPress.AllowXMLRPC {
		e.refuse(w, r, http.StatusForbidden, idXMLRPC, "xmlrpc.php is switched off")
		return false
	}
	if runsScript(p, "/wp-login.php") && r.Method == http.MethodPost {
		perMinute := e.cfg.WordPress.LoginPerMinute
		if perMinute <= 0 {
			perMinute = 10
		}
		return e.checkRate(w, r, "login:"+clientKey(client), perMinute, idRateLimited, "too many login attempts from one address")
	}
	return true
}

// runsScript reports a route path that runs script, directly or with path info after it.
func runsScript(p, script string) bool { return p == script || strings.HasPrefix(p, script+"/") }
