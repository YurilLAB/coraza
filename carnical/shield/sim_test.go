// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A simulation of a small business site under distributed attacks, on a simulated clock, through the real Shield: every
// request is a real *http.Request through Admit, Write's decisions and Done. The site's application can serve
// originCapacity requests a second; beyond that, requests fail (503 from the origin), which is what a flood does to an
// unprotected site. Ordinary traffic is people: returning visitors (who become known before the attack) and new visitors,
// each visit a page and three assets, from a mix of browsers. Attacks come from tens of thousands of addresses spread
// over hundreds of networks and dozens of countries.

const defaultCapacity = 200

var browsers = [][]string{
	{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36", "Accept-Language", "en-AU,en;q=0.9", "Accept-Encoding", "gzip, deflate, br, zstd", "Sec-Ch-Ua", `"Chromium";v="141"`},
	{"User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1", "Accept-Language", "en-AU", "Accept-Encoding", "gzip, deflate, br"},
	{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0", "Accept-Language", "en-GB,en;q=0.5", "Accept-Encoding", "gzip, deflate, br, zstd"},
	{"User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15", "Accept-Language", "en-US", "Accept-Encoding", "gzip, deflate, br"},
	{"User-Agent", "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Mobile Safari/537.36", "Accept-Language", "en-AU,en;q=0.9", "Accept-Encoding", "gzip, deflate, br, zstd", "Sec-Ch-Ua", `"Chromium";v="141"`},
	{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36 Edg/141.0", "Accept-Language", "en-AU,en;q=0.9", "Accept-Encoding", "gzip, deflate, br, zstd", "Sec-Ch-Ua", `"Microsoft Edge";v="141"`},
}

var countries = strings.Fields("BR US ID VN IN CN RU TR MX AR CO PH TH EG ZA NG PK BD UA PL DE FR IT ES GB KR JP TW MY IR")

// fakeLabeler gives each /8 a country, the way a real table would give each allocation one.
type fakeLabeler struct{}

func (fakeLabeler) Label(a netip.Addr) string {
	b := a.As4()
	return countries[int(b[0])%len(countries)] + " AS" + strconv.Itoa(64500+int(b[0]))
}

type simVisitor struct {
	addr    netip.Addr
	browser int
	cookie  *http.Cookie
}

type sim struct {
	t        *testing.T
	s        *Shield
	clock    time.Time
	r        *rand.Rand
	served   int // requests the origin served this second
	known    []*simVisitor
	stats    map[string]*tally
	nextIP   uint32
	capacity int          // requests a second the application can serve
	kv, nv   int          // visits a second by returning and by new visitors
	shared   []netip.Addr // addresses with many visitors behind them (a company, a mobile carrier)
	app      []string     // when set, every visit is the mobile app calling one API endpoint
	natShare float64      // the share of returning visits that come through them
}

type tally struct{ sent, ok int }

func (t *tally) rate() float64 {
	if t.sent == 0 {
		return 1
	}
	return float64(t.ok) / float64(t.sent)
}

func newSim(t *testing.T, mod func(*Config)) *sim {
	m := &sim{t: t, clock: time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC), r: rand.New(rand.NewPCG(7, 11)), stats: map[string]*tally{}, nextIP: 1, capacity: defaultCapacity, kv: 4, nv: 4}
	cfg := Config{Now: func() time.Time { return m.clock }, ChallengeBits: 8, Labeler: fakeLabeler{}}
	if mod != nil {
		mod(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	m.s = s
	for i := 0; i < 400; i++ {
		m.known = append(m.known, &simVisitor{addr: m.legitAddr(), browser: i % len(browsers)})
	}
	return m
}

// legitAddr is a fresh address for a person: the site's audience is mostly in a few countries' networks.
func (m *sim) legitAddr() netip.Addr {
	m.nextIP++
	n := m.nextIP
	return netip.AddrFrom4([4]byte{byte(100 + n%20), byte(n >> 16), byte(n >> 8), byte(n)})
}

func (m *sim) tally(name string) *tally {
	if m.stats[name] == nil {
		m.stats[name] = &tally{}
	}
	return m.stats[name]
}

// do sends one request and reports whether the visitor got what they asked for (from the origin, within its capacity).
// A browser that is shown the challenge answers it, as a real one does, and then asks again.
func (m *sim) do(class string, v *simVisitor, path string, nav bool, headers []string) bool {
	tl := m.tally(class)
	tl.sent++
	for attempt := 0; attempt < 2; attempt++ {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header = http.Header{}
		for i := 0; i+1 < len(headers); i += 2 {
			r.Header.Set(headers[i], headers[i+1])
		}
		if nav {
			r.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
			r.Header.Set("Sec-Fetch-Mode", "navigate")
		} else if strings.HasPrefix(class, "legit") {
			r.Header.Set("Accept", "*/*")
			r.Header.Set("Sec-Fetch-Mode", "no-cors")
		}
		if v.cookie != nil {
			r.AddCookie(v.cookie)
		}
		d := m.s.Admit(r, v.addr)
		switch d.Action {
		case Allow:
			ok := m.served < m.capacity
			if ok {
				m.served++
				m.s.Done(d, 200, true)
				tl.ok++
			} else {
				m.s.Done(d, 503, true)
			}
			return ok
		case Challenge:
			if !strings.HasPrefix(class, "legit") || attempt > 0 {
				return false // bots do not run the page; a person who failed twice gives up
			}
			tok := m.s.token(SourceKey(v.addr), m.clock)
			vr := httptest.NewRequest(http.MethodGet, VerifyPath+"?t="+tok+"&n="+solve(tok, 8)+"&to=/", nil)
			vr.Header.Set("User-Agent", r.Header.Get("User-Agent"))
			vd := m.s.Admit(vr, v.addr)
			if vd.Action != Respond || vd.resp.cookie == nil {
				return false
			}
			v.cookie = vd.resp.cookie
			m.tally(class+" challenged").sent++
		default:
			return false
		}
	}
	return false
}

// visit is a person loading a page and its assets.
func (m *sim) visit(class string, v *simVisitor) {
	if m.app != nil {
		for i := 0; i < 4; i++ {
			m.do(class, v, "/api/v2/feed?cursor="+strconv.Itoa(m.r.IntN(1e6)), false, m.app)
		}
		return
	}
	h := browsers[v.browser]
	m.do(class, v, "/blog/post-"+strconv.Itoa(m.r.IntN(40)), true, h)
	for _, a := range []string{"/static/site.css", "/static/site.js", "/img/" + strconv.Itoa(m.r.IntN(60)) + ".jpg"} {
		m.do(class, v, a, false, h)
	}
}

// second runs one simulated second: visits from known and new people, and n attack requests from attack().
func (m *sim) second(visitsKnown, visitsNew, attackN int, attack func(i int)) {
	m.served = 0
	start := m.clock
	total := visitsKnown + visitsNew + attackN
	step := time.Second / time.Duration(max(total, 1)+1)
	order := m.r.Perm(total)
	for _, k := range order {
		m.clock = m.clock.Add(step)
		switch {
		case k < visitsKnown:
			v := m.known[m.r.IntN(len(m.known))]
			if len(m.shared) > 0 && m.r.Float64() < m.natShare {
				v = &simVisitor{addr: m.shared[m.r.IntN(len(m.shared))], browser: v.browser}
			}
			m.visit("legit known", v)
		case k < visitsKnown+visitsNew:
			m.visit("legit new", &simVisitor{addr: m.legitAddr(), browser: m.r.IntN(len(browsers))})
		default:
			attack(k - visitsKnown - visitsNew)
		}
	}
	m.clock = start.Add(time.Second)
	m.s.Tick()
}

// warm runs ordinary traffic long enough for the baseline to settle and the returning visitors to become known.
func (m *sim) warm(minutes int) {
	for i := 0; i < minutes*60; i++ {
		m.second(m.kv, m.nv, 0, nil)
	}
	if st := m.s.State(); st != Normal {
		m.t.Fatalf("after warm-up the state is %v", st)
	}
	m.stats = map[string]*tally{}
}

// botnet is n addresses spread over many /8s (countries) and /16s.
func botnet(n int, r *rand.Rand) []*simVisitor {
	out := make([]*simVisitor, n)
	for i := range out {
		out[i] = &simVisitor{addr: netip.AddrFrom4([4]byte{byte(1 + r.IntN(90)), byte(r.IntN(256)), byte(r.IntN(256)), byte(1 + r.IntN(254))})}
	}
	return out
}

type result struct {
	detectedAfter  int // seconds; -1 if never
	attackAdmitted float64
	known, new     float64
	inc            *Incident
	maxState       State
}

func (r result) String() string {
	return fmt.Sprintf("detected after %ds, attack admitted %.2f%%, returning visitors served %.1f%%, new visitors served %.1f%%",
		r.detectedAfter, 100*r.attackAdmitted, 100*r.known, 100*r.new)
}

// run sends ordinary traffic plus an attack of perSecond requests a second for seconds seconds.
func (m *sim) run(seconds, perSecond int, attack func(i int)) result {
	res := result{detectedAfter: -1}
	var admittedAfter, sentAfter int
	var knownAt, newAt tally // the visitors' tallies when the attack was detected
	for sec := 0; sec < seconds; sec++ {
		before := *m.tally("attack")
		m.second(m.kv, m.nv, perSecond, attack)
		st := m.s.State()
		if st > res.maxState {
			res.maxState = st
		}
		if st == Attack && res.detectedAfter < 0 {
			res.detectedAfter = sec + 1
			knownAt, newAt = *m.tally("legit known"), *m.tally("legit new")
		}
		if res.detectedAfter >= 0 && sec >= res.detectedAfter {
			after := m.tally("attack")
			admittedAfter += after.ok - before.ok
			sentAfter += after.sent - before.sent
		}
	}
	if sentAfter > 0 {
		res.attackAdmitted = float64(admittedAfter) / float64(sentAfter)
	}
	// Visitors are counted from the moment of detection: before it, the flood has the origin to itself, which is the
	// price of not acting on traffic until it is known to be an attack.
	k, n := m.tally("legit known"), m.tally("legit new")
	if res.detectedAfter < 0 {
		knownAt, newAt = tally{}, tally{}
	}
	res.known = (&tally{sent: k.sent - knownAt.sent, ok: k.ok - knownAt.ok}).rate()
	res.new = (&tally{sent: n.sent - newAt.sent, ok: n.ok - newAt.ok}).rate()
	if snap := m.s.Snapshot(); snap.Current != nil {
		res.inc = snap.Current
	}
	return res
}

func TestSimulatedAttacks(t *testing.T) {
	if testing.Short() {
		t.Skip("simulation")
	}
	python := []string{"User-Agent", "python-requests/2.32.3", "Accept", "*/*", "Accept-Encoding", "gzip, deflate", "Connection", "keep-alive"}

	t.Run("a botnet of 20,000 addresses in 30 countries, 5,000 requests a second, cache-busting the home page", func(t *testing.T) {
		m := newSim(t, nil)
		m.warm(10)
		bots := botnet(20_000, m.r)
		res := m.run(90, 5000, func(i int) {
			m.do("attack", bots[m.r.IntN(len(bots))], "/?r="+strconv.Itoa(m.r.IntN(1e9)), false, python)
		})
		t.Log(res)
		t.Logf("incident: %d addresses, %d networks, %d countries/networks labelled; refused %d, banned %d; reasons: %q",
			res.inc.Sources, res.inc.Networks, res.inc.DistinctLabels, res.inc.Refused, res.inc.Banned, res.inc.Reasons)
		if res.detectedAfter < 0 || res.detectedAfter > 10 || res.attackAdmitted > 0.02 || res.known < 0.98 || res.new < 0.9 {
			t.Fatal("protection below the bar")
		}
		if res.inc.Sources < 17_000 || res.inc.Sources > 23_000 || res.inc.DistinctLabels < 25 {
			t.Fatalf("the record misjudges the attack's spread: %+v", res.inc)
		}
	})

	t.Run("the same botnet with the shield in monitor mode (control: the mitigation is what protects)", func(t *testing.T) {
		m := newSim(t, func(c *Config) { c.MonitorOnly = true })
		m.warm(10)
		bots := botnet(20_000, m.r)
		res := m.run(60, 5000, func(i int) {
			m.do("attack", bots[m.r.IntN(len(bots))], "/?r="+strconv.Itoa(m.r.IntN(1e9)), false, python)
		})
		t.Log(res)
		if res.detectedAfter < 0 || res.known > 0.2 {
			t.Fatal("monitor mode either missed the attack or the simulated origin is not overwhelmed (the test proves nothing)")
		}
	})

	t.Run("bots that copy a real browser exactly, loading a search page from 30,000 addresses", func(t *testing.T) {
		m := newSim(t, nil)
		m.warm(10)
		bots := botnet(30_000, m.r)
		res := m.run(90, 3000, func(i int) {
			m.do("attack", bots[m.r.IntN(len(bots))], "/search?q="+strconv.Itoa(m.r.IntN(1e9)), true, browsers[0])
		})
		t.Log(res)
		t.Logf("reasons: %q", res.inc.Reasons)
		if res.detectedAfter < 0 || res.detectedAfter > 12 || res.attackAdmitted > 0.03 || res.known < 0.98 || res.new < 0.85 {
			t.Fatal("protection below the bar")
		}
	})

	t.Run("low and slow: 10,000 addresses, each one request every 20 seconds", func(t *testing.T) {
		m := newSim(t, nil)
		m.warm(10)
		bots := botnet(10_000, m.r)
		res := m.run(90, 500, func(i int) {
			m.do("attack", bots[m.r.IntN(len(bots))], "/wp-login.php", false, python)
		})
		t.Log(res)
		if res.detectedAfter < 0 || res.detectedAfter > 12 || res.attackAdmitted > 0.05 || res.known < 0.98 {
			t.Fatal("protection below the bar")
		}
	})

	// A patient botnet: 2,000 addresses that each loaded the home page every 100 seconds, like a person, for ten minutes before
	// the attack, and so earned standing. The control gives standing no budget of its own (as before the standing budget
	// existed): the bots then go straight through.
	patient := func(t *testing.T, mod func(*Config)) result {
		m := newSim(t, mod)
		bots := botnet(2_000, m.r)
		for i := range bots {
			bots[i].browser = 0
		}
		for sec := 0; sec < 10*60; sec++ {
			m.second(m.kv, m.nv, 20, func(i int) {
				b := bots[(sec*20+i)%len(bots)]
				m.do("bots earning standing", b, "/", true, browsers[0])
			})
		}
		if st := m.s.State(); st != Normal {
			t.Fatalf("after warm-up the state is %v", st)
		}
		m.stats = map[string]*tally{}
		return m.run(90, 3000, func(i int) {
			m.do("attack", bots[m.r.IntN(len(bots))], "/search?q="+strconv.Itoa(m.r.IntN(1e9)), true, browsers[0])
		})
	}
	t.Run("a botnet that earned standing before it attacks, copying a real browser", func(t *testing.T) {
		res := patient(t, nil)
		t.Log(res)
		if res.detectedAfter < 0 || res.detectedAfter > 12 || res.attackAdmitted > 0.05 || res.known < 0.95 || res.new < 0.85 {
			t.Fatal("protection below the bar")
		}
	})
	t.Run("the same botnet with standing unbudgeted (control: the standing budget is what holds it)", func(t *testing.T) {
		res := patient(t, func(c *Config) { c.KnownFactor = 1e6 })
		t.Log(res)
		if res.detectedAfter < 0 || res.known > 0.2 {
			t.Fatal("with standing unbudgeted the attack was missed or visitors were still served: the simulation does not test the budget")
		}
	})

	t.Run("a newsletter sends a crowd to one article whose assets are on another host (taken for an attack, people still served)", func(t *testing.T) {
		m := newSim(t, nil)
		m.warm(10)
		crowd := func(i int) {
			v := &simVisitor{addr: m.legitAddr(), browser: m.r.IntN(len(browsers))}
			m.do("legit new", v, "/blog/big-news", true, browsers[v.browser])
		}
		res := m.run(90, 150, crowd) // within what the origin can serve: the question is only what the shield does
		t.Logf("highest state %v; %s; reasons %q", res.maxState, res, m.s.Snapshot().Reasons)
		if all := m.tally("legit new").rate(); all < 0.95 {
			t.Fatalf("only %.1f%% of the crowd was served", 100*all)
		}
	})

	t.Run("a flash crowd of real people (negative control: not an attack)", func(t *testing.T) {
		m := newSim(t, nil)
		m.warm(10)
		res := result{detectedAfter: -1}
		for sec := 0; sec < 120; sec++ {
			m.second(4, 40, 0, nil) // ten times the visits, almost all new, every browser, pages and assets
			if st := m.s.State(); st > res.maxState {
				res.maxState = st
			}
		}
		t.Logf("highest state %v; new visitors served %.1f%%", res.maxState, 100*m.tally("legit new").rate())
		if res.maxState == Attack {
			t.Fatalf("a crowd of people was taken for an attack: %q", m.s.Snapshot().Reasons)
		}
	})
}

// busy builds a site with ten times the traffic of the one above, a share of whose returning visitors come through a few
// addresses that carry many people each (a company's gateway, a mobile carrier's), which any fixed per-address limit
// treats as attackers.
func busy(t *testing.T, mod func(*Config)) *sim {
	m := newSim(t, mod)
	m.capacity, m.kv, m.nv = 4000, 240, 60 // 1,200 requests a second of ordinary traffic
	m.natShare = 0.5
	for i := 1; i <= 4; i++ {
		m.shared = append(m.shared, netip.AddrFrom4([4]byte{100, 64, 0, byte(i)}))
	}
	for i := 0; i < 4000; i++ {
		m.known = append(m.known, &simVisitor{addr: m.legitAddr(), browser: i % len(browsers)})
	}
	return m
}

func TestASiteWithMuchTrafficIsNotLimitedAsIfItWereSmall(t *testing.T) {
	if testing.Short() {
		t.Skip("simulation")
	}
	python := []string{"User-Agent", "python-requests/2.32.3", "Accept", "*/*", "Accept-Encoding", "gzip, deflate", "Connection", "keep-alive"}

	t.Run("visitors behind shared addresses are served, because the limits follow the site's own busiest addresses", func(t *testing.T) {
		m := busy(t, nil)
		for i := 0; i < 8*60; i++ {
			m.second(m.kv, m.nv, 0, nil)
		}
		snap := m.s.Snapshot()
		t.Logf("state %v, usual %.0f requests a second; per-address limit raised %.1fx, per-network %.1fx; legit served %.2f%%",
			snap.State, snap.BaselineRate, snap.RequestScale, snap.NetworkScale, 100*m.tally("legit known").rate())
		if snap.State == Attack {
			t.Fatalf("ordinary busy traffic was taken for an attack: %q", snap.Reasons)
		}
		m.stats = map[string]*tally{}
		for i := 0; i < 60; i++ {
			m.second(m.kv, m.nv, 0, nil)
		}
		if got := m.tally("legit known").rate(); got < 0.995 {
			t.Fatalf("only %.2f%% of returning visitors (half of them behind shared addresses) were served", 100*got)
		}
	})

	t.Run("control: with the limits fixed, the same visitors are refused", func(t *testing.T) {
		m := busy(t, func(c *Config) { c.Detector.MaxScale = 1 })
		for i := 0; i < 8*60; i++ {
			m.second(m.kv, m.nv, 0, nil)
		}
		got := m.tally("legit known").rate()
		t.Logf("legit returning visitors served with fixed limits: %.1f%%", 100*got)
		if got > 0.9 {
			t.Fatalf("with fixed limits %.1f%% were served: the simulated site does not stress them, so the test above proves nothing", 100*got)
		}
	})

	t.Run("an attack of 8,000 requests a second from 25,000 addresses on a site that serves 1,200", func(t *testing.T) {
		m := busy(t, nil)
		for i := 0; i < 8*60; i++ {
			m.second(m.kv, m.nv, 0, nil)
		}
		m.stats = map[string]*tally{}
		bots := botnet(25_000, m.r)
		res := m.run(60, 8000, func(i int) {
			m.do("attack", bots[m.r.IntN(len(bots))], "/?r="+strconv.Itoa(m.r.IntN(1e9)), false, python)
		})
		t.Log(res)
		if res.detectedAfter < 0 || res.detectedAfter > 12 || res.attackAdmitted > 0.02 || res.known < 0.98 || res.new < 0.9 {
			t.Fatal("protection below the bar")
		}
	})

	t.Run("a sudden tripling of real traffic is not an attack", func(t *testing.T) {
		m := busy(t, nil)
		for i := 0; i < 8*60; i++ {
			m.second(m.kv, m.nv, 0, nil)
		}
		m.stats = map[string]*tally{}
		worst := Normal
		for i := 0; i < 120; i++ {
			m.second(3*m.kv, 3*m.nv, 0, nil)
			if st := m.s.State(); st > worst {
				worst = st
			}
		}
		t.Logf("highest state %v; returning %.1f%%, new %.1f%% served", worst, 100*m.tally("legit known").rate(), 100*m.tally("legit new").rate())
		if worst == Attack {
			t.Fatalf("a tripling of ordinary visits was taken for an attack: %q", m.s.Snapshot().Reasons)
		}
	})
}

// A steady site and a bursty one with the same average must not have the same threshold: the bursty one has to see more
// before it calls it an attack, because its own ordinary traffic already swings that far.
func TestTheRateThresholdFollowsTheSitesOwnVariation(t *testing.T) {
	drive := func(burst bool) (mean, threshold float64) {
		now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
		d := newDetector(DetectorConfig{Warmup: 2 * time.Minute, Tau: 5 * time.Minute})
		n := uint32(0)
		for sec := 0; sec < 40*60; sec++ {
			rate := 200
			if burst && sec%37 < 5 { // five seconds in thirty-seven at six times the rate
				rate = 1200
			}
			if burst && sec%37 >= 5 {
				rate = 120
			}
			for i := 0; i < rate; i++ {
				n++
				a := netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)})
				d.observe(now.Add(time.Duration(sec)*time.Second+time.Duration(i)*time.Millisecond).UnixNano(), a, 1, "x", 2, "/")
			}
			d.tick(now.Add(time.Duration(sec+1) * time.Second).UnixNano())
		}
		d.mu.Lock()
		mean = d.base.rate
		d.mu.Unlock()
		return mean, d.rateThreshold()
	}
	sMean, sThr := drive(false)
	bMean, bThr := drive(true)
	t.Logf("steady: mean %.0f/s, threshold %.0f/s (%.1fx); bursty: mean %.0f/s, threshold %.0f/s (%.1fx)", sMean, sThr, sThr/sMean, bMean, bThr, bThr/bMean)
	if sThr < 3.9*sMean || sThr > 4.4*sMean {
		t.Fatalf("a steady site's threshold is %.1fx its average, want about 4x", sThr/sMean)
	}
	if bThr/bMean < 1.25*sThr/sMean {
		t.Fatalf("a bursty site's threshold (%.1fx) is not clearly above a steady site's (%.1fx)", bThr/bMean, sThr/sMean)
	}
}

// A site that is already busy when the proxy starts (a first deployment, a restart) has no baseline: its first seconds
// must not be taken for an attack, and a state of "attack" must always be able to end.
func TestABusySiteIsNotAnAttackWhenTheProxyStarts(t *testing.T) {
	if testing.Short() {
		t.Skip("simulation")
	}
	m := busy(t, nil)
	worst, attackSeconds := Normal, 0
	for i := 0; i < 10*60; i++ {
		m.second(m.kv, m.nv, 0, nil)
		st := m.s.State()
		if st > worst {
			worst = st
		}
		if st == Attack {
			attackSeconds++
		}
	}
	t.Logf("first ten minutes of a site serving 1,200 requests a second, no baseline: highest state %v, %d seconds in attack; new visitors served %.1f%%",
		worst, attackSeconds, 100*m.tally("legit new").rate())
	if attackSeconds > 0 {
		t.Fatalf("a busy site's first minutes were taken for an attack: %q", m.s.Snapshot().Reasons)
	}
	if got := m.tally("legit new").rate(); got < 0.99 {
		t.Fatalf("new visitors served %.1f%%", 100*got)
	}
}

func TestAnAttackThatShowsNoEvidenceForFiveMinutesEnds(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	d := newDetector(DetectorConfig{Warmup: 2 * time.Minute, Tau: 5 * time.Minute, MinAttack: 30 * time.Second, EvidenceTimeout: 3 * time.Minute})
	n := uint32(0)
	feed := func(sec, rate int, fp uint64, path uint64, variety uint32) {
		for i := 0; i < rate; i++ {
			n++
			a := netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)})
			d.observe(now.Add(time.Duration(sec)*time.Second).UnixNano(), a, fp+uint64(n%variety), "x", path+uint64(n%variety), "/")
			d.count(now.Add(time.Duration(sec)*time.Second).UnixNano(), func(w *window) { w.engaged++ })
		}
		d.tick(now.Add(time.Duration(sec+1) * time.Second).UnixNano())
	}
	sec := 0
	for ; sec < 300; sec++ {
		feed(sec, 100, 1, 100, 8) // eight fingerprints and eight targets, ordinary
	}
	if d.state == Attack {
		t.Fatal("the attack was declared during ordinary traffic")
	}
	for ; sec < 330; sec++ {
		feed(sec, 1500, 500, 900, 1) // one program, one target: an attack
	}
	if d.state != Attack {
		t.Fatalf("the attack was not declared (state %v)", d.state)
	}
	// The rate stays high but the evidence is gone (the traffic is now as varied as ordinary traffic).
	ended := -1
	for ; sec < 330+600; sec++ {
		for i := 0; i < 1500; i++ {
			n++
			a := netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)})
			d.observe(now.Add(time.Duration(sec)*time.Second).UnixNano(), a, 1+uint64(n%8), "x", 100+uint64(n%8), "/")
			d.count(now.Add(time.Duration(sec)*time.Second).UnixNano(), func(w *window) { w.engaged++ })
		}
		d.tick(now.Add(time.Duration(sec+1) * time.Second).UnixNano())
		if d.state != Attack && ended < 0 {
			ended = sec - 330
		}
	}
	if ended < 0 {
		t.Fatal("the attack never ended although nothing shows it any more")
	}
	t.Logf("with traffic still at 15x but nothing to show an attack, the attack ended %d seconds later (timeout 180)", ended)
	if ended < 150 || ended > 260 {
		t.Fatalf("it ended after %d seconds, want about the 180-second timeout", ended)
	}
}

// Traffic that is naturally concentrated (one mobile app calling one endpoint, which is most of what an API serves) has
// exactly the look of a flood to a detector that has not yet learnt it: one fingerprint, one target, all of the traffic.
// That must not be taken for an attack when the proxy starts, nor ever.
func TestAnAPIServedToOneAppIsNotAnAttackWhenTheProxyStarts(t *testing.T) {
	if testing.Short() {
		t.Skip("simulation")
	}
	m := busy(t, nil)
	m.app = []string{"User-Agent", "ExampleApp/5.2 (iOS 18.6; iPhone16,2) Alamofire/5.9", "Accept", "application/json", "Accept-Encoding", "gzip, br"}
	attackSeconds := 0
	for i := 0; i < 10*60; i++ {
		m.second(m.kv, m.nv, 0, nil)
		if m.s.State() == Attack {
			attackSeconds++
		}
	}
	t.Logf("first ten minutes of an API serving 1,200 requests a second to one app, no baseline: %d seconds in attack; served %.2f%% (returning) %.2f%% (new)",
		attackSeconds, 100*m.tally("legit known").rate(), 100*m.tally("legit new").rate())
	if attackSeconds > 0 {
		t.Fatalf("the app's own traffic was taken for an attack: %q", m.s.Snapshot().Reasons)
	}
	if m.tally("legit new").rate() < 0.99 {
		t.Fatalf("new devices were refused")
	}
}

// Traffic that arrives in bursts from the moment the proxy starts: the first seconds look like a rise of several times
// "the usual", because nothing is usual yet. Nothing may be declared an attack until a baseline exists, and an attack
// declared on no baseline must not be able to stay.
func TestBurstyTrafficFromTheFirstSecondIsNotAnAttack(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	d := newDetector(DetectorConfig{Warmup: 2 * time.Minute, Tau: 5 * time.Minute})
	n := uint32(0)
	attackSeconds := 0
	for sec := 0; sec < 20*60; sec++ {
		rate := 120
		if sec%37 < 5 {
			rate = 1200 // five seconds in thirty-seven at ten times the rest
		}
		at := now.Add(time.Duration(sec) * time.Second).UnixNano()
		for i := 0; i < rate; i++ {
			n++
			a := netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)})
			d.observe(at, a, 1, "one program", 2, "/api/feed")
			d.count(at, func(w *window) { w.engaged++ })
		}
		d.tick(now.Add(time.Duration(sec+1) * time.Second).UnixNano())
		if d.state == Attack {
			attackSeconds++
		}
	}
	d.mu.Lock()
	mean := d.base.rate
	d.mu.Unlock()
	t.Logf("20 minutes of bursty traffic (mean %.0f requests a second) from a cold start: %d seconds in attack", mean, attackSeconds)
	if attackSeconds > 0 {
		t.Fatalf("%d seconds of ordinary bursty traffic were taken for an attack", attackSeconds)
	}
}
