// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"math"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// The detector decides whether the site is under a denial-of-service attack. It cannot do it by looking at addresses
// one at a time: a botnet of residential routers, cameras and phones sends from tens of thousands of addresses in many
// countries, each one slower than any per-address limit. What gives such an attack away is what all those addresses have
// in common and what they lack compared with the site's ordinary traffic:
//
//   - volume: the request rate is several times the site's own recent baseline, and above an absolute floor;
//   - concentration: one client fingerprint (one program) or one target is a far larger share of the traffic than it
//     usually is;
//   - spread: a burst of addresses that have not been seen before, or many more different addresses than usual;
//   - no engagement: new visitors that are people load a page and then its assets; a flood of new addresses that each
//     ask for one thing and nothing else is not people;
//   - pain: the application starts failing or slowing down.
//
// Volume alone is not an attack (a newsletter goes out, a post is shared), and the detector says so ("elevated") without
// acting. Volume with a concentrated fingerprint from many sources, or with a concentrated target from new sources that
// do not behave like browsers, or with the application in pain and the traffic coming from new places, is an attack.
//
// Everything is measured in one-second windows; decisions use the last ten seconds against a baseline that is an
// exponentially weighted average of the same measures, updated only while the site is not under attack, so that an
// attack cannot teach the detector that it is normal.

// State is what the detector thinks is happening.
type State uint8

const (
	// Normal: nothing unusual.
	Normal State = iota
	// Elevated: much more traffic than usual, without the signs of an attack. Nothing extra is done; it is reported.
	Elevated
	// Attack: the mitigations are on (see Shield.Admit).
	Attack
)

func (s State) String() string {
	switch s {
	case Elevated:
		return "elevated"
	case Attack:
		return "attack"
	}
	return "normal"
}

// DetectorConfig tunes the detector. The zero value of each field means its default.
type DetectorConfig struct {
	// Warmup is how long the baseline learns before it is used with its full weight (default 5 minutes). During warm-up
	// the baseline is the plain average of what has been seen.
	Warmup time.Duration
	// Tau is the time constant of the baseline's moving average (default 10 minutes): long enough that an attack that
	// ramps up over a minute stands out, short enough to follow a site's ordinary daily rise and fall.
	Tau time.Duration
	// MinAttackRate is an absolute floor, in requests a second, under which traffic is never an attack (default 20): a
	// small site that goes from 1 to 10 requests a second is not under attack. It only matters to small sites. What
	// decides for every other site is the site's own average and variation: the traffic must exceed the larger of
	// RateFactor times the moving average and the average plus Sigmas standard deviations of the site's own recent rates.
	MinAttackRate float64
	// Sigmas is how many standard deviations above the moving average the rate must be (default 8). The deviation is the
	// site's own, measured on the same ten-second rates and learnt the same way, so a site whose traffic is bursty has to
	// exceed more than a site whose traffic is steady.
	Sigmas float64
	// LimitMargin and MaxScale make the per-address and per-network limits follow the site's own traffic: each limit is
	// raised to LimitMargin (default 4) times the moving average of the busiest address's (or network's) request rate
	// when that is higher than the configured limit, up to MaxScale (default 20) times the configured limit. A busy site
	// with many visitors behind one company or mobile-carrier address is not limited as if each address were one person.
	LimitMargin, MaxScale float64
	// EvidenceTimeout ends an attack that has gone on this long (default 5 minutes) without any of the evidence that
	// declared it (concentration, spread, harm), even if the traffic has not fallen: a baseline that stopped learning
	// when the attack began must never be able to hold a site in "attack" for ever.
	EvidenceTimeout time.Duration
	// MinHistory is how long the detector must have been running before it can declare an attack (default 60 seconds): with
	// less data nothing is known about what is usual. Until Warmup has passed, only a rise of 2.5 times RateFactor counts.
	MinHistory time.Duration
	// RateFactor is how many times the baseline rate the traffic must be for there to be an attack (default 4).
	RateFactor float64
	// ExitFactor is how far the rate must fall, relative to the baseline at the start of the attack, before the attack
	// can be over (default 2).
	ExitFactor float64
	// Confirm is how many consecutive seconds the evidence must hold before the mitigations start (default 3).
	Confirm int
	// MinAttack is the shortest an attack lasts once declared (default 60 seconds): attackers pulse their floods to make
	// a defence switch off and on.
	MinAttack time.Duration
	// ExitQuiet is how long the traffic must stay below the exit rate before the attack is over (default 30 seconds).
	ExitQuiet time.Duration
	// MinClusterSources is how many different addresses must share a fingerprint for it to count as a distributed
	// cluster (default 20). Fewer is a handful of clients, which the per-address limits deal with.
	MinClusterSources int
	// SeenPeriod is how long an address is remembered as seen (between one and two periods; default 12 hours).
	SeenPeriod time.Duration
	// InitialRate, if set, is the baseline request rate to start from instead of learning it from nothing, so that a
	// restart during an attack does not take the attack for normal traffic.
	InitialRate float64
}

func (c *DetectorConfig) defaults() {
	def := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	deff := func(f *float64, v float64) {
		if *f == 0 {
			*f = v
		}
	}
	def(&c.Warmup, 5*time.Minute)
	def(&c.Tau, 10*time.Minute)
	def(&c.MinAttack, time.Minute)
	def(&c.ExitQuiet, 30*time.Second)
	def(&c.EvidenceTimeout, 5*time.Minute)
	def(&c.MinHistory, time.Minute)
	def(&c.SeenPeriod, 12*time.Hour)
	deff(&c.MinAttackRate, 20)
	deff(&c.Sigmas, 8)
	deff(&c.LimitMargin, 4)
	deff(&c.MaxScale, 20)
	deff(&c.RateFactor, 4)
	deff(&c.ExitFactor, 2)
	if c.Confirm == 0 {
		c.Confirm = 3
	}
	if c.MinClusterSources == 0 {
		c.MinClusterSources = 20
	}
}

const (
	ringSeconds = 64 // windows kept; the last aggSeconds are used for decisions
	aggSeconds  = 10
	topKeys     = 16
	baseKeys    = 64
)

type window struct {
	sec                                      int64
	reqs, newSrcs, engaged                   uint32
	done, errs, latN                         uint32
	refused, challenged, solved, banned      uint32
	connsIn, connsRefused                    uint32
	connClosed, earlyCloses, securityRejects uint32
	maxSrc, maxNet                           uint32  // the most requests one address, and one network, sent in this second
	lat                                      float64 // milliseconds, summed over latN
	srcs, nets                               hll
	fps, paths                               topK
}

func (w *window) reset(sec int64) {
	srcs, nets, fps, paths := w.srcs, w.nets, w.fps, w.paths
	srcs.reset()
	nets.reset()
	fps.reset()
	paths.reset()
	*w = window{sec: sec, srcs: srcs, nets: nets, fps: fps, paths: paths}
}

// share is one fingerprint or target and its part of the traffic over the last ten seconds.
type share struct {
	key     uint64
	label   string
	share   float64
	sources float64
}

// aggregate is the last ten seconds.
type aggregate struct {
	rate, srcs, nets, newShare, newSrcs  float64
	engagement                           float64 // -1 when too few new sources to tell
	errRatio, lat                        float64 // -1 when nothing completed
	connRate, connRefused                float64
	closed, earlyCloses, securityRejects float64
	refused, challenged                  float64
	peakSrc, peakNet                     float64 // the busiest address's and network's requests a second, averaged over the ten seconds
	fps, paths                           []share
}

type baseline struct {
	rate, rateVar, srcs, newShare, errRatio, lat, connRate float64
	peakSrc, peakNet                                       float64
	lastSample                                             float64
	sampled                                                bool
	fps, paths                                             map[uint64]float64
}

// attackInfo is what the request path needs to know during an attack. It is replaced as a whole and read without a lock.
type attackInfo struct {
	epoch        uint32
	since        int64 // when the attack began
	fps, paths   map[uint64]bool
	unknownRate  float64
	clusterRate  float64
	knownRate    float64
	pathAttack   bool
	fingerprints int
}

type detector struct {
	cfg DetectorConfig

	mu         sync.Mutex
	ring       [ringSeconds]window
	cur        int
	curSec     int64
	started    bool
	seen       seenFilter
	rotated    int64
	base       baseline
	age        int
	state      State
	run        int // consecutive seconds of evidence
	since      int64
	quiet      int
	noEvidence int      // consecutive seconds of attack without evidence
	frozen     baseline // the baseline when the attack began
	epoch      uint32
	last       aggregate
	reasons    []string
	scratchS   hll
	scratchN   hll
	incident   *incidentAcc
	history    []Incident

	info atomic.Pointer[attackInfo]
	// learning is true while traffic is ordinary: no attack, no traffic above the usual, no evidence building up. Clients
	// earn their standing only then.
	learning atomic.Bool
	// winMaxSrc and winMaxNet are the most requests one address, and one network, has sent in the current second; the
	// request path raises them without a lock and the detector takes them when the second ends.
	winMaxSrc, winMaxNet atomic.Uint32
	// scaleSrc and scaleNet (float64 bits) are how far the per-address and per-network limits are raised to follow the
	// site's traffic: 1 for the configured limit.
	scaleSrc, scaleNet atomic.Uint64
	// refSrc and refNet are the configured per-address and per-network request rates the scales apply to.
	refSrc, refNet float64

	// set by the Shield
	labeler      Labeler
	onEvent      func(Event)
	idsReasons   []string
	idsLast      int64
	idsReported  bool
	unknownRate  func(base float64) float64
	knownRate    func(base float64) float64
	clusterRate  float64
	clusterShare float64
}

func newDetector(cfg DetectorConfig) *detector {
	cfg.defaults()
	d := &detector{cfg: cfg, seen: newSeenFilter(), scratchS: newHLL(10), scratchN: newHLL(8)}
	for i := range d.ring {
		d.ring[i] = window{srcs: newHLL(10), nets: newHLL(8), fps: newTopK(topKeys), paths: newTopK(topKeys)}
	}
	d.base = baseline{rate: cfg.InitialRate, fps: map[uint64]float64{}, paths: map[uint64]float64{}}
	if cfg.InitialRate > 0 {
		d.age = int(cfg.Warmup / time.Second)
	}
	return d
}

// netOf is the network an address belongs to for counting how widely an attack is spread: a /24 for IPv4 and a /48 for
// IPv6 (a site or a customer's allocation).
func netOf(a netip.Addr) netip.Prefix {
	if a.Is4() {
		p, _ := a.Prefix(24)
		return p
	}
	p, _ := a.Prefix(48)
	return p
}

// observe counts one request and reports whether its source has not been seen before.
func (d *detector) observe(ns int64, client netip.Addr, fp uint64, fpLabel string, pt uint64, ptLabel string) bool {
	h := hashAddr(client)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.advance(ns)
	w := &d.ring[d.cur]
	w.reqs++
	w.srcs.add(h)
	w.nets.add(maphashPrefix(netOf(client)))
	w.fps.add(fp, fpLabel, h, 1)
	w.paths.add(pt, ptLabel, h, 1)
	isNew := !d.seen.has(h)
	if isNew {
		d.seen.add(h)
		w.newSrcs++
	}
	if inc := d.incident; inc != nil {
		inc.requests++
		inc.srcs.add(h)
		inc.nets.add(maphashPrefix(netOf(client)))
		if d.labeler != nil {
			if l := d.labeler.Label(client); l != "" {
				lh := hashString(l)
				inc.labels.add(lh, l, h, 1)
				inc.labelSet.add(lh)
			}
		}
	}
	return isNew
}

// count records something the Shield did.
func (d *detector) count(ns int64, f func(w *window)) {
	d.mu.Lock()
	d.advance(ns)
	f(&d.ring[d.cur])
	d.mu.Unlock()
}

// note records something the Shield did, in the window and in the attack's record if there is one.
func (d *detector) note(ns int64, f func(w *window, inc *incidentAcc)) {
	d.mu.Lock()
	d.advance(ns)
	f(&d.ring[d.cur], d.incident)
	d.mu.Unlock()
}

// done records a request the application answered (or failed to answer). latency is negative when unknown.
func (d *detector) done(ns int64, status int, latency time.Duration) {
	d.count(ns, func(w *window) {
		w.done++
		if status >= 500 {
			w.errs++
		}
		if latency >= 0 {
			w.lat += float64(latency) / float64(time.Millisecond)
			w.latN++
		}
	})
}

// tick closes the windows that have ended. The Shield calls it every second so that the state moves on while no
// requests arrive.
func (d *detector) tick(ns int64) {
	d.mu.Lock()
	d.advance(ns)
	d.mu.Unlock()
}

func (d *detector) advance(ns int64) {
	sec := ns / 1e9
	if !d.started {
		d.started, d.curSec, d.rotated = true, sec, ns
		d.ring[d.cur].reset(sec)
		return
	}
	if sec <= d.curSec {
		return
	}
	steps := sec - d.curSec
	if steps > ringSeconds {
		// A long silence: the closed windows are empty; evaluate a full ring of them and jump.
		d.curSec = sec - ringSeconds
		steps = ringSeconds
	}
	for i := int64(0); i < steps; i++ {
		closing := &d.ring[d.cur]
		closing.maxSrc, closing.maxNet = d.winMaxSrc.Swap(0), d.winMaxNet.Swap(0)
		d.evaluate((d.curSec + 1) * 1e9)
		d.cur = (d.cur + 1) % ringSeconds
		d.curSec++
		d.ring[d.cur].reset(d.curSec)
	}
	if time.Duration(ns-d.rotated) >= d.cfg.SeenPeriod {
		d.seen.rotate()
		d.rotated = ns
	}
}

// aggregate sums the last aggSeconds closed windows (the current, open one is not included).
func (d *detector) aggregate() aggregate {
	var a aggregate
	var reqs, newSrcs, engaged, done, errs, latN, conns, connsRef, refused, challenged, maxSrc, maxNet, closed, earlyCloses, securityRejects float64
	var lat float64
	d.scratchS.reset()
	d.scratchN.reset()
	type acc struct {
		count float64
		label string
		srcs  hll
	}
	fps := map[uint64]*acc{}
	paths := map[uint64]*acc{}
	merge := func(m map[uint64]*acc, t *topK) {
		for i := range t.e {
			e := &t.e[i]
			x := m[e.key]
			if x == nil {
				x = &acc{label: e.label, srcs: newHLL(6)}
				m[e.key] = x
			}
			x.count += float64(e.count)
			x.srcs.merge(&e.srcs)
		}
	}
	for i := 1; i <= aggSeconds; i++ {
		w := &d.ring[(d.cur-i+ringSeconds)%ringSeconds]
		reqs += float64(w.reqs)
		newSrcs += float64(w.newSrcs)
		engaged += float64(w.engaged)
		done += float64(w.done)
		errs += float64(w.errs)
		latN += float64(w.latN)
		lat += w.lat
		conns += float64(w.connsIn)
		connsRef += float64(w.connsRefused)
		closed += float64(w.connClosed)
		earlyCloses += float64(w.earlyCloses)
		securityRejects += float64(w.securityRejects)
		refused += float64(w.refused)
		maxSrc += float64(w.maxSrc)
		maxNet += float64(w.maxNet)
		challenged += float64(w.challenged)
		d.scratchS.merge(&w.srcs)
		d.scratchN.merge(&w.nets)
		merge(fps, &w.fps)
		merge(paths, &w.paths)
	}
	a.rate = reqs / aggSeconds
	a.peakSrc, a.peakNet = maxSrc/aggSeconds, maxNet/aggSeconds
	a.connRate = conns / aggSeconds
	a.connRefused = connsRef / aggSeconds
	a.closed, a.earlyCloses, a.securityRejects = closed/aggSeconds, earlyCloses/aggSeconds, securityRejects/aggSeconds
	a.refused = refused / aggSeconds
	a.challenged = challenged / aggSeconds
	a.newSrcs = newSrcs
	if reqs > 0 {
		a.srcs = d.scratchS.estimate()
		a.nets = d.scratchN.estimate()
		a.newShare = newSrcs / reqs
	}
	a.engagement = -1
	if newSrcs >= 20 {
		a.engagement = engaged / newSrcs
	}
	a.errRatio, a.lat = -1, -1
	if done > 0 {
		a.errRatio = errs / done
	}
	if latN > 0 {
		a.lat = lat / latN
	}
	list := func(m map[uint64]*acc) []share {
		out := make([]share, 0, len(m))
		for k, x := range m {
			if reqs > 0 {
				out = append(out, share{key: k, label: x.label, share: x.count / reqs, sources: x.srcs.estimate()})
			}
		}
		slices.SortFunc(out, func(p, q share) int {
			switch {
			case p.share > q.share:
				return -1
			case p.share < q.share:
				return 1
			}
			return 0
		})
		return out[:min(len(out), 8)]
	}
	a.fps, a.paths = list(fps), list(paths)
	return a
}

// evaluate runs once a second, at the end of a window.
func (d *detector) evaluate(ns int64) {
	a := d.aggregate()
	d.last = a
	d.detectIDS(ns, a)
	b := &d.base
	if d.state == Attack {
		b = &d.frozen
	}
	rateBase := math.Max(b.rate, 0)
	warming := d.age < int(d.cfg.Warmup/time.Second)
	trained := d.age >= int(d.cfg.MinHistory/time.Second) || d.state == Attack // too little data tells nothing about what is usual
	thr := d.threshold(rateBase, b.rateVar)
	if warming { // still learning what is usual: only a far larger rise counts
		thr = math.Max(thr, 2.5*d.cfg.RateFactor*rateBase)
	}
	gate := a.rate >= thr

	var reasons []string
	strongFP, pathConc := false, false
	for _, s := range a.fps {
		if s.share >= 0.3 && s.share-b.fps[s.key] >= 0.25 && s.sources >= float64(d.cfg.MinClusterSources) {
			strongFP = true
			reasons = append(reasons, "one client fingerprint is "+pct(s.share)+" of requests from about "+itoa(s.sources)+" addresses (usually "+pct(b.fps[s.key])+"): "+s.label)
			break
		}
	}
	for _, s := range a.paths {
		if s.share >= 0.3 && s.share-b.paths[s.key] >= 0.25 {
			pathConc = true
			reasons = append(reasons, "one target is "+pct(s.share)+" of requests (usually "+pct(b.paths[s.key])+"): "+s.label)
			break
		}
	}
	newSrc := a.newShare >= 0.5 && a.newShare >= b.newShare+0.3
	burst := a.srcs >= 4*math.Max(b.srcs, 10)
	spread := newSrc || burst
	if newSrc {
		reasons = append(reasons, pct(a.newShare)+" of requests are from addresses not seen before (usually "+pct(b.newShare)+")")
	}
	if burst {
		reasons = append(reasons, "about "+itoa(a.srcs)+" different addresses in ten seconds (usually "+itoa(b.srcs)+")")
	}
	lowEngage := a.engagement < 0.25 // includes "too few new sources to tell"
	if a.engagement >= 0 && lowEngage && spread {
		reasons = append(reasons, "new addresses ask for one thing and nothing else ("+pct(a.engagement)+" go on to a second page or asset)")
	}
	pain := (a.errRatio >= 0.2 && a.errRatio >= b.errRatio+0.1) || (a.lat >= 200 && b.lat > 0 && a.lat >= 4*b.lat)
	if pain {
		reasons = append(reasons, "the application is failing or slow ("+pct(math.Max(a.errRatio, 0))+" errors, "+itoa(math.Max(a.lat, 0))+" ms)")
	}
	connFlood := a.connRate >= math.Max(d.cfg.RateFactor*b.connRate, d.cfg.MinAttackRate) && a.connRate >= 3*math.Max(a.rate, 1)
	if connFlood {
		reasons = append(reasons, "connections are opened without requests ("+itoa(a.connRate)+" a second)")
	}
	evidence := gate && (strongFP || pathConc && spread && lowEngage || pain && spread) || connFlood
	evidence = evidence && trained
	if gate {
		reasons = append([]string{"about " + itoa(a.rate) + " requests a second, the usual is " + itoa(rateBase)}, reasons...)
	}

	switch d.state {
	case Normal, Elevated:
		if evidence {
			d.run++
		} else {
			d.run = 0
		}
		if d.run >= d.cfg.Confirm {
			d.startAttack(ns, a, reasons, strongFP, pathConc && spread && lowEngage)
		} else if gate {
			if d.state != Elevated {
				d.state = Elevated
				d.emit(Event{Kind: "elevated", At: time.Unix(0, ns), State: Elevated, Rate: a.rate, BaselineRate: rateBase, Reasons: reasons})
			}
		} else {
			d.state = Normal
		}
		if d.state != Attack {
			d.learn(a)
		}
	case Attack:
		exitRate := math.Max(d.cfg.ExitFactor*d.frozen.rate, d.cfg.MinAttackRate/2)
		if a.rate < exitRate && !connFlood {
			d.quiet++
		} else {
			d.quiet = 0
		}
		if evidence {
			d.noEvidence = 0
		} else {
			d.noEvidence++
		}
		inc := d.incident
		if a.rate > inc.peak {
			inc.peak = a.rate
		}
		inc.addReasons(reasons)
		d.widen(a, strongFP, pathConc && spread && lowEngage)
		if time.Duration(ns-d.since) >= d.cfg.MinAttack && (time.Duration(d.quiet)*time.Second >= d.cfg.ExitQuiet ||
			time.Duration(d.noEvidence)*time.Second >= d.cfg.EvidenceTimeout) {
			d.endAttack(ns)
		} else if (ns/1e9-d.since/1e9)%10 == 0 {
			ev := d.incidentEvent("attack_update", ns)
			d.emit(ev)
		}
	}
	d.reasons = reasons
	d.learning.Store(d.state == Normal && d.run == 0)
}

// detectIDS reports strong admission and rejection signals without changing mitigation.
// A response error alone cannot classify an attack; these bounded alerts let operators
// investigate rejected probes, connection churn or capacity/configuration problems.
func (d *detector) detectIDS(ns int64, a aggregate) {
	var reasons []string
	floor := d.cfg.MinAttackRate
	if a.connRefused >= floor && a.connRefused >= 0.5*a.connRate {
		reasons = append(reasons, "IP/network connection admission pressure: "+itoa(a.connRefused)+" refusals a second")
	}
	if a.earlyCloses >= floor && a.earlyCloses >= 0.75*a.closed {
		reasons = append(reasons, "connections close before HTTP activity: "+itoa(a.earlyCloses)+" a second")
	}
	if a.securityRejects >= floor && a.securityRejects >= 0.5*a.rate {
		reasons = append(reasons, "requests rejected before the origin: "+itoa(a.securityRejects)+" a second")
	}
	d.idsReasons = reasons
	if len(reasons) == 0 || d.idsReported && ns-d.idsLast < int64(30*time.Second) {
		return
	}
	d.idsLast, d.idsReported = ns, true
	d.emit(Event{Kind: "ids_signal", At: time.Unix(0, ns), State: d.state, Rate: a.rate, BaselineRate: d.base.rate, Reasons: append([]string(nil), reasons...)})
}

// learn moves the baseline towards the last ten seconds. The rate may at most double per step's worth of weight, so a
// sudden rise is not learnt at once.
func (d *detector) learn(a aggregate) {
	d.age++
	alpha := 1 / float64(d.age)
	if warm := float64(d.cfg.Warmup / time.Second); float64(d.age) > warm {
		alpha = 1 / float64(d.cfg.Tau/time.Second)
	}
	b := &d.base
	ew := func(x *float64, v float64) { *x += alpha * (v - *x) }
	rate := a.rate
	warming := float64(d.age) <= float64(d.cfg.Warmup/time.Second)
	if !warming { // while warming up the baseline is the plain average of what was seen, whatever it is
		rate = math.Min(rate, math.Max(2*b.rate, d.cfg.MinAttackRate/2))
	}
	// The spread of the site's rate is measured between ten-second rates that do not overlap, so that a steady rise or
	// fall (a day's ramp, or the baseline still catching up) is not mistaken for noise.
	if d.age%10 == 0 {
		if b.sampled {
			diff := rate - b.lastSample
			b.rateVar += math.Min(1, 10*alpha) * (diff*diff/2 - b.rateVar)
		}
		b.lastSample, b.sampled = rate, true
	}
	ew(&b.rate, rate)
	ps, pn := a.peakSrc, a.peakNet
	if !warming { // a sudden rise in the busiest address is not learnt at once either
		ps = math.Min(ps, math.Max(2*b.peakSrc, d.refSrc/2))
		pn = math.Min(pn, math.Max(2*b.peakNet, d.refNet/2))
	}
	ew(&b.peakSrc, ps)
	ew(&b.peakNet, pn)
	d.scaleSrc.Store(math.Float64bits(d.scale(b.peakSrc, d.refSrc)))
	d.scaleNet.Store(math.Float64bits(d.scale(b.peakNet, d.refNet)))
	ew(&b.srcs, a.srcs)
	ew(&b.newShare, a.newShare)
	ew(&b.connRate, a.connRate)
	if a.errRatio >= 0 {
		ew(&b.errRatio, a.errRatio)
	}
	if a.lat >= 0 {
		if b.lat == 0 {
			b.lat = a.lat
		}
		ew(&b.lat, a.lat)
	}
	learnShares(b.fps, a.fps, alpha)
	learnShares(b.paths, a.paths, alpha)
}

func learnShares(m map[uint64]float64, now []share, alpha float64) {
	for k := range m {
		m[k] *= 1 - alpha
	}
	for _, s := range now {
		m[s.key] += alpha * s.share
	}
	for k, v := range m {
		if v < 0.002 {
			delete(m, k)
		}
	}
	for len(m) > baseKeys {
		var lk uint64
		lv := math.Inf(1)
		for k, v := range m {
			if v < lv {
				lk, lv = k, v
			}
		}
		delete(m, lk)
	}
}

func (d *detector) startAttack(ns int64, a aggregate, reasons []string, fpAttack, pathAttack bool) {
	d.state, d.since, d.quiet, d.noEvidence, d.run = Attack, ns, 0, 0, 0
	d.epoch++
	d.frozen = baseline{rate: d.base.rate, rateVar: d.base.rateVar, peakSrc: d.base.peakSrc, peakNet: d.base.peakNet, srcs: d.base.srcs, newShare: d.base.newShare, errRatio: d.base.errRatio, lat: d.base.lat,
		connRate: d.base.connRate, fps: cloneMap(d.base.fps), paths: cloneMap(d.base.paths)}
	d.incident = &incidentAcc{start: ns, peak: a.rate, baseRate: d.base.rate, srcs: newHLL(14), nets: newHLL(12),
		labels: newTopK(32), labelSet: newHLL(10)}
	d.incident.addReasons(reasons)
	unknown, known := d.cfg.MinAttackRate, d.cfg.MinAttackRate
	if d.unknownRate != nil {
		unknown = d.unknownRate(d.base.rate)
	}
	if d.knownRate != nil {
		known = d.knownRate(d.base.rate)
	}
	cluster := math.Max(d.clusterRate, d.clusterShare*d.base.rate) // look-alike requests may be a small share of a big site
	d.info.Store(&attackInfo{epoch: d.epoch, since: ns, fps: map[uint64]bool{}, paths: map[uint64]bool{}, unknownRate: unknown,
		clusterRate: cluster, knownRate: known})
	d.widen(a, fpAttack, pathAttack)
	d.emit(d.incidentEvent("attack_start", ns))
}

// widen adds the fingerprints and targets that stand out to the attack's clusters. A cluster stays for the whole attack:
// once the mitigation works, the attack is still in the counts (requests are counted before they are refused), so it
// keeps standing out, but an attacker who rotates fingerprints must not be able to free an old one.
func (d *detector) widen(a aggregate, fpAttack, pathAttack bool) {
	old := d.info.Load()
	if old == nil {
		return
	}
	fps, paths := cloneSet(old.fps), cloneSet(old.paths)
	changed := false
	for _, s := range a.fps {
		if len(fps) >= topKeys {
			break
		}
		if s.share >= 0.1 && s.share-d.frozen.fps[s.key] >= 0.1 && s.sources >= 3 && !fps[s.key] {
			fps[s.key], changed = true, true
			d.incident.addCluster("fingerprint", s)
		}
	}
	if pathAttack || old.pathAttack {
		for _, s := range a.paths {
			if len(paths) >= topKeys {
				break
			}
			if s.share >= 0.1 && s.share-d.frozen.paths[s.key] >= 0.1 && !paths[s.key] {
				paths[s.key], changed = true, true
				d.incident.addCluster("target", s)
			}
		}
	}
	_ = fpAttack
	if changed || pathAttack != old.pathAttack {
		n := *old
		n.fps, n.paths, n.pathAttack, n.fingerprints = fps, paths, old.pathAttack || pathAttack, len(fps)
		d.info.Store(&n)
	}
}

func (d *detector) endAttack(ns int64) {
	ev := d.incidentEvent("attack_end", ns)
	d.history = append(d.history, ev.Incident)
	if len(d.history) > 20 {
		d.history = d.history[len(d.history)-20:]
	}
	d.state, d.incident, d.quiet = Normal, nil, 0
	d.info.Store(nil)
	d.emit(ev)
}

func (d *detector) emit(ev Event) {
	if d.onEvent != nil {
		d.onEvent(ev)
	}
}

func cloneMap(m map[uint64]float64) map[uint64]float64 {
	out := make(map[uint64]float64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneSet(m map[uint64]bool) map[uint64]bool {
	out := make(map[uint64]bool, len(m)+2)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// threshold is the request rate, in a second of ten, above which traffic is more than the site's own normal: the largest
// of RateFactor times the moving average, the average plus Sigmas standard deviations of the site's own rates, and the
// absolute floor. A steady site is held to the first; a bursty one, whose ordinary rate swings widely, to the second.
func (d *detector) threshold(mean, variance float64) float64 {
	return math.Max(math.Max(d.cfg.RateFactor*mean, mean+d.cfg.Sigmas*math.Sqrt(math.Max(variance, 0))), d.cfg.MinAttackRate)
}

// rateThreshold is threshold for the detector's own baseline.
func (d *detector) rateThreshold() float64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.threshold(d.base.rate, d.base.rateVar)
}

// scale is the factor a limit configured as ref is multiplied by, given the moving average of the busiest address's (or
// network's) rate: LimitMargin times that average if it is above the configured limit, at most MaxScale, never below 1.
func (d *detector) scale(peak, ref float64) float64 {
	if ref <= 0 {
		return 1
	}
	return math.Min(math.Max(d.cfg.LimitMargin*peak/ref, 1), d.cfg.MaxScale)
}

// scales returns the current factors for the per-address and the per-network limits.
func (d *detector) scales() (src, net float64) {
	src, net = math.Float64frombits(d.scaleSrc.Load()), math.Float64frombits(d.scaleNet.Load())
	if src < 1 {
		src = 1
	}
	if net < 1 {
		net = 1
	}
	return src, net
}

// notePeaks raises the second's record of the busiest address and network.
func (d *detector) notePeaks(src, net uint32) {
	for {
		cur := d.winMaxSrc.Load()
		if src <= cur || d.winMaxSrc.CompareAndSwap(cur, src) {
			break
		}
	}
	for {
		cur := d.winMaxNet.Load()
		if net <= cur || d.winMaxNet.CompareAndSwap(cur, net) {
			break
		}
	}
}
