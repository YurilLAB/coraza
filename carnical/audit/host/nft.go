package host

import (
	"bufio"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// The network policy is checked by what its chains do, not by whether its words appear: a chain whose policy was changed
// to accept, a drop turned into an accept, a rule put in front of the blocks or a table set dormant all leave every word
// of the ruleset in place. Where the policy lets traffic through, only the forms the shipped ruleset uses are accepted:
// nftables can say "accept everything" in more ways than a list of bad forms could name.

// nftChain is one chain of a listed table.
type nftChain struct {
	typ, hook, policy string
	priority          int
	rules             []string
}

// nftTable is one table as `nft list ruleset` prints it.
type nftTable struct {
	dormant bool
	chains  map[string]*nftChain
	sets    map[string]string // each set's elements statement
}

var nftHookRe = regexp.MustCompile(`^type (\w+) hook (\w+)\b.*?\bpriority ([^;]+);(?:\s*policy (\w+);)?\s*$`)

// nftPriorities are the names nft prints for the standard priorities of the ip, ip6 and inet families.
var nftPriorities = map[string]int{"raw": -300, "mangle": -150, "dstnat": -100, "filter": 0, "security": 50, "srcnat": 100}

// parsePriority reads a chain priority as nft prints it: a number, a name, or a name plus or minus a number.
func parsePriority(s string) (int, bool) {
	w := strings.Fields(s)
	if len(w) != 1 && len(w) != 3 {
		return 0, false
	}
	base, ok := nftPriorities[w[0]]
	if !ok {
		n, err := strconv.Atoi(w[0])
		if err != nil {
			return 0, false
		}
		base = n
	}
	if len(w) == 3 {
		n, err := strconv.Atoi(w[2])
		switch {
		case err != nil:
			return 0, false
		case w[1] == "+":
			base += n
		case w[1] == "-":
			base -= n
		default:
			return 0, false
		}
	}
	return base, true
}

// braces counts the braces of a line that are not inside a quoted string.
func braces(line string) (open, closed int) {
	quoted := false
	for _, r := range line {
		switch {
		case r == '"':
			quoted = !quoted
		case quoted:
		case r == '{':
			open++
		case r == '}':
			closed++
		}
	}
	return open, closed
}

// parseNFTTable finds one table in a listing and reads its chains and sets. It reports false if the table is not there.
func parseNFTTable(text, family, name string) (*nftTable, bool) {
	header := "table " + family + " " + name + " {"
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var t *nftTable
	depth := 0
	var chain *nftChain
	var set, elements *strings.Builder
	var setName string
	var pending string // a rule whose braces are not closed yet
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue // a comment, in a ruleset file
		}
		open, closed := braces(line)
		if t == nil {
			if depth == 0 && line == header {
				t = &nftTable{chains: map[string]*nftChain{}, sets: map[string]string{}}
			}
			depth += open - closed
			if t != nil {
				depth = 1
			}
			continue
		}
		before := depth
		depth += open - closed
		switch {
		case depth <= 0:
			return t, true // the end of the table
		case before == 1 && open > closed:
			kind, rest, _ := strings.Cut(line, " ")
			objName, _, _ := strings.Cut(rest, " ")
			switch kind {
			case "chain":
				chain = &nftChain{}
				t.chains[objName] = chain
			case "set", "map":
				set, setName = &strings.Builder{}, objName
			}
		case before == 1:
			if line == "flags dormant" || strings.HasPrefix(line, "flags ") && strings.Contains(line, "dormant") {
				t.dormant = true
			}
		case depth == 1: // a chain or set has ended
			if set != nil {
				t.sets[setName] = set.String()
			}
			chain, set, elements, pending = nil, nil, nil, ""
		case set != nil:
			// Only the elements statement is kept: a comment or anything else in the set cannot pass for elements.
			if before == 2 && strings.HasPrefix(line, "elements = {") {
				elements = set
			}
			if elements != nil {
				elements.WriteString(line + " ")
				if depth == 2 {
					elements = nil
				}
			}
		case chain != nil:
			if pending != "" || depth > 2 {
				pending += line + " "
				if depth > 2 {
					continue
				}
				line, pending = strings.TrimSpace(pending), ""
			}
			if line == "" || strings.HasPrefix(line, "comment ") {
				continue
			}
			if m := nftHookRe.FindStringSubmatch(line); m != nil {
				chain.typ, chain.hook, chain.policy = m[1], m[2], m[4]
				chain.priority, _ = parsePriority(m[3])
				continue
			}
			chain.rules = append(chain.rules, line)
		}
	}
	return t, t != nil
}

// nftRewriter is a NAT chain on the output hook: it can change where a locally made connection goes.
type nftRewriter struct {
	table, chain string
	priority     int
	known        bool // whether the priority could be read
}

// outputRewriters lists the NAT chains on the output hook in every table of a listing.
func outputRewriters(text string) []nftRewriter {
	var out []nftRewriter
	var table, chain string
	depth := 0
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		open, closed := braces(line)
		switch w := strings.Fields(line); {
		case depth == 0 && len(w) == 4 && w[0] == "table" && w[3] == "{":
			table = w[1] + " " + w[2]
		case depth == 1 && len(w) == 3 && w[0] == "chain" && w[2] == "{":
			chain = w[1]
		case depth == 2:
			if m := nftHookRe.FindStringSubmatch(line); m != nil && m[1] == "nat" && m[2] == "output" {
				p, ok := parsePriority(m[3])
				out = append(out, nftRewriter{table, chain, p, ok})
			}
		}
		depth += open - closed
	}
	return out
}

// fields splits a rule into words, keeping a quoted string as one word.
func fields(rule string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, r := range rule {
		switch {
		case r == '"':
			quoted = !quoted
			cur.WriteRune(r)
		case !quoted && (r == ' ' || r == '\t'):
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// nftNameKeys are the keys of `nft -j` whose strings nft lists as they are, without quotes: names, and what refers to them.
var nftNameKeys = map[string]bool{"name": true, "target": true, "table": true, "chain": true, "dev": true, "devices": true}

// nftMisread lists the names and strings in `nft -j list ruleset` that the text listing cannot show unambiguously. nft
// escapes nothing when it lists a ruleset (nftables 1.1.3): a comment written through JSON as `q"} accept` is listed as
// comment "q"} accept", and a chain named `x drop` as `jump x drop`, which reads as a drop. The text listing is what the
// check reads, so it is trusted only when no name holds a space, quote, brace, comma, semicolon, # or control character,
// and no string a quote or control character. Every table is looked at, not only carnical's: a line break in another
// table's string could hold lines that close it and open a table inet carnical of its own, ahead of the real one.
func nftMisread(data []byte) ([]string, error) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	report := func(what, s string) {
		if r := []rune(s); len(r) > 64 {
			s = string(r[:64]) + "..."
		}
		if msg := fmt.Sprintf("the ruleset has a %s, which nft lists as it is, so the listing can be misread: %q", what, s); !seen[msg] && len(out) < 10 {
			seen[msg] = true
			out = append(out, msg)
		}
	}
	var visit func(key string, v any)
	visit = func(key string, v any) {
		switch v := v.(type) {
		case map[string]any:
			for _, k := range slices.Sorted(maps.Keys(v)) {
				visit(k, v[k])
			}
		case []any:
			if !nftNameKeys[key] {
				key = ""
			}
			for _, item := range v {
				visit(key, item)
			}
		case string:
			switch {
			case nftNameKeys[key] && strings.ContainsFunc(v, func(r rune) bool {
				return unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune(`"{},;#`, r)
			}):
				report("name with a space, quote, brace, comma, semicolon, # or control character", v)
			case strings.ContainsFunc(v, func(r rune) bool { return r == '"' || unicode.IsControl(r) }):
				report("string with a quote or control character", v)
			}
		}
	}
	visit("", v)
	return out, nil
}

var nftVerdicts = map[string]bool{"accept": true, "drop": true, "reject": true, "return": true, "jump": true, "goto": true, "continue": true, "queue": true}

// verdict is what a rule does with a packet it matches, and the chain it sends it to for jump and goto. A rule with no
// verdict (a log line with a rate limit) lets the packet go on to the next rule. A rule that looks its verdict up in a map
// is of kind "vmap", and one that jumps to a chain written inline is of kind "anon": what either does depends on the packet,
// so neither is taken for a drop.
func verdict(rule string) (kind, target string, before string) {
	w := fields(rule)
	for i, word := range w {
		if word == "vmap" {
			return "vmap", "", rule
		}
		if (word == "jump" || word == "goto") && i+1 < len(w) && w[i+1] == "{" {
			return "anon", "", rule
		}
	}
	at := -1
	for i := 0; i < len(w); i++ {
		if nftVerdicts[w[i]] {
			kind, target, at = w[i], "", i
			if (kind == "jump" || kind == "goto") && i+1 < len(w) {
				target = w[i+1]
				i++
			}
		}
	}
	if at < 0 {
		return "", "", rule
	}
	return kind, target, strings.Join(w[:at], " ")
}

// conditions is what stands before a rule's verdict without its counters and log statements, which match every packet.
func conditions(before string) string {
	w := fields(before)
	var out []string
	for i := 0; i < len(w); i++ {
		switch w[i] {
		case "counter":
			switch {
			case i+2 < len(w) && w[i+1] == "name":
				i += 2
			case i+4 < len(w) && w[i+1] == "packets" && w[i+3] == "bytes":
				i += 4
			}
		case "log":
			for i+2 < len(w) && slices.Contains([]string{"prefix", "level", "group", "snaplen", "queue-threshold", "flags"}, w[i+1]) {
				i += 2
			}
		default:
			out = append(out, w[i])
		}
	}
	return strings.Join(out, " ")
}

// oneOrSet matches one item or an anonymous set of them, as nft prints them.
func oneOrSet(item string) string {
	return `(?:(?:` + item + `)|\{ (?:` + item + `)(?:, (?:` + item + `))* \})`
}

func form(s string) *regexp.Regexp { return regexp.MustCompile(`^` + s + `$`) }

// replies are connections already accepted and what belongs to them, written as nft prints either spelling.
const replies = `ct state (?:(?:established|related)(?:,(?:established|related))?|\{ (?:established|related)(?:, (?:established|related))? \})`

var (
	// inputAccepts are what the input chain may accept: loopback, replies, the ICMP that keeps paths working, limited echo,
	// and named ports (from named sources, for administration). Each is matched against the conditions of the rule and of
	// every jump that led to it.
	inputAccepts = []*regexp.Regexp{
		form(`iif(?:name)? "lo"`),
		form(replies),
		form(`icmp type ` + oneOrSet(`destination-unreachable|time-exceeded|parameter-problem`)),
		form(`icmpv6 type ` + oneOrSet(`destination-unreachable|packet-too-big|time-exceeded|parameter-problem`)),
		form(`icmpv6 type ` + oneOrSet(`nd-neighbor-solicit|nd-neighbor-advert`) + ` ip6 hoplimit 255`),
		form(`icmpv6 type nd-router-advert ip6 saddr fe80::/10 ip6 hoplimit 255`),
		form(`icmp(?:v6)? type echo-request limit rate \d+/second burst \d+ packets`),
		form(`(?:ip6? saddr (?:\{[^{}]+\}|\S+) )?(?:tcp|udp) dport ` + oneOrSet(`\d+`) + `(?: ct state new)?(?: limit rate \d+/\w+(?: burst \d+ packets)?)?`),
	}
	established   = form(replies)
	privateBlock4 = form(`ip daddr @not_public4`)
	privateBlock6 = form(`ip6 daddr @not_public6`)
	localBlock    = form(`fib daddr type local`)
	// resolver is a name lookup to named hosts, which comes before the blocks: single addresses, not ranges or sets.
	resolver = form(`ip6? daddr ` + oneOrSet(`[0-9A-Fa-f:.]+`) + ` (?:udp|tcp) dport 53`)
	// edgeAccepts is what the edge may connect to after its blocks, where only public destinations are left: named ports, to
	// any of them or to named addresses.
	edgeAccepts = form(`(?:ip6? daddr (?:@\w+|\{[^{}]+\}|[0-9A-Fa-f:./]+) )?(?:tcp|udp) dport ` + oneOrSet(`\d+`) + `(?: ct state new)?`)
	// localResolver is the same on this machine only: the internal services may reach nothing else.
	localResolver = form(`ip6? daddr ` + oneOrSet(`127(?:\.\d{1,3}){3}|::1`) + ` (?:udp|tcp) dport 53`)
	loopback      = form(`oif(?:name)? "lo"`)
	metadata4     = form(`ip daddr 169\.254\.169\.254(?: meta skuid != 0)?`)
	metadata6     = form(`ip6 daddr fd00:ec2::254(?: meta skuid != 0)?`)
)

// nftMaxJumps is how deep nft lets jumps go; it refuses to load a ruleset that goes deeper.
const nftMaxJumps = 16

// walk follows every way a packet can go from a chain, with the conditions of the jumps that led there, and reports each
// accept whose conditions are not among those allowed, and each verdict it cannot follow.
func (t *nftTable) walk(name string, allowed []*regexp.Regexp) []string {
	var out []string
	seen := map[string]bool{}
	report := func(format string, a ...any) {
		if msg := fmt.Sprintf(format, a...); !seen[msg] {
			seen[msg] = true
			out = append(out, msg)
		}
	}
	budget := 10000 // paths through a ruleset can multiply; a real one has a few dozen
	var visit func(chain string, path []string, depth int)
	visit = func(chain string, path []string, depth int) {
		c := t.chains[chain]
		if c == nil {
			return
		}
		if budget--; depth > nftMaxJumps || budget < 0 {
			report("the %s chain sends packets through more chains than this check follows", name)
			return
		}
		for _, r := range c.rules {
			kind, target, before := verdict(r)
			cond := conditions(before)
			here := path
			if cond != "" {
				here = slices.Concat(path, []string{cond}) // a copy: other ways out of this chain share path
			}
			all := strings.Join(here, " ")
			switch kind {
			case "", "continue", "drop", "reject", "return":
			case "accept":
				switch {
				case all == "":
					report("the %s chain accepts every packet: %q", name, r)
				case !slices.ContainsFunc(allowed, func(re *regexp.Regexp) bool { return re.MatchString(all) }):
					report("the %s chain accepts %q, which this check does not recognise", name, all)
				}
			case "jump", "goto":
				visit(target, here, depth+1)
			case "vmap":
				report("the %s chain decides through a verdict map, which this check cannot follow: %q", name, r)
			case "anon":
				report("the %s chain decides through an inline chain, which this check cannot follow: %q", name, r)
			default:
				report("the %s chain hands packets to a program: %q", name, r)
			}
			// After a rule that ends every packet's way through this chain, the rest of it is never reached.
			if cond == "" && (slices.Contains([]string{"drop", "reject", "accept", "return", "goto", "queue"}, kind) ||
				kind == "jump" && t.alwaysDrops(target, depth+1)) {
				return
			}
		}
	}
	visit(name, nil, 0)
	return out
}

// alwaysDrops reports whether every packet that enters a chain is dropped by it.
func (t *nftTable) alwaysDrops(name string, depth int) bool {
	c := t.chains[name]
	if c == nil || depth > nftMaxJumps {
		return false
	}
	for _, r := range c.rules {
		kind, target, before := verdict(r)
		drops := kind == "drop" || kind == "reject" || (kind == "jump" || kind == "goto") && t.alwaysDrops(target, depth+1)
		switch {
		case kind == "" || kind == "continue":
		case drops && conditions(before) == "":
			return true
		case drops:
		default:
			return false // some packets leave the chain another way
		}
	}
	return false
}

// drops reports whether a rule drops the packets it matches.
func (t *nftTable) drops(rule string) bool {
	kind, target, _ := verdict(rule)
	return kind == "drop" || kind == "reject" || (kind == "jump" || kind == "goto") && t.alwaysDrops(target, 1)
}

// endsInDrop reports whether a chain's last rule drops every packet that reaches it.
func (t *nftTable) endsInDrop(rule string) bool {
	_, _, before := verdict(rule)
	return t.drops(rule) && conditions(before) == ""
}

// PrivateRanges4 and PrivateRanges6 are the destinations the edge must never reach, as deploy/nftables/carnical.nft lists them
// in not_public4 and not_public6 (nft prints a single address without its /32 or /128). A test keeps the two the same.
var (
	PrivateRanges4 = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "168.63.129.16", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4"}
	PrivateRanges6 = []string{"::", "::1", "64:ff9b::/96", "100::/64", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8"}
)

// InternalUsers are the services that may reach only this machine, as deploy/nftables/carnical.nft sends them to internal_out.
var InternalUsers = []string{"carnical-portal", "carnical-ctl", "carnical-signer", "carnical-audit"}

// addrSpan is the first and last address of an element of a set: an address, a prefix or a range.
type addrSpan struct{ lo, hi netip.Addr }

func parseSpan(s string) (addrSpan, bool) {
	if lo, hi, ok := strings.Cut(s, "-"); ok {
		a, errA := netip.ParseAddr(lo)
		b, errB := netip.ParseAddr(hi)
		return addrSpan{a, b}, errA == nil && errB == nil && a.BitLen() == b.BitLen()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return addrSpan{a, a}, true
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return addrSpan{}, false
	}
	p = p.Masked()
	last := p.Addr().AsSlice()
	for i := p.Bits(); i < len(last)*8; i++ {
		last[i/8] |= 1 << (7 - i%8)
	}
	hi, _ := netip.AddrFromSlice(last)
	return addrSpan{p.Addr(), hi}, true
}

// setMissing says which of the wanted ranges no element of a set covers. nft may merge elements (auto-merge prints :: and ::1
// as ::/127), so ranges are compared by the addresses they hold.
func setMissing(elements string, want []string) []string {
	_, list, _ := strings.Cut(elements, "elements = {")
	list, _, _ = strings.Cut(list, "}")
	var have []addrSpan
	for _, e := range strings.Split(list, ",") {
		if s, ok := parseSpan(strings.TrimSpace(e)); ok {
			have = append(have, s)
		}
	}
	var missing []string
	for _, w := range want {
		ws, _ := parseSpan(w)
		if !slices.ContainsFunc(have, func(h addrSpan) bool { return h.lo.Compare(ws.lo) <= 0 && ws.hi.Compare(h.hi) <= 0 }) {
			missing = append(missing, w)
		}
	}
	return missing
}

// nftUsers is how the service users can appear in a rule: each one's name in quotes, and its uid when nft has no name for it.
type nftUsers struct {
	edge     []string
	internal [][]string // one entry for each of InternalUsers
}

// internalSet reports whether a rule's conditions name every one of the internal services' users. Another user named with them
// is held to the same chain, which can only take from what it may reach, so it does not matter here.
func (u nftUsers) internalSet(cond string) bool {
	rest, ok := strings.CutPrefix(cond, "meta skuid ")
	if !ok {
		return false
	}
	elems := []string{rest}
	if inner, ok := strings.CutPrefix(rest, "{ "); ok {
		inner, ok = strings.CutSuffix(inner, " }")
		if !ok {
			return false
		}
		elems = strings.Split(inner, ", ")
	}
	found := make([]bool, len(u.internal))
	for _, e := range elems {
		if i := slices.IndexFunc(u.internal, func(forms []string) bool { return slices.Contains(forms, e) }); i >= 0 {
			found[i] = true
		}
	}
	return !slices.Contains(found, false)
}

// nftProblems says what in the listed carnical table does not hold, and how many things were looked at.
func nftProblems(text string, users nftUsers) (out []string, checked int) {
	t, ok := parseNFTTable(text, "inet", "carnical")
	if !ok {
		return []string{"the loaded rules have no carnical table"}, 1
	}
	checked = 12 // the table; the input, forward and output chains; the edge's chain and its three blocks; the internal chain; two sets; other tables
	add := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }
	if t.dormant {
		add("the carnical table is dormant, so none of its rules are in force")
	}
	for _, hook := range []string{"input", "forward"} {
		c := t.chains[hook]
		switch {
		case c == nil:
			add("the loaded rules have no %s chain", hook)
			continue
		case c.hook != hook:
			add("the %s chain is not attached to the %s hook", hook, hook)
		case c.typ != "filter":
			add("the %s chain is not a filter chain (type %s)", hook, c.typ)
		case c.policy != "drop":
			add("the %s chain does not refuse by default (policy %q)", hook, c.policy)
		}
		var allowed []*regexp.Regexp // nothing is forwarded
		if hook == "input" {
			allowed = inputAccepts
		}
		out = append(out, t.walk(hook, allowed)...)
	}

	// The output chain sends the edge and the internal services to their chains, and stops the metadata service first.
	out = append(out, t.outputProblems(users)...)
	if c := t.chains["output"]; c != nil {
		for _, r := range outputRewriters(text) {
			// At the same priority the order of the two is not defined, so that counts as after.
			if r.table+" "+r.chain != "inet carnical output" && (!r.known || r.priority >= c.priority) {
				add("connections from this machine can be sent elsewhere after the filter has passed them: the NAT chain %s in table %s", r.chain, r.table)
			}
		}
	}

	edge := t.chains["edge_out"]
	if edge == nil {
		add("the loaded rules have no edge output chain (edge_out)")
	} else {
		blocks := []struct {
			what, token string
			form        *regexp.Regexp
		}{
			{"private IPv4 destinations", "@not_public4", privateBlock4},
			{"private IPv6 destinations", "@not_public6", privateBlock6},
			{"this machine's own addresses", "fib daddr type local", localBlock},
		}
		last := -1
		for _, b := range blocks {
			at, near := -1, ""
			for i, r := range edge.rules {
				if _, _, before := verdict(r); b.form.MatchString(conditions(before)) {
					at = i
					break
				}
				if near == "" && strings.Contains(r, b.token) {
					near = r
				}
			}
			switch {
			case at < 0 && near != "":
				add("the edge's block on %s does not cover every packet: %q", b.what, near)
			case at < 0:
				add("the edge's chain has no block on %s", b.what)
			case !t.drops(edge.rules[at]):
				add("the edge's chain lets %s through: %q", b.what, edge.rules[at])
			}
			last = max(last, at)
		}
		for _, r := range edge.rules[:max(last, 0)] {
			kind, _, before := verdict(r)
			if kind == "" || t.drops(r) || kind == "accept" && resolver.MatchString(conditions(before)) {
				continue // name lookups to the resolver come first
			}
			add("a rule ahead of the edge's blocks can let traffic past them: %q", r)
		}
		n := len(edge.rules)
		if n == 0 || !t.endsInDrop(edge.rules[n-1]) {
			add("the edge's chain does not end by refusing what it has not allowed")
		}
		// After the blocks the edge may reach public addresses on named ports, and nothing else before the final drop.
		for i := last + 1; last >= 0 && i < n-1; i++ {
			kind, _, before := verdict(edge.rules[i])
			if kind == "" || t.drops(edge.rules[i]) || kind == "accept" && edgeAccepts.MatchString(conditions(before)) {
				continue
			}
			add("a rule after the edge's blocks lets connections out in a way this check does not recognise: %q", edge.rules[i])
		}
	}
	if internal := t.chains["internal_out"]; internal == nil {
		add("the loaded rules have no internal services' output chain (internal_out)")
	} else if n := len(internal.rules); n == 0 || !t.endsInDrop(internal.rules[n-1]) {
		add("the internal services' chain does not end by refusing what it has not allowed")
	} else {
		for _, r := range internal.rules[:n-1] {
			kind, _, before := verdict(r)
			cond := conditions(before)
			if kind == "" || t.drops(r) || kind == "accept" && (loopback.MatchString(cond) || localResolver.MatchString(cond)) {
				continue
			}
			add("the internal services' chain lets connections out in a way this check does not recognise: %q", r)
		}
	}
	if m := setMissing(t.sets["not_public4"], PrivateRanges4); len(m) > 0 {
		add("the private IPv4 destinations do not include %s", strings.Join(m, ", "))
	}
	if m := setMissing(t.sets["not_public6"], PrivateRanges6); len(m) > 0 {
		add("the private IPv6 destinations do not include %s", strings.Join(m, ", "))
	}
	return out, checked
}

func (t *nftTable) outputProblems(users nftUsers) []string {
	c := t.chains["output"]
	if c == nil {
		return []string{"the loaded rules have no output chain"}
	}
	var out []string
	switch {
	case c.hook != "output":
		out = append(out, "the output chain is not attached to the output hook")
	case c.typ != "filter":
		out = append(out, fmt.Sprintf("the output chain is not a filter chain (type %s)", c.typ))
	}
	edgeAt, internalAt, imds4At, imds6At := -1, -1, -1, -1
	for i, r := range c.rules {
		kind, target, before := verdict(r)
		cond := conditions(before)
		sends := kind == "jump" || kind == "goto"
		switch {
		case edgeAt < 0 && sends && target == "edge_out" && slices.ContainsFunc(users.edge, func(u string) bool { return cond == "meta skuid "+u }):
			edgeAt = i
		case internalAt < 0 && sends && target == "internal_out" && users.internalSet(cond):
			internalAt = i
		case imds4At < 0 && metadata4.MatchString(cond) && t.drops(r):
			imds4At = i
		case imds6At < 0 && metadata6.MatchString(cond) && t.drops(r):
			imds6At = i
		}
	}
	if edgeAt < 0 {
		out = append(out, fmt.Sprintf("the edge's connections are not sent to its chain (meta skuid %s jump edge_out)", users.edge[0]))
	}
	if internalAt < 0 {
		out = append(out, fmt.Sprintf("the internal services' connections are not sent to their chain (meta skuid { %s } jump internal_out)", strings.Join(InternalUsers, ", ")))
	}
	for _, m := range []struct {
		address string
		at      int
	}{{"169.254.169.254", imds4At}, {"fd00:ec2::254", imds6At}} {
		if m.at < 0 || edgeAt >= 0 && m.at > edgeAt {
			out = append(out, fmt.Sprintf("the metadata service (%s) is not blocked before the edge's chain", m.address))
		}
	}
	// Nothing ahead of a chain may let its users' connections go out another way. The output chain's policy is accept, so a
	// return, a verdict map or an inline chain there is as good as an accept.
	ahead := func(from, to int, whose string) {
		for _, r := range c.rules[from:max(to, from)] {
			kind, _, before := verdict(r)
			if kind == "" || t.drops(r) || kind == "accept" && established.MatchString(conditions(before)) {
				continue
			}
			out = append(out, fmt.Sprintf("a rule ahead of the %s chain can let its connections past it: %q", whose, r))
		}
	}
	ahead(0, edgeAt, "edge's")
	if edgeAt >= 0 && edgeAt < internalAt {
		ahead(edgeAt+1, internalAt, "internal services'") // what stands ahead of the edge's jump is reported once, above
	} else {
		ahead(0, internalAt, "internal services'")
	}
	return out
}
