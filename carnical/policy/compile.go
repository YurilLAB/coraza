// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"fmt"

	"github.com/YurilLAB/coraza/carnical/crs"
	"github.com/YurilLAB/coraza/carnical/proxy"
)

// Compiled is what an edge runs for one policy. The first group of fields are exactly the fields of proxy.Config and
// crs.Settings that a policy decides, under the same names, so that ApplyTo can copy them across; the rest are the sections
// that belong to components outside this package, passed on as they are.
type Compiled struct {
	// AllowedHosts is proxy.Config.AllowedHosts: the only names the site answers to (empty: any).
	AllowedHosts []string
	// Paths is proxy.Config.Paths.
	Paths proxy.PathPolicy
	// DenyHeaders is proxy.Config.DenyHeaders, including next-action if the framework option asks for it.
	DenyHeaders []string
	// WordPress is proxy.Config.WordPress.
	WordPress proxy.WordPressPolicy
	// Uploads is proxy.Config.Uploads.
	Uploads proxy.UploadPolicy
	// Responses is proxy.Config.Responses.
	Responses proxy.ResponsePolicy
	// MaxFormBody is proxy.Config.MaxFormBody.
	MaxFormBody int64
	// CRS is proxy.Config.CRS: the mode, the paranoia level, the thresholds, the body limit, the allowed methods, whether
	// responses are inspected, and in Before and After the SecLang this package generated (the address lists, exclusions and custom
	// rules before the Core Rule Set, the rule groups' changes after it). UploadDir is left empty: it is the operator's.
	CRS crs.Settings

	// VPatch is for package vpatch: the tiers that run and the software the site declares.
	VPatch VPatchOptions
	// APIMode, API and BodyFormats are for the API guard and the body-format checks (packages inspect, formats and their
	// neighbours); API and BodyFormats are canonical JSON, or empty.
	APIMode     APIMode
	API         json.RawMessage
	BodyFormats json.RawMessage

	// Revision and Hash identify the policy this was compiled from (Policy.Hash); an edge reports them as the policy in force.
	Revision uint64
	Hash     string
	// Notes say, in plain sentences, where the edge does something other than what the policy literally says, so that the web UI
	// can show it. They are empty for most policies.
	Notes []string
}

// Compile validates a policy and compiles it. It returns an *Error for an invalid policy, and for a valid one it returns
// settings that crs.Settings.Validate accepts and SecLang that builds a Coraza WAF on top of the Core Rule Set (the tests
// build one from every kind of policy). Compile does no I/O and keeps no state, so it is safe for concurrent use, and its
// cost is bounded by the policy's limits: at most a few thousand lines of SecLang.
func Compile(p Policy) (Compiled, error) {
	q := p.Normalize()
	if err := q.Validate(); err != nil {
		return Compiled{}, err
	}
	pre := presets[q.Sensitivity]
	_, inbound := q.effective()
	before, _, err := renderBefore(q)
	if err != nil {
		return Compiled{}, fmt.Errorf("policy: %w", err)
	}
	after, notes, err := renderAfter(q)
	if err != nil {
		return Compiled{}, fmt.Errorf("policy: %w", err)
	}
	mode := map[Mode]crs.Mode{ModeBlock: crs.ModeBlock, ModeMonitor: crs.ModeDetect, ModeOff: crs.ModeOff}[q.Mode]
	deny := append([]string(nil), q.DenyHeaders...)
	if q.Framework.DenyNextAction {
		deny = sortedUnique(append(deny, "next-action"))
	}
	c := Compiled{
		AllowedHosts: append([]string(nil), q.AllowedHosts...),
		Paths:        proxy.PathPolicy{AllowEncodedSlash: q.Paths.AllowEncodedSlash, AllowPathParams: q.Paths.AllowPathParams},
		DenyHeaders:  deny,
		WordPress:    proxy.WordPressPolicy{Enabled: q.WordPress.Enabled, AllowXMLRPC: q.WordPress.AllowXMLRPC, LoginPerMinute: q.WordPress.LoginPerMinute},
		Uploads:      proxy.UploadPolicy{AllowExecutableNames: q.Uploads.AllowScriptNames, AllowScriptContent: q.Uploads.AllowScriptContent},
		Responses:    proxy.ResponsePolicy{KeepBanners: q.Responses.KeepBanners, KeepCaching: q.Responses.KeepCaching},
		MaxFormBody:  q.Body.MaxFormBytes,
		CRS: crs.Settings{
			Mode:                   mode,
			ParanoiaLevel:          pre.ParanoiaLevel,
			DetectionParanoiaLevel: 0, // the same as the blocking level
			InboundThreshold:       inbound,
			OutboundThreshold:      pre.OutboundThreshold,
			RequestBodyLimit:       q.Body.MaxUploadBytes,
			InspectResponses:       q.Responses.Inspect,
			AllowedMethods:         append([]string(nil), q.AllowedMethods...),
			Before:                 before,
			After:                  after,
		},
		VPatch:      VPatchOptions{Tiers: append([]string{}, q.VPatch.Tiers...), Software: append([]string{}, q.VPatch.Software...)},
		APIMode:     q.APIMode,
		API:         append(json.RawMessage(nil), q.API...),
		BodyFormats: append(json.RawMessage(nil), q.BodyFormats...),
		Revision:    q.Revision,
		Hash:        q.Hash(),
		Notes:       notes,
	}
	if err := c.CRS.Validate(); err != nil {
		return Compiled{}, fmt.Errorf("policy: the Core Rule Set settings are not usable: %w", err)
	}
	return c, nil
}

// ApplyTo sets the fields of a proxy.Config that the policy decides. It leaves the rest alone (the upstream, the origin guard,
// the trusted proxies, the limits that belong to the machine), and it keeps the Core Rule Set's UploadDir and the choice of local
// rules that the operator set, which a policy has no field for.
func (c Compiled) ApplyTo(cfg *proxy.Config) {
	uploadDir, localOff, localRulesOff := cfg.CRS.UploadDir, cfg.CRS.DisableLocalRules, append([]int(nil), cfg.CRS.LocalRulesOff...)
	cfg.AllowedHosts = append([]string(nil), c.AllowedHosts...)
	cfg.Paths = c.Paths
	cfg.DenyHeaders = append([]string(nil), c.DenyHeaders...)
	cfg.WordPress = c.WordPress
	cfg.Uploads = c.Uploads
	cfg.Responses = c.Responses
	cfg.MaxFormBody = c.MaxFormBody
	cfg.CRS = c.CRS
	cfg.CRS.AllowedMethods = append([]string(nil), c.CRS.AllowedMethods...)
	cfg.CRS.UploadDir = uploadDir
	cfg.CRS.DisableLocalRules, cfg.CRS.LocalRulesOff = localOff, localRulesOff
}
