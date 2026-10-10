// Package crs embeds the OWASP Core Rule Set so a Coraza WAF can run it without any files on disk, and turns a
// few typed settings (mode, paranoia level, thresholds) into the directives that configure it. A separate local/ directory
// holds Carnical's supplemental signatures; those are not part of the upstream release or its provenance manifest.
//
// The rules in owasp_crs/ are copied, never edited, by tools/update-crs from an official release after its GPG
// signature has been checked against the CRS project's pinned key. provenance.json records the release, the
// archive hash, the signer and the hash of every embedded file, and a test fails if any file differs from it.
package crs

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

//go:embed owasp_crs base local provenance.json
var files embed.FS

// FS returns the embedded files. Its root holds base/coraza.conf (Coraza's recommended configuration), owasp_crs/
// (the rule and data files, and the setup example) and provenance.json. Pass it to WithRootFS.
func FS() fs.FS { return portableFS{files} }

// portableFS accepts "\\" as well as "/" in a name. Coraza builds Include paths with the operating system's
// separator, which on Windows is a backslash that an embedded file system refuses; Linux never sends one.
type portableFS struct{ fs.FS }

func (p portableFS) Open(name string) (fs.File, error) {
	return p.FS.Open(strings.ReplaceAll(name, "\\", "/"))
}

// Provenance says where the embedded rules came from.
type Provenance struct {
	Version              string            `json:"version"`
	Source               string            `json:"source"`
	ArchiveSHA256        string            `json:"archive_sha256"`
	SignatureSHA256      string            `json:"signature_sha256"`
	SignerFingerprint    string            `json:"signer_fingerprint"`
	SignatureVerifiedUTC string            `json:"signature_verified_utc"`
	Files                map[string]string `json:"files"`
}

// Info returns the provenance of the embedded rules.
func Info() (Provenance, error) {
	raw, err := files.ReadFile("provenance.json")
	if err != nil {
		return Provenance{}, err
	}
	var p Provenance
	if err := json.Unmarshal(raw, &p); err != nil {
		return Provenance{}, fmt.Errorf("provenance.json: %w", err)
	}
	return p, nil
}

// Version is the CRS release that is embedded, such as "4.30.0".
func Version() string {
	p, err := Info()
	if err != nil {
		return "unknown"
	}
	return p.Version
}

// Mode says what the engine does with a request that reaches the blocking threshold.
type Mode string

const (
	// ModeBlock refuses such a request with a 403.
	ModeBlock Mode = "block"
	// ModeDetect only logs it. Use it first on a site, and read the log before blocking.
	ModeDetect Mode = "detect"
	// ModeOff runs no rules.
	ModeOff Mode = "off"
)

// Settings are the choices the CRS documentation asks every installation to make.
type Settings struct {
	Mode Mode
	// ParanoiaLevel 1 to 4: rules at this level and below can block. Level 1 is the CRS default and is meant to
	// give very few false positives; each level up catches more and needs more tuning for the site.
	ParanoiaLevel int
	// DetectionParanoiaLevel runs the rules of a higher level for logging only. 0 means the same as ParanoiaLevel.
	DetectionParanoiaLevel int
	// InboundThreshold is the anomaly score at which a request is blocked (CRS default 5: one critical rule).
	InboundThreshold int
	// OutboundThreshold is the same for a response; it only matters with InspectResponses.
	OutboundThreshold int
	// RequestBodyLimit is the most bytes of request body that are inspected, and a larger body is refused.
	// Default 1 MiB. Bodies are held in memory, so memory use is up to this limit
	// times the number of requests in flight.
	RequestBodyLimit int64
	// UploadDir is where the engine writes the file parts of a multipart upload while it reads them. They are
	// removed when the request ends. Empty means the system's temporary directory, which other programs share: give
	// it a directory of its own (mode 0700, owned by the service user) so that an upload is never readable by, or
	// confusable with, anything else.
	UploadDir string
	// InspectResponses also runs the CRS response rules (information leaks, web shells). It buffers responses
	// up to 512 KiB of text, HTML and XML, and costs latency, so it is off by default.
	InspectResponses bool
	// AllowedMethods replaces the CRS list (GET HEAD POST OPTIONS). REST APIs need PUT, PATCH and DELETE here.
	AllowedMethods []string
	// Before and After are extra SecLang directives run before and after the CRS rules, which is where the CRS
	// documentation puts rule exclusions. They are trusted configuration written by the operator, so never fill
	// them from a tenant's input.
	Before, After string
	// DisableLocalRules omits Carnical's supplemental injection rules. They are separate from the verified, unmodified CRS
	// release, run at PL1 and add five inbound anomaly points per finding. Mode and thresholds apply to both rule sets.
	DisableLocalRules bool
	// LocalRulesOff switches single local rules off by id, for a site whose ordinary traffic one of them refuses (an
	// admin reaching its own diagnostic page, say). At most 32 ids, each a local rule's.
	LocalRulesOff []int
}

// DefaultSettings blocks at paranoia level 1 with the standard thresholds.
func DefaultSettings() Settings {
	return Settings{Mode: ModeBlock, ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, RequestBodyLimit: 1 << 20}
}

// ResponseBodyLimit is the response body limit base/coraza.conf gives the rules (SecResponseBodyLimit): with
// InspectResponses, the response body rules run when a response reaches it.
const ResponseBodyLimit = 512 << 10

// ResponseLimit is ResponseBodyLimit, or 0 when Before or After may change it.
func (s Settings) ResponseLimit() int64 {
	if strings.Contains(strings.ToLower(s.Before+s.After), "responsebodylimit") {
		return 0
	}
	return ResponseBodyLimit
}

var methodShape = regexp.MustCompile(`^[A-Z][A-Z-]{0,19}$`)

// pathShape keeps what is written into a SecLang directive from being able to end it or start another: no space,
// quote, newline, semicolon or backtick.
var pathShape = regexp.MustCompile(`^[A-Za-z0-9_./:\\-]+$`)

// Validate reports the first setting that is not usable.
func (s Settings) Validate() error {
	switch s.Mode {
	case ModeBlock, ModeDetect, ModeOff:
	default:
		return fmt.Errorf("mode %q is not block, detect or off", s.Mode)
	}
	if s.ParanoiaLevel < 1 || s.ParanoiaLevel > 4 {
		return fmt.Errorf("paranoia level %d is not 1 to 4", s.ParanoiaLevel)
	}
	if s.DetectionParanoiaLevel != 0 && (s.DetectionParanoiaLevel < s.ParanoiaLevel || s.DetectionParanoiaLevel > 4) {
		return fmt.Errorf("detection paranoia level %d must be 0 or from %d to 4", s.DetectionParanoiaLevel, s.ParanoiaLevel)
	}
	if s.InboundThreshold < 1 || s.InboundThreshold > 1000 || s.OutboundThreshold < 1 || s.OutboundThreshold > 1000 {
		return fmt.Errorf("thresholds must be 1 to 1000")
	}
	if s.RequestBodyLimit < 1024 || s.RequestBodyLimit > 1<<30 {
		return fmt.Errorf("request body limit must be 1 KiB to 1 GiB")
	}
	if s.UploadDir != "" && (!filepath.IsAbs(s.UploadDir) || !pathShape.MatchString(s.UploadDir)) {
		return fmt.Errorf("the upload directory must be an absolute path made of letters, digits and . _ - / : and backslash only")
	}
	// SecLang joins a line ending in a backslash to the next one, which would swallow the following directive.
	if strings.HasSuffix(s.UploadDir, `\`) {
		return fmt.Errorf("the upload directory must not end with a backslash")
	}
	for _, m := range s.AllowedMethods {
		if !methodShape.MatchString(m) {
			return fmt.Errorf("method %q is not an upper-case HTTP method", m)
		}
	}
	if len(s.AllowedMethods) > 20 {
		return fmt.Errorf("more than 20 allowed methods")
	}
	if len(s.LocalRulesOff) > 32 {
		return fmt.Errorf("more than 32 local rules switched off")
	}
	for _, id := range s.LocalRulesOff {
		if LocalRuleMessage(id) == "" {
			return fmt.Errorf("%d is not a local rule id", id)
		}
	}
	return nil
}

// Directives returns the SecLang that configures the engine and loads the whole CRS from FS(). Give it to
// coraza.NewWAFConfig().WithRootFS(crs.FS()).WithDirectives(...).
func (s Settings) Directives() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	engine := map[Mode]string{ModeBlock: "On", ModeDetect: "DetectionOnly", ModeOff: "Off"}[s.Mode]
	response := "Off"
	if s.InspectResponses {
		response = "On"
	}
	detection := s.DetectionParanoiaLevel
	if detection == 0 {
		detection = s.ParanoiaLevel
	}
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	line("Include base/coraza.conf")
	line("SecRuleEngine %s", engine)
	line("SecRequestBodyAccess On")
	line("SecRequestBodyLimit %d", s.RequestBodyLimit)
	line("SecRequestBodyInMemoryLimit %d", s.RequestBodyLimit) // a body that is not a file upload stays in memory
	if s.UploadDir != "" {
		line("SecUploadDir %s", s.UploadDir)
	}
	line("SecUploadKeepFiles Off")
	line("SecRequestBodyLimitAction Reject")
	line("SecResponseBodyAccess %s", response)
	line("SecAuditEngine Off") // matches are reported through the error callback, not an audit file
	line("Include owasp_crs/crs-setup.conf.example")
	line(`SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d"`, s.ParanoiaLevel)
	line(`SecAction "id:900001,phase:1,pass,t:none,nolog,setvar:tx.detection_paranoia_level=%d"`, detection)
	line(`SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d"`,
		s.InboundThreshold, s.OutboundThreshold)
	if len(s.AllowedMethods) > 0 {
		line(`SecAction "id:900200,phase:1,pass,t:none,nolog,setvar:'tx.allowed_methods=%s'"`, strings.Join(s.AllowedMethods, " "))
	}
	if s.Before != "" {
		line("%s", s.Before)
	}
	// Multiphase builds can inspect query/cookie values during phase 1. Load
	// local signatures after CRS initializes the per-PL scores, or that reset
	// would erase their findings. Keep every upstream file in sorted order.
	rules, err := fs.Glob(files, "owasp_crs/*.conf")
	if err != nil {
		return "", fmt.Errorf("list embedded CRS rules: %w", err)
	}
	initialized := false
	for _, path := range rules {
		line("Include %s", path)
		if path == "owasp_crs/REQUEST-901-INITIALIZATION.conf" {
			initialized = true
			if !s.DisableLocalRules {
				line("Include local/*.conf")
				if len(s.LocalRulesOff) > 0 {
					ids := make([]string, len(s.LocalRulesOff))
					for i, id := range s.LocalRulesOff {
						ids[i] = strconv.Itoa(id)
					}
					line("SecRuleRemoveById %s", strings.Join(ids, " "))
				}
			}
		}
	}
	if !initialized {
		return "", fmt.Errorf("embedded CRS initialization rules are missing")
	}
	if s.After != "" {
		line("%s", s.After)
	}
	return b.String(), nil
}
