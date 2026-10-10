// SPDX-License-Identifier: Apache-2.0

// Command carnical puts the OWASP Core Rule Set, run by Coraza, in front of one website.
//
//	carnical -upstream http://127.0.0.1:8081 -listen :8080            (logs what the rules find, blocks nothing)
//	carnical -upstream http://127.0.0.1:8081 -mode block              (blocks at the anomaly threshold)
//
// Start in detect mode, read the log for a few days, add exclusions for the false positives, then switch to block.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	stdlog "log"
	"log/slog"
	"maps"
	"net"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/YurilLAB/coraza/carnical/crowdsec"
	"github.com/YurilLAB/coraza/carnical/crs"
	"github.com/YurilLAB/coraza/carnical/inspect"
	"github.com/YurilLAB/coraza/carnical/proxy"
	"github.com/YurilLAB/coraza/carnical/sandbox"
)

func main() {
	if err := run(); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "carnical:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "setup" {
		if len(os.Args) != 2 {
			return errors.New("use carnical setup without extra arguments")
		}
		return runSetup(os.Stdin, os.Stdout, runArgs)
	}
	return runArgs(os.Args[1:])
}

// runArgs runs the proxy, leaving the settings a site file stores encrypted out of whatever error it returns.
func runArgs(args []string) error {
	private := map[string]string{}
	return redactPrivate(runFlags(args, private), private)
}

func runFlags(args []string, private map[string]string) error {
	flags := flag.NewFlagSet("carnical", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: carnical setup | carnical [flags]")
		flags.PrintDefaults()
	}
	configFile := flags.String("config", "", "site JSON configuration, including encrypted setup fields (maximum 64 KiB; CLI flags override it)")
	flags.String("config-key-file", "", "owner-only 32-byte key file for encrypted site fields (default: setup user key store)")
	check := flags.Bool("check", false, "validate settings and local files, then exit without listening or applying confinement")
	checkOriginHTTP := flags.Bool("check-origin-http", false, "with -check -check-origin, send HEAD / to confirm origin HTTP acceptance; no redirects")
	originCert := flags.String("origin-client-cert", "", "PEM client certificate for authenticated HTTPS origin access")
	originKey := flags.String("origin-client-key", "", "private PEM key for -origin-client-cert (loaded before confinement)")
	originCA := flags.String("origin-ca-file", "", "PEM origin CA bundle (default: system roots; server verification always enabled)")
	checkOrigin := flags.Bool("check-origin", false, "with -check, also verify origin DNS, TCP and HTTPS certificate within 10s (sends no HTTP request)")
	listen := flags.String("listen", "127.0.0.1:8080", "address to listen on")
	healthListen := flags.String("health-listen", "", "private health listener: numeric loopback address and port (default: disabled)")
	probe := flags.String("probe", "", "probe live or ready on -health-listen, then exit without loading the WAF")
	drainDelay := flags.Duration("drain-delay", 0, "delay after withdrawing readiness before closing the visitor listener (0 to 1m)")
	shutdownTimeout := flags.Duration("shutdown-timeout", 30*time.Second, "total budget for drain delay and active HTTP requests (100ms to 10m)")
	upstream := flags.String("upstream", "", "the website to protect, such as http://127.0.0.1:8081 (required)")
	upstreamHost := flags.String("upstream-host", "", "Host header to send to the upstream (default: the visitor's)")
	mode := flags.String("mode", "detect", "detect (log only), block, or off")
	paranoia := flags.Int("paranoia", 1, "CRS paranoia level 1 to 4: rules at this level and below block")
	detection := flags.Int("detection-paranoia", 0, "log what a higher level would find (0 = same as -paranoia)")
	inbound := flags.Int("inbound-threshold", 5, "anomaly score at which a request is blocked")
	outbound := flags.Int("outbound-threshold", 4, "anomaly score at which a response is blocked (with -inspect-responses)")
	maxBody := flags.Int64("max-body", 1<<20, "largest request body inspected, in bytes; a larger body is refused")
	formatsMode := flags.String("formats-mode", "monitor", "request formats: monitor (default), block, or off; independent of -mode and overrides policy monitor")
	formatsPolicy := flags.String("formats-policy", "", "JSON request-format policy file (maximum 1 MiB; default: built-in format limits)")
	formatsStats := flags.Duration("formats-stats-interval", time.Minute, "log changed per-rule blocked/monitored format totals (0 = off; 100ms to 24h)")
	requestEncoding := flags.Bool("allow-request-encoding", false, "allow one bounded gzip or deflate layer through the format inspector (requires formats enabled)")
	responses := flags.Bool("inspect-responses", false, "also run the CRS response rules (buffers text, HTML and XML responses)")
	localRules := flags.Bool("local-rules", true, "run Carnical supplemental injection rules at PL1, with the selected CRS mode and threshold")
	apiSpec := flags.String("api-spec", "", "local OpenAPI JSON/YAML contract; scalar/array parameters and JSON bodies (no fetching or learning)")
	apiSpecMode := flags.String("api-spec-mode", "block", "OpenAPI contract action: block or monitor (block requires formats block)")
	methods := flags.String("allowed-methods", "", "comma-separated HTTP methods to allow (default: the CRS list GET HEAD POST OPTIONS)")
	trustedList := flags.String("trusted-proxies", "", "comma-separated addresses or ranges that may supply X-Forwarded-For")
	originAllow := flags.String("origin-allow", "", "comma-separated addresses or ranges the upstream may be at even though they are not public (default: public addresses only)")
	hosts := flags.String("hosts", "", "comma-separated names this site answers to; any other Host gets 421 (default: any)")
	encodedSlash := flags.Bool("allow-encoded-slash", false, "allow %2f and %5c in request paths (refused by default)")
	pathParams := flags.Bool("allow-path-params", false, "allow a semicolon in request paths, as Java's ;jsessionid= needs (refused by default)")
	denyHeaders := flags.String("deny-headers", "", "comma-separated headers whose presence refuses the request, such as Next-Action on a site with no server actions")
	wordpress := flags.Bool("wordpress", false, "protect a WordPress site: no scripts from upload and cache directories, xmlrpc.php off, login attempts limited")
	xmlrpc := flags.Bool("allow-xmlrpc", false, "with -wordpress, leave xmlrpc.php reachable")
	loginRate := flags.Int("login-per-minute", 10, "with -wordpress, POSTs to wp-login.php one address may make a minute")
	apiRate := flags.Int("api-per-minute", 0, "shared API requests per verified client address in a sliding minute (0 = disabled; maximum 100000)")
	apiPaths := flags.String("api-rate-paths", "/api,/graphql", "plain path prefixes sharing -api-per-minute, matched by path segment; / covers every route")
	scriptNames := flags.Bool("allow-script-names", false, "allow uploads named like scripts (shell.php, .htaccess); refused by default")
	scriptContent := flags.Bool("allow-script-content", false, "allow uploads that contain a PHP, ASP or JSP opening tag; refused by default")
	keepBanners := flags.Bool("keep-banners", false, "keep X-Powered-By and Server headers from the application")
	keepCaching := flags.Bool("keep-caching", false, "do not add Cache-Control: private, no-store to responses that set a cookie or look like a stylesheet but are HTML")
	ddosMode := flags.String("ddos", "on", "flood protection: on (detect attacks, including ones spread over many addresses, and mitigate them), monitor (detect and log; baseline connection/request limits still apply), or off")
	ddosRate := flags.Float64("ddos-rate", 50, "the least requests a second one address may make, at all times; raised automatically to follow the busiest addresses on a busy site")
	ddosBurst := flags.Float64("ddos-burst", 200, "burst of requests one address may make at once")
	ddosConns := flags.Int("ddos-max-conns", 20000, "the least connections held open at once, raised with the site's average; a fifth are kept for clients that used the site before")
	ddosChallenge := flags.Bool("ddos-challenge", true, "during an attack, ask unknown browsers to pass a short JavaScript check instead of refusing them")
	ddosBaseline := flags.Float64("ddos-baseline-rate", 0, "the site's usual requests a second, to start from instead of learning it (so a restart during an attack is not fooled)")
	ddosRanges := flags.String("ddos-ranges", "", "address-range table (ip2asn TSV) naming the countries and networks an attack comes from, in the attack logs")
	csAPI := flags.String("crowdsec-api", "", "CrowdSec LAPI HTTP(S) origin or absolute Unix socket path (empty = disabled; HTTP requires loopback)")
	csKey := flags.String("crowdsec-key-file", "", "private file containing a dedicated CrowdSec bouncer key")
	csCA := flags.String("crowdsec-ca-file", "", "PEM CA bundle for CrowdSec HTTPS (default: system roots; verification always enabled)")
	csInterval := flags.Duration("crowdsec-poll", 10*time.Second, "CrowdSec update interval, 1s to 1h")
	csTimeout := flags.Duration("crowdsec-timeout", 5*time.Second, "CrowdSec API timeout, 100ms to 30s")
	csStale := flags.Duration("crowdsec-max-stale", 2*time.Minute, "CrowdSec cache freshness limit; at least poll + timeout, at most 24h")
	csFailOpen := flags.Bool("crowdsec-fail-open", false, "allow unlisted visitors when CrowdSec cache is stale; unexpired bans still block")
	csLimit := flags.Int("crowdsec-max-decisions", 200000, "maximum stored CrowdSec bans and decisions in a response, 1 to 1000000")
	csOrigins := flags.String("crowdsec-origins", "", "optional comma-separated CrowdSec decision origins (empty = all)")
	maxConns := flags.Int("max-conns-per-ip", 128, "connections one address may hold open (negative = no limit)")
	uploadDir := flags.String("upload-dir", "", "directory for the file parts of uploads while a request runs (default: the system temporary directory; give it a private one)")
	fromSystemd := flags.Bool("systemd-socket", false, "use the listening socket systemd passes in (socket activation), so the proxy needs no privilege to use port 443")
	confine := flags.Bool("confine", false, "after start-up, confine the process: no new programs, no ptrace, no other files, no other ports (Linux; build with CGO_ENABLED=0)")
	confineConnect := flags.String("confine-connect", "80,443,53", "with -confine, the TCP ports the proxy may connect to: the ports of the origins, and 53 for DNS")
	confineRead := flags.String("confine-read", "", "with -confine, extra files and directories the proxy may read (for example a certificate directory it reloads from)")
	confineBestEffort := flags.Bool("confine-best-effort", false, "with -confine, carry on with the layers the kernel supports instead of refusing to start")
	allowUpgrade := flags.Bool("allow-upgrade", false, "let WebSocket upgrades through, uninspected")
	maxUpstream := flags.Int("max-upstream", 256, "requests allowed at the upstream at once")
	evalBudget := flags.Duration("eval-budget", 2*time.Second, "most time each phase of rule evaluation may take for one request; a request over it is refused with 503")
	maxEval := flags.Int("max-evaluations", 0, "requests in rule evaluation at once (0 = the number of CPUs, negative = no limit)")
	maxForm := flags.Int64("max-form-body", 128<<10, "largest request body that is not a file upload, in bytes; uploads may be as large as -max-body")
	details := flags.Bool("log-details", false, "log client address, URI, matched data and macro-expanded messages (may contain credentials)")
	certFile := flags.String("tls-cert", "", "TLS certificate file")
	keyFile := flags.String("tls-key", "", "TLS key file (not accessible to everyone or writable by its group, as 0600 or 0640)")
	showVersion := flags.Bool("version", false, "print the CRS version that is embedded and exit")
	if err := flags.Parse(args); err != nil {
		return err
	}

	if *showVersion {
		if *probe != "" || *check || *checkOrigin || *checkOriginHTTP {
			return errors.New("-version cannot be combined with probes or deployment checks")
		}
		info, err := crs.Info()
		if err != nil {
			return err
		}
		fmt.Printf("OWASP CRS %s (archive sha256 %s, signed by %s)\n", info.Version, info.ArchiveSHA256, info.SignerFingerprint)
		return nil
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments; use named flags")
	}
	if *configFile != "" {
		encrypted, err := loadSiteConfig(*configFile, flags)
		if err != nil {
			return err
		}
		maps.Copy(private, encrypted)
	}
	if *checkOrigin && !*check {
		return errors.New("-check-origin requires -check")
	}
	if *checkOriginHTTP && (!*check || !*checkOrigin) {
		return errors.New("-check-origin-http requires -check and -check-origin")
	}
	lifecycle := lifecycleOptions{healthAddress: *healthListen, drain: *drainDelay, shutdown: *shutdownTimeout, details: *details}
	if err := lifecycle.validate(); err != nil {
		return err
	}
	if *probe != "" {
		if *check || *checkOrigin || *checkOriginHTTP {
			return errors.New("-probe cannot be combined with deployment checks")
		}
		return probeHealth(*probe, *healthListen)
	}
	// A hang-up drains like SIGTERM: there is no configuration to reload. Once the first signal has started the drain, the
	// handlers are removed, so a second signal ends the process at once instead of waiting out the shutdown budget.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	go func() {
		<-ctx.Done()
		stop()
	}()
	if *upstream == "" {
		return errors.New("-upstream is required")
	}
	if (*certFile == "") != (*keyFile == "") {
		return errors.New("give both -tls-cert and -tls-key, or neither")
	}
	if *formatsStats != 0 && (*formatsStats < 100*time.Millisecond || *formatsStats > 24*time.Hour) {
		return errors.New("-formats-stats-interval must be 0 or between 100ms and 24h")
	}
	formatInspector, err := configureFormats(*formatsMode, *formatsPolicy, *requestEncoding)
	if err != nil {
		return err
	}
	var inspectors []inspect.Inspector
	if formatInspector != nil {
		inspectors = append(inspectors, formatInspector)
	}
	apiInspector, apiReport, err := configureAPI(*apiSpec, *apiSpecMode, *formatsMode)
	if err != nil {
		return err
	}
	if apiInspector != nil {
		inspectors = append(inspectors, apiInspector)
	}
	target, err := url.Parse(*upstream)
	if err != nil {
		return fmt.Errorf("-upstream: %w", err)
	}
	originTLS, err := configureOriginTLS(target, *originCert, *originKey, *originCA)
	if err != nil {
		return err
	}
	trusted, err := proxy.ParseTrusted(*trustedList)
	if err != nil {
		return err
	}
	origin, err := proxy.ParseOriginAllow(*originAllow)
	if err != nil {
		return err
	}
	settings := crs.DefaultSettings()
	settings.Mode = crs.Mode(*mode)
	settings.ParanoiaLevel, settings.DetectionParanoiaLevel = *paranoia, *detection
	settings.InboundThreshold, settings.OutboundThreshold = *inbound, *outbound
	settings.RequestBodyLimit = *maxBody
	settings.InspectResponses = *responses
	settings.DisableLocalRules = !*localRules
	settings.UploadDir = *uploadDir
	if *methods != "" {
		for _, m := range strings.Split(*methods, ",") {
			settings.AllowedMethods = append(settings.AllowedMethods, strings.ToUpper(strings.TrimSpace(m)))
		}
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cs, err := configureCrowdSec(crowdSecFlags{api: *csAPI, keyFile: *csKey, caFile: *csCA, origins: *csOrigins,
		interval: *csInterval, timeout: *csTimeout, maxStale: *csStale, failOpen: *csFailOpen, maxDecisions: *csLimit})
	if err != nil {
		return err
	}
	if cs != nil {
		defer cs.Close()
		if !*check {
			if err := cs.Sync(ctx); err != nil {
				return err
			} // authentication and complete snapshot required at startup
			log.Info("CrowdSec connected", "entries", cs.Stats().Entries, "skipped", cs.Stats().Skipped, "fail_open", *csFailOpen)
		}
	}
	if apiInspector != nil {
		log.Info("API contract loaded", "mode", *apiSpecMode, "sha256", apiReport.Hash, "routes", apiReport.Routes,
			"warnings", apiReport.Warnings, "warnings_dropped", apiReport.WarningsDropped)
	}
	guard, err := configureShield(log, shieldFlags{mode: *ddosMode, rate: *ddosRate, burst: *ddosBurst, maxConns: *ddosConns,
		challenge: *ddosChallenge, baseline: *ddosBaseline, ranges: *ddosRanges}, trusted)
	if err != nil {
		return err
	}
	if guard != nil {
		defer guard.Close()
	}
	// The reverse proxy's own lines (an application that stops part way through a response body) join the JSON log as
	// the servers' do, under the name "origin".
	originErrors := newServerErrors(log.With("server", "origin"), *details)
	defer originErrors.flush()
	edge, err := proxy.New(proxy.Config{
		Upstream: target, Origin: proxy.OriginPolicy{Allow: origin}, OriginTLS: originTLS, UpstreamHost: *upstreamHost, CRS: settings, TrustedProxies: trusted, AllowUpgrade: *allowUpgrade,
		MaxUpstreamInFlight: *maxUpstream, LogDetails: *details, EvalBudget: *evalBudget, MaxEvaluations: *maxEval, MaxFormBody: *maxForm,
		AllowedHosts: splitList(*hosts), Paths: proxy.PathPolicy{AllowEncodedSlash: *encodedSlash, AllowPathParams: *pathParams},
		DenyHeaders: splitList(*denyHeaders), WordPress: proxy.WordPressPolicy{Enabled: *wordpress, AllowXMLRPC: *xmlrpc, LoginPerMinute: *loginRate},
		APIRate:   proxy.APIRatePolicy{PerMinute: *apiRate, Paths: splitList(*apiPaths)},
		Uploads:   proxy.UploadPolicy{AllowExecutableNames: *scriptNames, AllowScriptContent: *scriptContent},
		Responses: proxy.ResponsePolicy{KeepBanners: *keepBanners, KeepCaching: *keepCaching}, MaxConnsPerIP: *maxConns,
		Inspectors: inspectors, AllowRequestEncoding: *requestEncoding, Shield: guard, CrowdSec: cs,
		ErrorLog: stdlog.New(originErrors, "", 0),
		OnMatch: func(m proxy.Match) {
			attrs := []any{"rule", m.RuleID, "severity", m.Severity, "rule_msg", m.Message, "tx", m.TransactionID, "disruptive", m.Disruptive}
			if *details {
				attrs = append(attrs, "client", m.ClientIP, "uri", m.URI, "data", m.Data, "expanded_msg", m.ExpandedMessage)
			}
			log.Warn("rule matched", attrs...)
		},
	})
	if err != nil {
		return err
	}
	defer edge.Close()

	server := edge.Server(*listen)
	// Everything the proxy needs from the outside is opened before it is confined: the certificate and key are read,
	// and the listening socket exists. After that it needs no more files, and no new ports to listen on.
	if *certFile != "" {
		certPEM, err := readTLSFile(*certFile, 1<<20, false)
		if err != nil {
			return fmt.Errorf("the certificate: %w", err)
		}
		keyPEM, err := readTLSFile(*keyFile, 64<<10, true)
		if err != nil {
			return fmt.Errorf("the TLS key: %w", err)
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return fmt.Errorf("the certificate: %w", err)
		}
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	}
	var confinement sandbox.Policy
	if *confine {
		ports, err := parsePorts(*confineConnect)
		if err != nil {
			return fmt.Errorf("-confine-connect: %w", err)
		}
		// The confined proxy can connect to these ports only, so a port it needs and was not given would pass -check and
		// then fail every request.
		listed := func(port uint16) bool {
			for _, p := range ports {
				if p == port {
					return true
				}
			}
			return false
		}
		originPort, err := upstreamPort(target)
		if err != nil {
			return err
		}
		if !listed(originPort) {
			return fmt.Errorf("the upstream's TCP port %d must be listed in -confine-connect", originPort)
		}
		if cs != nil && cs.ConnectPort() != 0 && !listed(cs.ConnectPort()) {
			return errors.New("CrowdSec API TCP port must be listed in -confine-connect")
		}
		confinement = sandbox.Policy{ReadOnly: splitList(*confineRead), ConnectTCP: ports, BindTCP: []uint16{}, Require: !*confineBestEffort}
		// The engine writes the file parts of an upload to disk, and the confined proxy may not write the system temporary
		// directory: without a directory of its own, such uploads are refused.
		if *uploadDir == "" {
			log.Warn("-confine without -upload-dir: uploads with file parts will be refused")
		} else {
			if err := checkUploadDir(*uploadDir); err != nil {
				return fmt.Errorf("-upload-dir: %w", err)
			}
			confinement.ReadWrite = []string{*uploadDir}
		}
	}
	if err := checkDeployment(deploymentCheck{listen: *listen, target: target, policy: proxy.OriginPolicy{Allow: origin},
		originTLS: originTLS, host: *upstreamHost, systemd: *fromSystemd, probe: *checkOrigin, probeHTTP: *checkOriginHTTP}); err != nil {
		return err
	}
	if *check {
		log.Info("configuration checked", "mode", *mode, "formats_mode", *formatsMode, "origin_checked", *checkOrigin, "origin_http_checked", *checkOriginHTTP, "origin_client_identity", originTLS.Certificate != nil, "tls", *certFile != "", "sandbox_applied", false)
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var ln net.Listener
	if *fromSystemd {
		if ln, err = systemdListener(); err != nil {
			return err
		}
	} else if ln, err = net.Listen("tcp", *listen); err != nil {
		return err
	}
	defer ln.Close()
	var healthListener net.Listener
	if *healthListen != "" {
		healthListener, err = net.Listen("tcp", *healthListen)
		if err != nil {
			return fmt.Errorf("health listener: %w", err)
		}
		defer healthListener.Close()
	}
	if guard != nil {
		ln = guard.Listener(ln)
	}
	if *confine {
		rep, err := sandbox.Apply(confinement)
		if err != nil {
			return err
		}
		log.Info("confined", "no_new_privs", rep.NoNewPrivs, "undumpable", rep.Undumpable, "landlock_abi", rep.LandlockABI,
			"files", rep.LandlockFS, "ports", rep.LandlockNet, "scope", rep.LandlockScope, "seccomp", rep.Seccomp, "notes", rep.Notes)
	}
	if cs != nil {
		pollCtx, cancelPoll := context.WithCancel(context.Background())
		pollDone := make(chan struct{})
		go func() {
			defer close(pollDone)
			cs.Run(pollCtx, func(s crowdsec.Stats, err error) {
				attrs := []any{"entries", s.Entries, "skipped", s.Skipped, "stale", s.Stale, "syncs", s.Syncs,
					"failures", s.Failures, "blocked", s.Blocked, "unavailable", s.Unavailable}
				if err != nil {
					attrs = append(attrs, "error", err.Error())
					log.Warn("CrowdSec refresh failed", attrs...)
				} else {
					log.Info("CrowdSec decisions", attrs...)
				}
			})
		}()
		defer func() { cancelPoll(); <-pollDone }()
	}
	stopStats := startFormatStats(log, formatInspector, *formatsStats)
	defer stopStats()
	health := &runtimeHealth{available: func() bool { return cs == nil || *csFailOpen || !cs.Stats().Stale }}
	log.Info("listening", "addr", ln.Addr().String(), "crs", crs.Version(), "mode", *mode, "paranoia", *paranoia,
		"inbound_threshold", *inbound, "tls", *certFile != "", "confined", *confine, "ddos", *ddosMode, "formats_mode", *formatsMode, "request_encoding", *requestEncoding,
		"health_enabled", healthListener != nil)
	return serveRuntime(ctx, server, ln, healthListener, health, lifecycle, log)
}

// systemdListener returns the listening socket systemd handed over as file descriptor 3 (see sd_listen_fds(3)).
func systemdListener() (net.Listener, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") != "1" {
		return nil, errors.New("-systemd-socket was given, but systemd did not pass exactly one socket to this process")
	}
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	f := os.NewFile(3, "systemd-socket")
	defer f.Close() // FileListener duplicates it
	return net.FileListener(f)
}

// readTLSFile reads the visitor certificate or key. Links are followed (certbot's live/ directory is links into archive/),
// but only a regular file is read: it is opened without blocking, so a FIFO cannot hold start-up, and a key must not be
// readable by everyone or writable by its group.
func readTLSFile(path string, limit int64, private bool) ([]byte, error) {
	// #nosec G304 -- The certificate and key paths are operator configuration, never request input.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	switch {
	case err != nil:
		return nil, err
	case !info.Mode().IsRegular():
		return nil, errors.New("not a regular file")
	case private && runtime.GOOS != "windows" && info.Mode().Perm()&0o027 != 0:
		return nil, fmt.Errorf("mode %04o: a private key must not be accessible to everyone or writable by its group", info.Mode().Perm())
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return data, nil
}

// checkUploadDir is checked before the proxy confines itself to its upload directory: one that other users may write would
// let them reach what the proxy keeps there. (The engine has already checked that it is a directory it can write.)
func checkUploadDir(path string) error {
	info, err := os.Stat(path)
	switch {
	case err != nil:
		return err
	case !info.IsDir():
		return errors.New("not a directory")
	case runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("mode %04o: it must not be writable by its group or by everyone", info.Mode().Perm())
	}
	return nil
}

// parsePorts reads a comma-separated list of TCP ports.
func parsePorts(s string) ([]uint16, error) {
	ports := []uint16{}
	for _, part := range splitList(s) {
		n, err := strconv.ParseUint(part, 10, 16)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("%q is not a port", part)
		}
		ports = append(ports, uint16(n))
	}
	return ports, nil
}

// splitList reads a comma-separated list, ignoring empty items.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
