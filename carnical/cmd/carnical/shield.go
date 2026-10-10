// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/netip"
	"os"
	"strings"

	"github.com/YurilLAB/coraza/carnical/shield"
)

const maxRangesBytes = 256 << 20

type shieldFlags struct {
	mode        string
	rate, burst float64
	maxConns    int
	challenge   bool
	baseline    float64
	ranges      string
	// knownFactor and knownRate are the budget returning visitors with standing share during an attack (0 means the default).
	knownFactor, knownRate float64
}

// configureShield builds the flood protection from the command line. It returns nil for -ddos off. The address-range
// table, if any, is read here, before the process confines itself.
func configureShield(log *slog.Logger, f shieldFlags, trusted []netip.Prefix) (*shield.Shield, error) {
	switch f.mode {
	case "off":
		if f.ranges != "" {
			return nil, errors.New("-ddos-ranges needs -ddos on or monitor")
		}
		return nil, nil
	case "on", "monitor":
	default:
		return nil, fmt.Errorf("-ddos must be on, monitor or off, not %q", f.mode)
	}
	cfg := shield.Config{
		RequestRate: f.rate, RequestBurst: f.burst, MaxConns: f.maxConns, NoChallenge: !f.challenge,
		MonitorOnly: f.mode == "monitor", Trusted: trusted, KnownFactor: f.knownFactor, MinKnownRate: f.knownRate,
		Detector: shield.DetectorConfig{InitialRate: f.baseline},
		OnEvent:  func(ev shield.Event) { logShieldEvent(log, ev) },
	}
	if cfg.SubnetRate == 0 && f.rate > 0 {
		cfg.SubnetRate = math.Max(500, 10*f.rate)
	}
	if f.ranges != "" {
		file, err := os.Open(f.ranges)
		if err != nil {
			return nil, fmt.Errorf("-ddos-ranges: %w", err)
		}
		defer file.Close()
		if st, err := file.Stat(); err != nil || !st.Mode().IsRegular() || st.Size() > maxRangesBytes {
			return nil, fmt.Errorf("-ddos-ranges: %s must be a regular file of at most 256 MiB", f.ranges)
		}
		r, err := shield.LoadRanges(io.LimitReader(file, maxRangesBytes))
		if err != nil {
			return nil, fmt.Errorf("-ddos-ranges: %w", err)
		}
		cfg.Labeler = r
	}
	return shield.New(cfg)
}

// logShieldEvent writes attack transitions and bounded IDS signals. Per-request logs would amplify a flood.
func logShieldEvent(log *slog.Logger, ev shield.Event) {
	attrs := []any{"state", ev.State.String(), "rate", math.Round(ev.Rate), "baseline_rate", math.Round(ev.BaselineRate), "reasons", ev.Reasons}
	if strings.HasPrefix(ev.Kind, "attack") {
		inc := ev.Incident
		clusters := make([]string, 0, len(inc.Clusters))
		for _, c := range inc.Clusters {
			clusters = append(clusters, fmt.Sprintf("%s %.0f%% from about %d addresses: %s", c.Kind, 100*c.Share, c.Sources, c.Label))
		}
		labels := make([]string, 0, len(inc.Labels))
		for _, l := range inc.Labels {
			labels = append(labels, fmt.Sprintf("%s %d", l.Label, l.Requests))
		}
		attrs = append(attrs, "started", inc.Start, "peak_rate", math.Round(inc.PeakRate), "requests", inc.Requests,
			"addresses", inc.Sources, "networks", inc.Networks, "clusters", clusters,
			"refused", inc.Refused, "challenged", inc.Challenged, "solved", inc.Solved, "banned", inc.Banned)
		if inc.DistinctLabels > 0 {
			attrs = append(attrs, "countries_or_networks", inc.DistinctLabels, "top_origins", labels)
		}
		if !inc.End.IsZero() {
			attrs = append(attrs, "ended", inc.End)
		}
	}
	msg := map[string]string{"elevated": "traffic is unusually high", "attack_start": "denial-of-service attack detected; mitigation on",
		"attack_update": "denial-of-service attack continues", "attack_end": "denial-of-service attack over", "ids_signal": "network or HTTP intrusion signal detected"}[ev.Kind]
	if ev.Kind == "elevated" {
		log.Info(msg, attrs...)
		return
	}
	log.Warn(msg, attrs...)
}
