// Package h2fp provides HTTP/2 client fingerprinting utilities.
//
// HTTP/2 clients advertise their preferences in the initial SETTINGS frame and
// WINDOW_UPDATE frame sent immediately after the connection preface.  Different
// HTTP clients (real browsers vs automation tools vs raw HTTP/2 libraries) emit
// distinctly different sequences, making it possible to verify whether the
// observed HTTP/2 behaviour matches the claimed User-Agent.
//
// The fingerprint is composed of:
//  1. SETTINGS frame: ordered list of (ID, value) pairs
//  2. WINDOW_UPDATE increment sent on the connection (stream 0)
//  3. Whether a PRIORITY frame was sent on stream 1
//  4. Order of pseudo-headers in the first HEADERS frame
//
// Reference:
//
//	https://www.rfc-editor.org/rfc/rfc7540 (HTTP/2)
//	https://www.rfc-editor.org/rfc/rfc9113 (HTTP/2 successor, same framing)
package h2fp

import "strings"

// SettingID is an HTTP/2 SETTINGS parameter identifier.
type SettingID uint16

const (
	SettingHeaderTableSize      SettingID = 0x1
	SettingEnablePush           SettingID = 0x2
	SettingMaxConcurrentStreams SettingID = 0x3
	SettingInitialWindowSize    SettingID = 0x4
	SettingMaxFrameSize         SettingID = 0x5
	SettingMaxHeaderListSize    SettingID = 0x6
)

// SettingName maps a SettingID to its human-readable name.
var SettingName = map[SettingID]string{
	SettingHeaderTableSize:      "HEADER_TABLE_SIZE",
	SettingEnablePush:           "ENABLE_PUSH",
	SettingMaxConcurrentStreams: "MAX_CONCURRENT_STREAMS",
	SettingInitialWindowSize:    "INITIAL_WINDOW_SIZE",
	SettingMaxFrameSize:         "MAX_FRAME_SIZE",
	SettingMaxHeaderListSize:    "MAX_HEADER_LIST_SIZE",
}

// Setting is a single parameter as sent in an HTTP/2 SETTINGS frame.
type Setting struct {
	ID    SettingID `json:"id"`
	Value uint32    `json:"value"`
}

// Profile describes the HTTP/2 behaviour of a known client.
type Profile struct {
	// Name is the human-readable client name (e.g. "Chrome 120").
	Name string

	// Settings is the ordered list of SETTINGS entries.
	Settings []Setting

	// WindowUpdate is the connection-level WINDOW_UPDATE increment.
	WindowUpdate uint32

	// StreamPriority indicates whether a PRIORITY frame was sent on stream 1.
	StreamPriority bool

	// PseudoHeaderOrder is the canonical order of HTTP/2 pseudo-headers in
	// the first HEADERS frame (method, path, authority, scheme).
	PseudoHeaderOrder []string
}

// knownProfiles is a curated set of HTTP/2 fingerprints for well-known clients.
// Values are sourced from open packet captures and public research.
var knownProfiles = []Profile{
	{
		Name: "Chrome 120 (Windows/macOS)",
		Settings: []Setting{
			{SettingHeaderTableSize, 65536},
			{SettingEnablePush, 0},
			{SettingMaxConcurrentStreams, 1000},
			{SettingInitialWindowSize, 6291456},
			{SettingMaxFrameSize, 16384},
			{SettingMaxHeaderListSize, 262144},
		},
		WindowUpdate:      15663105,
		StreamPriority:    false,
		PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"},
	},
	{
		Name: "Firefox 121 (Windows/macOS)",
		Settings: []Setting{
			{SettingHeaderTableSize, 65536},
			{SettingInitialWindowSize, 131072},
			{SettingMaxFrameSize, 16384},
			{SettingMaxConcurrentStreams, 100},
			{SettingMaxHeaderListSize, 10485760},
			{SettingEnablePush, 0},
		},
		WindowUpdate:      12517377,
		StreamPriority:    true,
		PseudoHeaderOrder: []string{":method", ":path", ":authority", ":scheme"},
	},
	{
		Name: "Safari 17 (macOS)",
		Settings: []Setting{
			{SettingHeaderTableSize, 4096},
			{SettingEnablePush, 0},
			{SettingMaxConcurrentStreams, 100},
			{SettingInitialWindowSize, 2097152},
			{SettingMaxFrameSize, 16384},
		},
		WindowUpdate:      10485760,
		StreamPriority:    false,
		PseudoHeaderOrder: []string{":method", ":scheme", ":path", ":authority"},
	},
	{
		Name: "Go net/http2",
		Settings: []Setting{
			{SettingHeaderTableSize, 4096},
			{SettingInitialWindowSize, 4194304},
		},
		WindowUpdate:      1073741824,
		StreamPriority:    false,
		PseudoHeaderOrder: []string{":authority", ":method", ":path", ":scheme"},
	},
	{
		Name: "Python httpx / h2",
		Settings: []Setting{
			{SettingHeaderTableSize, 4096},
			{SettingEnablePush, 0},
			{SettingMaxConcurrentStreams, 100},
			{SettingInitialWindowSize, 65535},
			{SettingMaxHeaderListSize, 65536},
		},
		WindowUpdate:      65535,
		StreamPriority:    false,
		PseudoHeaderOrder: []string{":method", ":path", ":scheme", ":authority"},
	},
	{
		Name: "Node.js http2 (built-in)",
		Settings: []Setting{
			{SettingHeaderTableSize, 4096},
			{SettingEnablePush, 1},
			{SettingInitialWindowSize, 65535},
			{SettingMaxFrameSize, 16384},
		},
		WindowUpdate:      65535,
		StreamPriority:    false,
		PseudoHeaderOrder: []string{":method", ":path", ":scheme", ":authority"},
	},
}

// Observation holds the HTTP/2 signals captured by the server for a single
// connection.  Populate it from whatever H2 inspection hook is available
// (e.g. a custom net.Conn wrapper or a reverse-proxy plugin).
type Observation struct {
	Settings          []Setting `json:"settings"`
	WindowUpdate      uint32    `json:"window_update"`
	StreamPriority    bool      `json:"stream_priority"`
	PseudoHeaderOrder []string  `json:"pseudo_header_order"`
}

// MatchResult is the output of Match.
type MatchResult struct {
	// Matched is the best-matching known Profile, or nil when no close match
	// was found.
	Matched *Profile

	// Score is a similarity score in [0, 1].  1.0 means all compared fields
	// are identical.
	Score float64

	// Anomalies lists human-readable descriptions of fields that differ
	// between the observation and the best-matching profile.
	Anomalies []string
}

// Match compares an Observation against all known profiles and returns the
// closest match.  When claimedUA is non-empty, it also checks whether the
// best match is consistent with what the User-Agent string claims.
func Match(obs Observation, claimedUA string) MatchResult {
	if len(knownProfiles) == 0 {
		return MatchResult{}
	}

	best := &knownProfiles[0]
	bestScore := similarity(obs, knownProfiles[0])
	for i := 1; i < len(knownProfiles); i++ {
		s := similarity(obs, knownProfiles[i])
		if s > bestScore {
			bestScore = s
			best = &knownProfiles[i]
		}
	}

	anomalies := diffAnomalies(obs, *best)

	// If a UA was supplied, check for obvious class mismatches.
	if claimedUA != "" {
		ua := strings.ToLower(claimedUA)
		name := strings.ToLower(best.Name)
		switch {
		case strings.Contains(ua, "chrome") && !strings.Contains(name, "chrome"):
			anomalies = append(anomalies, "H2 profile matches "+best.Name+" but User-Agent claims Chrome")
		case strings.Contains(ua, "firefox") && !strings.Contains(name, "firefox"):
			anomalies = append(anomalies, "H2 profile matches "+best.Name+" but User-Agent claims Firefox")
		case strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome") && !strings.Contains(name, "safari"):
			anomalies = append(anomalies, "H2 profile matches "+best.Name+" but User-Agent claims Safari")
		}
	}

	return MatchResult{
		Matched:   best,
		Score:     bestScore,
		Anomalies: anomalies,
	}
}

// AllProfiles returns a copy of the built-in profile table.
func AllProfiles() []Profile {
	out := make([]Profile, len(knownProfiles))
	copy(out, knownProfiles)
	return out
}


// similarity returns a score in [0, 1] measuring how closely obs matches p.
func similarity(obs Observation, p Profile) float64 {
	total := 4.0 // four components
	score := 0.0

	// 1. SETTINGS match (order-sensitive)
	if settingsEqual(obs.Settings, p.Settings) {
		score++
	}

	// 2. WindowUpdate exact match
	if obs.WindowUpdate == p.WindowUpdate {
		score++
	}

	// 3. StreamPriority match
	if obs.StreamPriority == p.StreamPriority {
		score++
	}

	// 4. Pseudo-header order match
	if pseudoOrderEqual(obs.PseudoHeaderOrder, p.PseudoHeaderOrder) {
		score++
	}

	return score / total
}

func settingsEqual(a, b []Setting) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Value != b[i].Value {
			return false
		}
	}
	return true
}

func pseudoOrderEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func diffAnomalies(obs Observation, p Profile) []string {
	var out []string
	if !settingsEqual(obs.Settings, p.Settings) {
		out = append(out, "SETTINGS frame contents differ from "+p.Name+" reference")
	}
	if obs.WindowUpdate != p.WindowUpdate {
		out = append(out, "WINDOW_UPDATE increment differs from "+p.Name+" reference")
	}
	if obs.StreamPriority != p.StreamPriority {
		out = append(out, "stream-1 PRIORITY presence differs from "+p.Name+" reference")
	}
	if !pseudoOrderEqual(obs.PseudoHeaderOrder, p.PseudoHeaderOrder) {
		out = append(out, "pseudo-header order differs from "+p.Name+" reference")
	}
	return out
}
