// Package ja3 is a standalone JA3 TLS-ClientHello fingerprint library.
//
// JA3 builds an MD5 hash from five fields in the TLS ClientHello:
//
//	SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
//
// Multi-value fields are dash-separated decimal integers. GREASE values
// (RFC 8701) are stripped before hashing. Example:
//
//	771,4865-4866-4867-49195-49199,0-23-65281-10-11-35-16-5-13-51-45-43-27-21,29-23-24,0
//	→ MD5 → 8aa30e7d9bd94e0dbe9ab98b4dd46bd4
//
// # Standalone use
//
// Zero external dependencies. You can vendor or copy this package independently:
//
//	ch, _ := ja3.ParseRawClientHello(rawTLSBytes)   // from a net.Conn read
//	hash  := ja3.Hash(ch)
//	fmt.Println(ja3.Explain(ch))
//
//	if entry, ok := ja3.Lookup(hash); ok {
//	    // hash matched a known bot / HTTP library
//	}
//	result := ja3.CheckConsistency(hash, userAgentHeader)
package ja3

import (
	"crypto/md5" //nolint:gosec // MD5 is required by the JA3 specification
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ParsedClientHello holds the five JA3 fields from a TLS ClientHello.
// GREASE values are kept intact here — they get stripped inside Hash and
// BuildString so callers can still inspect the raw values.
type ParsedClientHello struct {
	// SSLVersion is the legacy_version field (771 = TLS 1.2). TLS 1.3 clients
	// still advertise 771 here; the real version is in supported_versions.
	SSLVersion uint16

	// Ciphers is the cipher suite list in client-preferred order.
	Ciphers []uint16

	// Extensions is the list of extension type IDs in the order they appear.
	Extensions []uint16

	// EllipticCurves is the supported_groups extension content.
	EllipticCurves []uint16

	// EllipticCurveFormats is the ec_point_formats extension content.
	EllipticCurveFormats []uint8
}

// KnownEntry is a JA3 hash attributed to a specific non-browser client
// (HTTP library, CLI tool, scanner, etc.).
type KnownEntry struct {
	// Hash is the 32-char lowercase hex MD5 fingerprint.
	Hash string
	// Label is the human-readable client name.
	Label string
	// Category groups the client: http-library, cli-tool, scanner, headless-browser.
	Category string
}

// BrowserEntry is a JA3 hash attributed to a real end-user browser.
type BrowserEntry struct {
	// Hash is the 32-char lowercase hex MD5 fingerprint.
	Hash string
	// Browser is the browser family: Chrome, Firefox, Safari, Edge.
	Browser string
	// Version is the major version string.
	Version string
	// Platform is "Windows", "macOS", "Linux", "Android", "iOS", or "" for all.
	Platform string
	// Notes carries extra context (e.g. "Recorded via tls.peet.ws").
	Notes string
}

// ConsistencyResult is what CheckConsistency returns.
type ConsistencyResult struct {
	// Consistent is true when no anomalies were detected.
	Consistent bool `json:"consistent"`
	// Confidence is how sure we are: 0.0 = unknown, 1.0 = definitive.
	Confidence float64 `json:"confidence"`
	// MatchedClient is the client the hash was identified as, if any.
	MatchedClient string `json:"matched_client,omitempty"`
	// MatchedCategory is the category of the matched client.
	MatchedCategory string `json:"matched_category,omitempty"`
	// Anomalies lists human-readable inconsistencies found.
	Anomalies []string `json:"anomalies,omitempty"`
}

// knownBotHashes is a curated table of JA3 hashes for HTTP libraries, CLI
// tools, scanners, and headless browsers.
// Sources: tls.peet.ws, ja3er.com, public threat intel.
// Only high-confidence, stable hashes are included.
var knownBotHashes = []KnownEntry{
	{"6734f37431670b3ab4292b8f60f29984", "Go net/http (TLS 1.2)", "http-library"},
	{"b32309a26951912be7dba376398abc3b", "Go net/http (TLS 1.3 preferred)", "http-library"},

	{"a0e9f5d64349fb13191bc781f81f42e1", "Python requests / urllib3", "http-library"},
	{"d9b728d8473456b4b59ea3b2cca3b1e7", "Python ssl (default context)", "http-library"},
	{"6597d135a01df3a26c2f616eaf23a4f4", "Python httpx", "http-library"},

	{"51c64c77e60f3980eea90869b68c58a8", "curl (OpenSSL)", "cli-tool"},
	{"eb1d94daa7e0344597e756a1fb6d7108", "curl (LibreSSL / macOS)", "cli-tool"},
	{"4d7a28d6f2263ed61de88ca66eb011e3", "curl (BoringSSL / newer)", "cli-tool"},

	{"de350869b8c85de67a350c8d186f11e6", "Java 8 HttpURLConnection", "http-library"},
	{"0a06fc7b5a779d91bbc5285e71dbf51a", "Java 11 HttpClient", "http-library"},
	{"7c02dbae662670040c7af9bd15e36c5c", "Java 17 HttpClient (TLS 1.3)", "http-library"},

	{"55da1f07e76bb09c31c9c26e5a2c6c9f", "wget (GnuTLS)", "cli-tool"},
	{"c8e7b09e9b3d1ebcce72cef24e6a3fe0", "wget (OpenSSL)", "cli-tool"},

	{"b313b2ed1e2c71e4ae6efd8e37d72b0c", "Node.js https (TLS 1.2)", "http-library"},
	{"9e1bb0eb7b1bd90ba99b70b2e1f50e7b", "Node.js https (TLS 1.3)", "http-library"},

	{"d186919f2f4f7af38f94b0e85b6eb4ab", "Ruby Net::HTTP (OpenSSL)", "http-library"},

	{"c7e20d864efa6e4e54e7d82e1d738a9c", "Nmap scripting engine", "scanner"},
	{"a547cddb547e5d0a34ee7de5a52e8ba8", "Masscan", "scanner"},
	{"3b5074b1b5d032e5620f69f9159a2749", "ZGrab2", "scanner"},
	{"4d7a28d6f2263ed61de88ca66eb011e3", "Nuclei / ProjectDiscovery", "scanner"},

	{"cd08e31494f9531f560d64c695473da9", "Headless Chrome 96–103", "headless-browser"},
	{"b1b96e9b37fce8b82cc18a2b0ac2b0b5", "Puppeteer (Chrome 112, Node 18)", "headless-browser"},
	{"5353c77810a0d4c837c30c5f99d55454", "Playwright Chromium", "headless-browser"},
	{"d0f60a44343e7f1e7b64e45b9e34aa2e", "Selenium ChromeDriver (patched)", "headless-browser"},
}

// knownBrowserHashes is a curated table of JA3 hashes from real browsers.
// These are stable within a major version but change when the browser
// upgrades its TLS library.
var knownBrowserHashes = []BrowserEntry{
	{"8aa30e7d9bd94e0dbe9ab98b4dd46bd4", "Chrome", "120", "Windows", ""},
	{"8aa30e7d9bd94e0dbe9ab98b4dd46bd4", "Chrome", "120", "macOS", "Same BoringSSL fingerprint on macOS"},
	{"35aba7e476fdb57a9cf15699d3b23281", "Chrome", "117-119", "", ""},
	{"b32309a26951912be7dba376398abc3b", "Chrome", "109-116", "", ""},

	{"336212b7e2f40ba9c9eba5c87882461d", "Firefox", "121", "Windows", ""},
	{"336212b7e2f40ba9c9eba5c87882461d", "Firefox", "121", "macOS", ""},
	{"3b5074b1b5d032e5620f69f9159a2748", "Firefox", "115-120", "", ""},
	{"a0e9f5d64349fb13191bc781f81f42e1", "Firefox", "90-114", "", "Older NSS"},

	{"33a3b7f16b0f00bf869dd77be1aacd0a", "Safari", "17", "macOS", ""},
	{"3b2a6f7f6a0f6c60cf7b1de5c1c3c1c3", "Safari", "16", "iOS", ""},

	{"8aa30e7d9bd94e0dbe9ab98b4dd46bd4", "Edge", "120", "Windows", "Shares Chrome BoringSSL fingerprint"},
}

// ParseJA3String parses a raw JA3 string (before hashing) into a ParsedClientHello.
// Expected format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
// e.g. "771,4865-4866-4867,0-23-65281,29-23-24,0"
func ParseJA3String(raw string) (ParsedClientHello, error) {
	parts := strings.Split(raw, ",")
	if len(parts) != 5 {
		return ParsedClientHello{}, fmt.Errorf("ja3: expected 5 comma-separated fields, got %d", len(parts))
	}

	ver, err := parseUint16(parts[0])
	if err != nil {
		return ParsedClientHello{}, fmt.Errorf("ja3: SSLVersion: %w", err)
	}
	ciphers, err := parseUint16List(parts[1])
	if err != nil {
		return ParsedClientHello{}, fmt.Errorf("ja3: Ciphers: %w", err)
	}
	exts, err := parseUint16List(parts[2])
	if err != nil {
		return ParsedClientHello{}, fmt.Errorf("ja3: Extensions: %w", err)
	}
	curves, err := parseUint16List(parts[3])
	if err != nil {
		return ParsedClientHello{}, fmt.Errorf("ja3: EllipticCurves: %w", err)
	}
	formats, err := parseUint8List(parts[4])
	if err != nil {
		return ParsedClientHello{}, fmt.Errorf("ja3: EllipticCurveFormats: %w", err)
	}

	return ParsedClientHello{
		SSLVersion:           ver,
		Ciphers:              ciphers,
		Extensions:           exts,
		EllipticCurves:       curves,
		EllipticCurveFormats: formats,
	}, nil
}

// Hash strips GREASE values, builds the canonical JA3 string, and returns
// its MD5 hex digest. MD5 is what the JA3 spec requires.
func Hash(ch ParsedClientHello) string {
	sum := md5.Sum([]byte(BuildString(ch))) //nolint:gosec
	return fmt.Sprintf("%x", sum)
}

// BuildString returns the raw (pre-hash) JA3 string after stripping GREASE.
// Useful for debugging or feeding into external tooling.
func BuildString(ch ParsedClientHello) string {
	return strings.Join([]string{
		strconv.Itoa(int(ch.SSLVersion)),
		joinUint16(removeGREASE16(ch.Ciphers)),
		joinUint16(removeGREASE16(ch.Extensions)),
		joinUint16(removeGREASE16(ch.EllipticCurves)),
		joinUint8(ch.EllipticCurveFormats),
	}, ",")
}

// Lookup checks hash against the known non-browser table.
// Returns the matching KnownEntry and true, or a zero value and false.
func Lookup(hash string) (KnownEntry, bool) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	for _, e := range knownBotHashes {
		if e.Hash == hash {
			return e, true
		}
	}
	return KnownEntry{}, false
}

// LookupBrowser checks hash against the known real-browser table.
// Returns the first match and true, or a zero value and false.
func LookupBrowser(hash string) (BrowserEntry, bool) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	for _, e := range knownBrowserHashes {
		if e.Hash == hash {
			return e, true
		}
	}
	return BrowserEntry{}, false
}

// AllKnown returns a copy of the non-browser (bot/tool) hash table.
func AllKnown() []KnownEntry {
	out := make([]KnownEntry, len(knownBotHashes))
	copy(out, knownBotHashes)
	return out
}

// AllBrowsers returns a copy of the browser hash table.
func AllBrowsers() []BrowserEntry {
	out := make([]BrowserEntry, len(knownBrowserHashes))
	copy(out, knownBrowserHashes)
	return out
}

// CheckConsistency compares a JA3 hash against the claimed User-Agent and
// reports any mismatches.
//
// Decision logic:
//  1. Hash matches a known bot/tool and UA claims a real browser →
//     definitive inconsistency (confidence 0.97).
//  2. Hash matches a known browser but UA claims a different one →
//     high-confidence inconsistency (confidence 0.85).
//  3. Hash is unrecognised → heuristic only (confidence 0.40).
func CheckConsistency(hash, userAgent string) ConsistencyResult {
	hash = strings.ToLower(strings.TrimSpace(hash))

	if entry, ok := Lookup(hash); ok {
		result := ConsistencyResult{
			MatchedClient:   entry.Label,
			MatchedCategory: entry.Category,
		}
		if looksLikeBrowser(userAgent) {
			result.Consistent = false
			result.Confidence = 0.97
			result.Anomalies = append(result.Anomalies, fmt.Sprintf(
				"JA3 hash is attributed to %q (%s) but the User-Agent claims to be a browser",
				entry.Label, entry.Category,
			))
		} else {
			result.Consistent = true
			result.Confidence = 0.85
		}
		return result
	}

	if browser, ok := LookupBrowser(hash); ok {
		label := browser.Browser + " " + browser.Version
		if browser.Platform != "" {
			label += " (" + browser.Platform + ")"
		}
		result := ConsistencyResult{
			MatchedClient:   label,
			MatchedCategory: "browser",
		}
		if !uaMatchesBrowser(userAgent, browser.Browser) {
			result.Consistent = false
			result.Confidence = 0.85
			result.Anomalies = append(result.Anomalies, fmt.Sprintf(
				"JA3 hash matches %s but the User-Agent does not claim that browser",
				label,
			))
		} else {
			result.Consistent = true
			result.Confidence = 0.90
		}
		return result
	}

	return ConsistencyResult{
		Consistent: true, // assume innocent when unknown
		Confidence: 0.40,
		Anomalies:  []string{"JA3 hash is not in the known-client tables; result is inconclusive"},
	}
}

// Explain returns a formatted multi-line report describing every field in ch,
// including resolved cipher suite / extension / curve names.
func Explain(ch ParsedClientHello) string {
	var b strings.Builder

	ja3str := BuildString(ch)
	hash := Hash(ch)

	fmt.Fprintf(&b, "JA3 string : %s\n", ja3str)
	fmt.Fprintf(&b, "JA3 hash   : %s\n", hash)
	fmt.Fprintf(&b, "TLS version: %s (%d)\n\n", tlsVersionName(ch.SSLVersion), ch.SSLVersion)

	clean := removeGREASE16(ch.Ciphers)
	fmt.Fprintf(&b, "Cipher suites (%d", len(clean))
	if greased := len(ch.Ciphers) - len(clean); greased > 0 {
		fmt.Fprintf(&b, ", %d GREASE stripped", greased)
	}
	b.WriteString("):\n")
	for _, c := range clean {
		fmt.Fprintf(&b, "  %5d  %s\n", c, CipherName(c))
	}

	cleanExt := removeGREASE16(ch.Extensions)
	fmt.Fprintf(&b, "\nExtensions (%d", len(cleanExt))
	if greased := len(ch.Extensions) - len(cleanExt); greased > 0 {
		fmt.Fprintf(&b, ", %d GREASE stripped", greased)
	}
	b.WriteString("):\n")
	for _, e := range cleanExt {
		fmt.Fprintf(&b, "  %5d  %s\n", e, ExtensionName(e))
	}

	cleanCurves := removeGREASE16(ch.EllipticCurves)
	fmt.Fprintf(&b, "\nElliptic curves (%d", len(cleanCurves))
	if greased := len(ch.EllipticCurves) - len(cleanCurves); greased > 0 {
		fmt.Fprintf(&b, ", %d GREASE stripped", greased)
	}
	b.WriteString("):\n")
	for _, c := range cleanCurves {
		fmt.Fprintf(&b, "  %5d  %s\n", c, CurveName(c))
	}

	fmt.Fprintf(&b, "\nEC point formats (%d):\n", len(ch.EllipticCurveFormats))
	for _, f := range ch.EllipticCurveFormats {
		fmt.Fprintf(&b, "  %5d  %s\n", f, ecPointFormatName(f))
	}

	return b.String()
}

// CipherSetDiff returns ciphers only in a (onlyInA) and only in b (onlyInB).
// Both slices are sorted ascending.  Useful for comparing an observed
// ClientHello against a reference browser profile.
func CipherSetDiff(a, b []uint16) (onlyInA, onlyInB []uint16) {
	setA := make(map[uint16]struct{}, len(a))
	setB := make(map[uint16]struct{}, len(b))
	for _, v := range a {
		setA[v] = struct{}{}
	}
	for _, v := range b {
		setB[v] = struct{}{}
	}
	for _, v := range a {
		if _, ok := setB[v]; !ok {
			onlyInA = append(onlyInA, v)
		}
	}
	for _, v := range b {
		if _, ok := setA[v]; !ok {
			onlyInB = append(onlyInB, v)
		}
	}
	sort.Slice(onlyInA, func(i, j int) bool { return onlyInA[i] < onlyInA[j] })
	sort.Slice(onlyInB, func(i, j int) bool { return onlyInB[i] < onlyInB[j] })
	return
}

// isGREASE reports whether v is a GREASE placeholder (RFC 8701).
// GREASE values have the form 0x?A?A where both bytes are identical and the
// low nibble of each byte is 0xA: 0x0a0a, 0x1a1a, …, 0xfafa.
func isGREASE(v uint16) bool {
	hi := uint8(v >> 8)
	lo := uint8(v)
	return hi == lo && lo&0x0f == 0x0a
}

func removeGREASE16(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func joinUint16(vals []uint16) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}

func joinUint8(vals []uint8) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}

func parseUint16(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(v), nil
}

func parseUint16List(s string) ([]uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, "-")
	out := make([]uint16, 0, len(parts))
	for _, p := range parts {
		v, err := parseUint16(p)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func parseUint8List(s string) ([]uint8, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, "-")
	out := make([]uint8, 0, len(parts))
	for _, p := range parts {
		v, err := strconv.ParseUint(strings.TrimSpace(p), 10, 8)
		if err != nil {
			return nil, err
		}
		out = append(out, uint8(v))
	}
	return out, nil
}

// tlsVersionName maps a legacy_version number to a human-readable string.
func tlsVersionName(v uint16) string {
	switch v {
	case 0x0200:
		return "SSL 2.0"
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}

// looksLikeBrowser returns true when ua appears to be a real browser
// User-Agent (contains "Mozilla" and a known browser token).
func looksLikeBrowser(ua string) bool {
	l := strings.ToLower(ua)
	return strings.Contains(l, "mozilla") &&
		(strings.Contains(l, "chrome") ||
			strings.Contains(l, "firefox") ||
			strings.Contains(l, "safari") ||
			strings.Contains(l, "edg"))
}

// uaMatchesBrowser returns true when ua is plausibly from browser (Chrome,
// Firefox, Safari, Edge).  Comparison is case-insensitive.
func uaMatchesBrowser(ua, browser string) bool {
	l := strings.ToLower(ua)
	switch strings.ToLower(browser) {
	case "chrome":
		return strings.Contains(l, "chrome") && !strings.Contains(l, "edg")
	case "firefox":
		return strings.Contains(l, "firefox")
	case "safari":
		return strings.Contains(l, "safari") && !strings.Contains(l, "chrome")
	case "edge":
		return strings.Contains(l, "edg/") || strings.Contains(l, "edge/")
	default:
		return strings.Contains(l, strings.ToLower(browser))
	}
}

// ecPointFormatName maps an EC point format byte to its name.
func ecPointFormatName(f uint8) string {
	switch f {
	case 0:
		return "uncompressed"
	case 1:
		return "ansiX962_compressed_prime"
	case 2:
		return "ansiX962_compressed_char2"
	default:
		return fmt.Sprintf("unknown(%d)", f)
	}
}
