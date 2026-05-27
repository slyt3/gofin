package fingerprint

// Package fingerprint defines the data types for the gofin pipeline.
// Everything flows through Fingerprint (the flat legacy type) or Payload
// (the newer structured version). Parse JSON into one, hand it to risk.
//
// Collect what you can from your JS probe and server-side TLS inspection,
// populate a Fingerprint, and let the scorer figure out what's suspicious.

import (
	"encoding/json"
	"fmt"
)

// Fingerprint is the flat input type. Every field is optional.
// Missing fields are ignored by the scorer — they never cause false positives,
// they just mean fewer signals can fire. Populate what you can.
type Fingerprint struct {
	// *** Browser identity ***

	// UserAgent is navigator.userAgent from JavaScript.
	UserAgent string `json:"user_agent"`

	// Platform is navigator.platform (e.g. "Win32", "MacIntel", "Linux x86_64").
	Platform string `json:"platform"`

	// *** Screen & viewport ***

	ScreenWidth  int     `json:"screen_width"`
	ScreenHeight int     `json:"screen_height"`
	ColorDepth   int     `json:"color_depth"` // screen.colorDepth
	PixelRatio   float64 `json:"pixel_ratio"` // window.devicePixelRatio

	// Viewport is the visible page area (excludes browser chrome).
	ViewportWidth  int `json:"viewport_width"`
	ViewportHeight int `json:"viewport_height"`

	// *** Locale & time ***

	// Timezone is an IANA timezone name (e.g. "America/New_York").
	Timezone string `json:"timezone"`

	// TimezoneOffset is new Date().getTimezoneOffset() in minutes.
	// Positive = west of UTC (New York EST = 300).
	// Pointer so the scorer can tell the difference between UTC and "not set".
	TimezoneOffset *int `json:"timezone_offset"`

	Language  string   `json:"language"`  // navigator.language
	Languages []string `json:"languages"` // navigator.languages

	// *** Hardware hints ***

	// HardwareConcurrency is navigator.hardwareConcurrency (logical CPU count).
	// 0 means the probe didn't run or the browser suppressed the value.
	HardwareConcurrency int `json:"hardware_concurrency"`

	// DeviceMemory is navigator.deviceMemory in GiB (0.25 | 0.5 | 1 | 2 | 4 | 8).
	// -1 means "not collected".  0 means the API returned 0, which is invalid.
	DeviceMemory float64 `json:"device_memory"`

	// *** Network (server-supplied) ***

	IP         string `json:"ip"`          // client IP address (IPv4 or IPv6)
	IPCountry  string `json:"ip_country"`  // ISO-3166-1 alpha-2 from geo-IP
	IPTimezone string `json:"ip_timezone"` // IANA timezone from geo-IP

	// *** Canvas API ***

	// CanvasHash is a hash of a canvas toDataURL() render.
	// Empty means the API was blocked or returned a blank image.
	CanvasHash string `json:"canvas_hash"`

	// *** WebGL ***

	WebGLHash     string `json:"webgl_hash"`     // hash of WEBGL_debug_renderer_info
	WebGLVendor   string `json:"webgl_vendor"`   // UNMASKED_VENDOR_WEBGL
	WebGLRenderer string `json:"webgl_renderer"` // UNMASKED_RENDERER_WEBGL

	// *** AudioContext ***

	// AudioHash is a hash of a small AudioContext computation.
	// Used to detect headless environments that fake audio support.
	AudioHash string `json:"audio_hash"`

	// *** Font detection ***

	// Fonts is the list of system fonts the probe detected.
	// Empty usually means either the probe didn't run or fonts were blocked.
	Fonts []string `json:"fonts"`

	// *** Browser plugins ***

	// Plugins is navigator.plugins as a list of plugin names.
	Plugins []string `json:"plugins"`

	// *** Touch capabilities ***

	TouchSupport   bool `json:"touch_support"`    // 'ontouchstart' in window
	MaxTouchPoints int  `json:"max_touch_points"` // navigator.maxTouchPoints

	// *** Miscellaneous browser flags ***

	CookieEnabled bool   `json:"cookie_enabled"`
	DoNotTrack    string `json:"do_not_track"` // "1", "0", or "unspecified"

	// *** Automation indicators ***
	// These are set to true by the JavaScript collector when the corresponding
	// artifact is detected in the DOM or global scope.

	// Webdriver is true when navigator.webdriver === true.
	Webdriver bool `json:"webdriver"`

	// HeadlessMode is true when headless-Chrome-specific properties are present
	// (e.g. window.chrome is undefined, or chrome.runtime is absent).
	HeadlessMode bool `json:"headless_mode"`

	// PhantomJS is true when window.callPhantom or window._phantom is defined.
	PhantomJS bool `json:"phantom_js"`

	// Selenium is true when ChromeDriver DOM artifacts (e.g. document.$cdc_*)
	// are detected.
	Selenium bool `json:"selenium"`

	// *** TLS layer (server-side) ***

	// JA3Hash is the MD5 JA3 TLS-ClientHello fingerprint computed by the server.
	JA3Hash string `json:"ja3_hash"`

	// JA3FullString is the raw JA3 input string before hashing, useful for
	// detailed analysis by pkg/ja3.
	JA3FullString string `json:"ja3_full_string"`

	// *** HTTP/2 fingerprint (server-side) ***
	// H2Settings is an ordered list of HTTP/2 SETTINGS parameter IDs as seen
	// in the initial SETTINGS frame.  Used by pkg/h2fp for browser matching.
	H2Settings []H2Setting `json:"h2_settings"`

	// H2WindowUpdate is the WINDOW_UPDATE increment sent by the client.
	H2WindowUpdate uint32 `json:"h2_window_update"`

	// H2StreamPriority indicates whether a PRIORITY frame was sent on stream 1.
	H2StreamPriority bool `json:"h2_stream_priority"`

	// H2PseudoHeaderOrder is the order of HTTP/2 pseudo-headers in the first
	// HEADERS frame (e.g. [":method", ":path", ":authority", ":scheme"]).
	H2PseudoHeaderOrder []string `json:"h2_pseudo_header_order"`

	// *** HTTP headers (server-side) ***

	AcceptLanguage string `json:"accept_language"`
	AcceptEncoding string `json:"accept_encoding"`

	// *** Battery ***

	BatteryCharging bool    `json:"battery_charging"`
	BatteryLevel    float64 `json:"battery_level"` // 0.0–1.0; -1 means not available

	// *** Connection ***

	ConnectionType     string  `json:"connection_type"`     // navigator.connection.effectiveType
	ConnectionDownlink float64 `json:"connection_downlink"` // Mbps
	ConnectionRTT      int     `json:"connection_rtt"`      // ms
}

// H2Setting is a single HTTP/2 SETTINGS parameter as sent in the client's
// initial SETTINGS frame.
type H2Setting struct {
	// ID is the SETTINGS parameter identifier (e.g. 1 = HEADER_TABLE_SIZE).
	ID uint16 `json:"id"`
	// Value is the value the client set for this parameter.
	Value uint32 `json:"value"`
}

// Parse decodes a JSON-encoded Fingerprint payload.
// Returns an error on empty input or malformed JSON.
func Parse(data []byte) (*Fingerprint, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("fingerprint: empty input")
	}
	var fp Fingerprint
	if err := json.Unmarshal(data, &fp); err != nil {
		return nil, fmt.Errorf("fingerprint: invalid JSON: %w", err)
	}
	return &fp, nil
}
