package fingerprint

// Payload is the structured input type for risk.Engine.
// Each sub-struct is optional — leave it nil if you didn't collect that
// category of data. Not everything needs to be filled in.
type Payload struct {
	Browser  *BrowserFingerprint `json:"browser,omitempty"`
	TLS      *TLSFingerprint     `json:"tls,omitempty"`
	Network  *NetworkSignals     `json:"network,omitempty"`
	Behavior *BehaviorSignals    `json:"behavior,omitempty"`
}

// BrowserFingerprint is everything collectable from the browser's JS APIs
// — navigator, screen, canvas, WebGL, AudioContext, and the automation flags.
type BrowserFingerprint struct {
	UserAgent           string   `json:"user_agent,omitempty"`
	Platform            string   `json:"platform,omitempty"`
	Language            string   `json:"language,omitempty"`
	Languages           []string `json:"languages,omitempty"`
	HardwareConcurrency int      `json:"hardware_concurrency,omitempty"`
	DeviceMemory        float64  `json:"device_memory,omitempty"`
	ScreenWidth         int      `json:"screen_width,omitempty"`
	ScreenHeight        int      `json:"screen_height,omitempty"`
	ColorDepth          int      `json:"color_depth,omitempty"`
	PixelRatio          float64  `json:"pixel_ratio,omitempty"`
	ViewportWidth       int      `json:"viewport_width,omitempty"`
	ViewportHeight      int      `json:"viewport_height,omitempty"`
	Timezone            string   `json:"timezone,omitempty"`
	TimezoneOffset      *int     `json:"timezone_offset,omitempty"`
	CanvasHash          string   `json:"canvas_hash,omitempty"`
	WebGLHash           string   `json:"webgl_hash,omitempty"`
	WebGLVendor         string   `json:"webgl_vendor,omitempty"`
	WebGLRenderer       string   `json:"webgl_renderer,omitempty"`
	AudioHash           string   `json:"audio_hash,omitempty"`
	Fonts               []string `json:"fonts,omitempty"`
	Plugins             []string `json:"plugins,omitempty"`
	TouchSupport        bool     `json:"touch_support,omitempty"`
	MaxTouchPoints      int      `json:"max_touch_points,omitempty"`
	CookieEnabled       bool     `json:"cookie_enabled,omitempty"`
	DoNotTrack          string   `json:"do_not_track,omitempty"`
	Webdriver           bool     `json:"webdriver,omitempty"`
	HeadlessMode        bool     `json:"headless_mode,omitempty"`
	PhantomJS           bool     `json:"phantomjs,omitempty"`
	Selenium            bool     `json:"selenium,omitempty"`
}

// TLSFingerprint holds what we can see from the TLS ClientHello and
// the HTTP/2 SETTINGS frame.
type TLSFingerprint struct {
	JA3Hash             string      `json:"ja3_hash,omitempty"`
	JA3FullString       string      `json:"ja3_full_string,omitempty"`
	CipherSuites        []uint16    `json:"cipher_suites,omitempty"`
	Extensions          []uint16    `json:"extensions,omitempty"`
	EllipticCurves      []uint16    `json:"elliptic_curves,omitempty"`
	PointFormats        []uint8     `json:"point_formats,omitempty"`
	TLSVersion          uint16      `json:"tls_version,omitempty"`
	H2Settings          []H2Setting `json:"h2_settings,omitempty"`
	H2WindowUpdate      uint32      `json:"h2_window_update,omitempty"`
	H2StreamPriority    bool        `json:"h2_stream_priority,omitempty"`
	H2PseudoHeaderOrder []string    `json:"h2_pseudo_header_order,omitempty"`
}

// NetworkSignals is the server-side geo-IP and proxy-detection data.
// Populate this from your geo-IP provider before running the engine.
type NetworkSignals struct {
	IP           string `json:"ip,omitempty"`
	Country      string `json:"country,omitempty"`
	Region       string `json:"region,omitempty"`
	City         string `json:"city,omitempty"`
	ASN          int    `json:"asn,omitempty"`
	ASNOrg       string `json:"asn_org,omitempty"`
	IPTimezone   string `json:"ip_timezone,omitempty"`
	IsProxy      bool   `json:"is_proxy,omitempty"`
	IsVPN        bool   `json:"is_vpn,omitempty"`
	IsTor        bool   `json:"is_tor,omitempty"`
	IsDatacenter bool   `json:"is_datacenter,omitempty"`
}

// BehaviorSignals is timing and interaction data recorded during the session.
// Useful for catching bots that fake a good passive fingerprint.
type BehaviorSignals struct {
	MouseMovements  int     `json:"mouse_movements,omitempty"`
	ScrollEvents    int     `json:"scroll_events,omitempty"`
	KeyTimings      []int64 `json:"key_timings,omitempty"`
	ClickCount      int     `json:"click_count,omitempty"`
	TimeOnPage      int64   `json:"time_on_page,omitempty"`
	FormInteraction bool    `json:"form_interaction,omitempty"`
}
