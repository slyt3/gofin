package risk

import (
	"fmt"
	"strings"
	"time"

	"github.com/slyt3/gofin/fingerprint"
)

// ruleFunc evaluates a single detection condition against a Fingerprint and
// returns the corresponding Signal.  Every rule always returns a Signal;
// Signal.Triggered == false means the condition did not fire.
type ruleFunc func(fp *fingerprint.Fingerprint) Signal

// allRules returns the complete ordered set of rule evaluators.
// Rules within a category are ordered by descending weight so that the
// explain package can present the most significant signals first.
func allRules() []ruleFunc {
	return []ruleFunc{
		ruleWebdriver,
		ruleHeadlessMode,
		rulePhantomJS,
		ruleSelenium,
		ruleSwiftShader,
		ruleLLVMPipe,

		ruleTimezoneOffsetMismatch,
		rulePlatformUAMismatch,
		ruleIPTimezoneMismatch,
		ruleSoftwareWebGLVendor,
		ruleImpossibleScreenResolution,
		ruleViewportLargerThanScreen,

		ruleCanvasBlocked,
		ruleWebGLBlocked,
		ruleAudioBlocked,

		ruleAcceptLanguageMismatch,
		ruleNoFontsDetected,
		ruleNoPluginsOnDesktop,
		ruleTouchDesktopMismatch,
		ruleZeroHardwareConcurrency,
		ruleZeroDeviceMemory,
	}
}


func ruleWebdriver(fp *fingerprint.Fingerprint) Signal {
	s := Signal{
		ID:          "webdriver",
		Category:    CategoryAutomation,
		Weight:      35,
		Description: "WebDriver flag is active",
	}
	if fp.Webdriver {
		s.Triggered = true
		s.Detail = "navigator.webdriver returns true — a definitive marker that a WebDriver-based automation framework (Selenium, Playwright, Puppeteer) is controlling this browser."
	}
	return s
}

func ruleHeadlessMode(fp *fingerprint.Fingerprint) Signal {
	s := Signal{
		ID:          "headless_mode",
		Category:    CategoryAutomation,
		Weight:      30,
		Description: "Headless browser mode detected",
	}
	if fp.HeadlessMode {
		s.Triggered = true
		s.Detail = "The browser is running without a visible window. Headless mode is the standard execution environment for automated test frameworks and web-scraping bots."
	}
	return s
}

func rulePhantomJS(fp *fingerprint.Fingerprint) Signal {
	s := Signal{
		ID:          "phantomjs",
		Category:    CategoryAutomation,
		Weight:      30,
		Description: "PhantomJS artifacts detected",
	}
	if fp.PhantomJS {
		s.Triggered = true
		s.Detail = "window.callPhantom or window._phantom is defined, identifying this session as PhantomJS-driven."
	}
	return s
}

func ruleSelenium(fp *fingerprint.Fingerprint) Signal {
	s := Signal{
		ID:          "selenium",
		Category:    CategoryAutomation,
		Weight:      25,
		Description: "Selenium/ChromeDriver artifacts detected",
	}
	if fp.Selenium {
		s.Triggered = true
		s.Detail = "ChromeDriver-specific DOM properties (e.g. document.$cdc_*) are present, indicating that Selenium or a ChromeDriver-based tool is in use."
	}
	return s
}

func ruleSwiftShader(fp *fingerprint.Fingerprint) Signal {
	s := Signal{
		ID:          "swiftshader_renderer",
		Category:    CategoryAutomation,
		Weight:      28,
		Description: "SwiftShader software GPU renderer",
	}
	if containsFold(fp.WebGLRenderer, "swiftshader") {
		s.Triggered = true
		s.Detail = fmt.Sprintf(
			"WebGL renderer is %q. Google SwiftShader is the CPU-based rasteriser used by headless Chrome when no physical GPU is present — common in CI/CD pipelines and cloud VMs.",
			fp.WebGLRenderer,
		)
	}
	return s
}

func ruleLLVMPipe(fp *fingerprint.Fingerprint) Signal {
	s := Signal{
		ID:          "llvmpipe_renderer",
		Category:    CategoryAutomation,
		Weight:      22,
		Description: "LLVMpipe/softpipe software GPU renderer",
	}
	r := strings.ToLower(fp.WebGLRenderer)
	if strings.Contains(r, "llvmpipe") || strings.Contains(r, "softpipe") {
		s.Triggered = true
		s.Detail = fmt.Sprintf(
			"WebGL renderer is %q. LLVMpipe/softpipe is the Mesa software rasteriser, typically found in headless Linux environments without a physical GPU.",
			fp.WebGLRenderer,
		)
	}
	return s
}


func ruleTimezoneOffsetMismatch(fp *fingerprint.Fingerprint) Signal {
	s := Signal{
		ID:          "timezone_offset_mismatch",
		Category:    CategorySpoofing,
		Weight:      20,
		Description: "Timezone offset inconsistent with claimed timezone name",
	}
	if fp.Timezone == "" || fp.TimezoneOffset == nil {
		return s
	}
	loc, err := time.LoadLocation(fp.Timezone)
	if err != nil {
		return s // unknown timezone name — skip rather than false-positive
	}
	// Go returns the UTC offset in seconds east of UTC; positive = east.
	// JavaScript getTimezoneOffset() returns minutes *west* of UTC; positive = west.
	// Relation: jsOffset = -(goOffsetSec / 60)
	_, goOffsetSec := time.Now().In(loc).Zone()
	expectedJSOffset := -(goOffsetSec / 60)
	if *fp.TimezoneOffset != expectedJSOffset {
		s.Triggered = true
		s.Detail = fmt.Sprintf(
			"Timezone %q implies a JavaScript offset of %d min, but the browser reports %d min. The clock timezone appears to have been programmatically overridden.",
			fp.Timezone, expectedJSOffset, *fp.TimezoneOffset,
		)
	}
	return s
}

func rulePlatformUAMismatch(fp *fingerprint.Fingerprint) Signal {
	s := Signal{
		ID:          "platform_ua_mismatch",
		Category:    CategorySpoofing,
		Weight:      18,
		Description: "navigator.platform OS does not match User-Agent OS",
	}
	if fp.UserAgent == "" || fp.Platform == "" {
		return s
	}
	uaOS := osFromUA(fp.UserAgent)
	platformOS := osFromPlatform(fp.Platform)
	if uaOS != "unknown" && platformOS != "unknown" && uaOS != platformOS {
		s.Triggered = true
		s.Detail = fmt.Sprintf(
			"User-Agent suggests %s but navigator.platform is %q (parsed as %s). A mismatch here almost always means the User-Agent string has been spoofed.",
			uaOS, fp.Platform, platformOS,
		)
	}
	return s
}

func ruleIPTimezoneMismatch(fp *fingerprint.Fingerprint) Signal {
	s := Signal{
		ID:          "ip_timezone_mismatch",
		Category:    CategorySpoofing,
		Weight:      15,
		Description: "IP geolocation timezone differs from browser timezone",
	}
	if fp.IPTimezone == "" || fp.Timezone == "" {
		return s
	}
	if !timezoneOffsetsClose(fp.IPTimezone, fp.Timezone, 3*3600) {
		s.Triggered = true
		s.Detail = fmt.Sprintf(
			"Geo-IP places the client in timezone %q but the browser reports %q. A difference of more than 3 hours suggests a VPN, proxy, or deliberately spoofed timezone.",
			fp.IPTimezone, fp.Timezone,
		)
	}
	return s
}

func ruleSoftwareWebGLVendor(fp *fingerprint.Fingerprint) Signal {
	s := Signal{
		ID:          "software_webgl_vendor",
		Category:    CategorySpoofing,
		Weight:      15,
		Description: "WebGL vendor identifies a known software renderer",
	}
	v := strings.ToLower(fp.WebGLVendor)
	if strings.Contains(v, "brian paul") || strings.Contains(v, "microsoft basic render") {
		s.Triggered = true
		s.Detail = fmt.Sprintf(
			"WebGL vendor is %q. This is a reference-software renderer, not a real GPU. Legitimate desktop browsers always report the actual hardware vendor.",
			fp.WebGLVendor,
		)
	}
	return s
}

func ruleImpossibleScreenResolution(fp *fingerprint.Fingerprint) Signal {
	s := Signal{
		ID:          "impossible_screen_resolution",
		Category:    CategorySpoofing,
		Weight:      12,
		Description: "Screen resolution is zero or impossibly small",
	}
	// Only check when at least one dimension was explicitly provided.
	if fp.ScreenWidth == 0 && fp.ScreenHeight == 0 {
		return s
	}
	if fp.ScreenWidth < 100 || fp.ScreenHeight < 100 {
		s.Triggered = true
		s.Detail = fmt.Sprintf(
			"Screen reported as %d×%d px. No real consumer display is this small; headless environments commonly report 0×0 or 1×1.",
			fp.ScreenWidth, fp.ScreenHeight,
		)
	}
	return s
}

func ruleViewportLargerThanScreen(fp *fingerprint.Fingerprint) Signal {
	s := Signal{
		ID:          "viewport_larger_than_screen",
		Category:    CategorySpoofing,
		Weight:      10,
		Description: "Viewport dimensions exceed reported screen dimensions",
	}
	if fp.ScreenWidth == 0 || fp.ViewportWidth == 0 {
		return s
	}
	if fp.ViewportWidth > fp.ScreenWidth || fp.ViewportHeight > fp.ScreenHeight {
		s.Triggered = true
		s.Detail = fmt.Sprintf(
			"Viewport (%d×%d) is larger than the screen (%d×%d). A real browser's content area can never exceed the physical display dimensions.",
			fp.ViewportWidth, fp.ViewportHeight, fp.ScreenWidth, fp.ScreenHeight,
		)
	}
	return s
}


func ruleCanvasBlocked(fp *fingerprint.Fingerprint) Signal {
	s := Signal{
		ID:          "canvas_blocked",
		Category:    CategoryPrivacy,
		Weight:      8,
		Description: "Canvas fingerprinting blocked or unavailable",
	}
	if fp.CanvasHash == "" {
		s.Triggered = true
		s.Detail = "The canvas element returned an empty or blank image hash. Privacy extensions (CanvasBlocker, Brave shields) and some headless environments suppress canvas data."
	}
	return s
}

func ruleWebGLBlocked(fp *fingerprint.Fingerprint) Signal {
	s := Signal{
		ID:          "webgl_blocked",
		Category:    CategoryPrivacy,
		Weight:      6,
		Description: "WebGL fingerprinting blocked or unavailable",
	}
	if fp.WebGLHash == "" {
		s.Triggered = true
		s.Detail = "The WebGL context returned no fingerprinting data. This results from privacy settings, disabled WebGL, or a headless environment with no GPU context."
	}
	return s
}

func ruleAudioBlocked(fp *fingerprint.Fingerprint) Signal {
	s := Signal{
		ID:          "audio_blocked",
		Category:    CategoryPrivacy,
		Weight:      5,
		Description: "AudioContext fingerprinting blocked or unavailable",
	}
	if fp.AudioHash == "" {
		s.Triggered = true
		s.Detail = "The AudioContext API returned no fingerprinting data. This is common with privacy-hardened browser profiles or system audio disabled."
	}
	return s
}


func ruleAcceptLanguageMismatch(fp *fingerprint.Fingerprint) Signal {
	s := Signal{
		ID:          "accept_language_mismatch",
		Category:    CategoryConsistency,
		Weight:      10,
		Description: "HTTP Accept-Language header conflicts with navigator.language",
	}
	if fp.AcceptLanguage == "" || fp.Language == "" {
		return s
	}
	// Extract the primary language tag from "en-US,en;q=0.9,..." → "en-US"
	httpPrimary := strings.ToLower(strings.TrimSpace(
		strings.SplitN(strings.SplitN(fp.AcceptLanguage, ",", 2)[0], ";", 2)[0],
	))
	navLang := strings.ToLower(strings.TrimSpace(fp.Language))

	// Compare base language codes (e.g. "en" == "en" even if regions differ).
	httpBase := strings.SplitN(httpPrimary, "-", 2)[0]
	navBase := strings.SplitN(navLang, "-", 2)[0]
	if httpBase != navBase {
		s.Triggered = true
		s.Detail = fmt.Sprintf(
			"HTTP Accept-Language primary tag is %q but navigator.language is %q. A mismatch at the base-language level means the HTTP headers were not generated by the same browser that ran the JavaScript probe — a strong indicator of header injection.",
			httpPrimary, navLang,
		)
	}
	return s
}

func ruleNoFontsDetected(fp *fingerprint.Fingerprint) Signal {
	s := Signal{
		ID:          "no_fonts_detected",
		Category:    CategoryConsistency,
		Weight:      10,
		Description: "No system fonts detected",
	}
	// Only flag when we have evidence the probe ran (UserAgent is set) but fonts
	// came back empty.
	if fp.UserAgent != "" && len(fp.Fonts) == 0 {
		s.Triggered = true
		s.Detail = "Font enumeration returned an empty list. Headless browsers have no font subsystem, and some privacy tools suppress font detection entirely."
	}
	return s
}

func ruleNoPluginsOnDesktop(fp *fingerprint.Fingerprint) Signal {
	s := Signal{
		ID:          "no_plugins_on_desktop",
		Category:    CategoryConsistency,
		Weight:      8,
		Description: "No browser plugins on a desktop User-Agent",
	}
	if fp.UserAgent == "" {
		return s
	}
	os := osFromUA(fp.UserAgent)
	isDesktop := os == "windows" || os == "macos" || os == "linux"
	if isDesktop && len(fp.Plugins) == 0 {
		s.Triggered = true
		s.Detail = "The browser claims to be a desktop browser but reports zero navigator.plugins. Standard desktop Chrome and Firefox always expose at least a PDF viewer plugin entry."
	}
	return s
}

func ruleTouchDesktopMismatch(fp *fingerprint.Fingerprint) Signal {
	s := Signal{
		ID:          "touch_desktop_mismatch",
		Category:    CategoryConsistency,
		Weight:      8,
		Description: "Touch capability inconsistent with User-Agent OS",
	}
	if fp.UserAgent == "" {
		return s
	}
	os := osFromUA(fp.UserAgent)
	switch {
	case (os == "android" || os == "ios") && !fp.TouchSupport:
		s.Triggered = true
		s.Detail = fmt.Sprintf(
			"User-Agent reports a mobile OS (%s) but touch support is disabled. Real mobile browsers always have touch capabilities enabled.",
			os,
		)
	case (os == "macos" || os == "linux") && fp.MaxTouchPoints > 0:
		// macOS and generic Linux desktops never have touch; Windows touchscreens do.
		s.Triggered = true
		s.Detail = fmt.Sprintf(
			"User-Agent reports desktop %s but MaxTouchPoints is %d. Automation frameworks sometimes inject touch support to evade mobile-UA detection.",
			os, fp.MaxTouchPoints,
		)
	}
	return s
}

func ruleZeroHardwareConcurrency(fp *fingerprint.Fingerprint) Signal {
	s := Signal{
		ID:          "zero_hardware_concurrency",
		Category:    CategoryConsistency,
		Weight:      5,
		Description: "Hardware concurrency reports zero logical CPU cores",
	}
	if fp.UserAgent != "" && fp.HardwareConcurrency == 0 {
		s.Triggered = true
		s.Detail = "navigator.hardwareConcurrency is 0. The spec defines a minimum return value of 1; zero is only possible if the API was suppressed or the value was overridden."
	}
	return s
}

func ruleZeroDeviceMemory(fp *fingerprint.Fingerprint) Signal {
	s := Signal{
		ID:          "zero_device_memory",
		Category:    CategoryConsistency,
		Weight:      4,
		Description: "Device memory reports 0 GiB",
	}
	// DeviceMemory == 0 when the probe ran but the API returned 0.
	// -1 means "not collected"; we only flag genuine 0 readings when the UA is set.
	if fp.UserAgent != "" && fp.DeviceMemory == 0 {
		s.Triggered = true
		s.Detail = "navigator.deviceMemory returned 0 GiB. Valid values are 0.25, 0.5, 1, 2, 4, or 8. A value of 0 indicates the API was blocked or overridden."
	}
	return s
}


// osFromUA extracts a normalised OS name from a User-Agent string.
// Returns "unknown" when the string cannot be parsed.
func osFromUA(ua string) string {
	l := strings.ToLower(ua)
	switch {
	case strings.Contains(l, "android"):
		return "android"
	case strings.Contains(l, "iphone") || strings.Contains(l, "ipad"):
		return "ios"
	case strings.Contains(l, "windows"):
		return "windows"
	case strings.Contains(l, "macintosh") || strings.Contains(l, "mac os x"):
		return "macos"
	case strings.Contains(l, "linux"):
		return "linux"
	}
	return "unknown"
}

// osFromPlatform extracts a normalised OS name from navigator.platform.
func osFromPlatform(platform string) string {
	l := strings.ToLower(platform)
	switch {
	case strings.HasPrefix(l, "win"):
		return "windows"
	case strings.HasPrefix(l, "mac"):
		return "macos"
	case strings.HasPrefix(l, "linux"):
		return "linux"
	case strings.Contains(l, "iphone") || strings.Contains(l, "ipad"):
		return "ios"
	case strings.Contains(l, "android"):
		return "android"
	}
	return "unknown"
}

// timezoneOffsetsClose reports whether two IANA timezone names have UTC
// offsets within toleranceSec seconds of each other (at the current instant).
// Returns true (i.e. "no mismatch") when either timezone cannot be loaded.
func timezoneOffsetsClose(tz1, tz2 string, toleranceSec int) bool {
	loc1, err1 := time.LoadLocation(tz1)
	loc2, err2 := time.LoadLocation(tz2)
	if err1 != nil || err2 != nil {
		return true
	}
	now := time.Now()
	_, off1 := now.In(loc1).Zone()
	_, off2 := now.In(loc2).Zone()
	diff := off1 - off2
	if diff < 0 {
		diff = -diff
	}
	return diff <= toleranceSec
}

// containsFold reports whether s contains substr, case-insensitively.
func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
