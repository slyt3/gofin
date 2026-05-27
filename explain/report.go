package explain

import (
	"fmt"

	"github.com/slyt3/gofin/risk"
)

// Report is the structured form of an explanation, for when you want to
// consume it programmatically rather than just print it.
type Report struct {
	// Summary is one sentence describing the overall situation.
	Summary string `json:"summary"`

	// Signals has a plain-English description for each rule that fired.
	Signals []string `json:"signals,omitempty"`

	// Suggestions are 1–3 things you can actually do about it.
	Suggestions []string `json:"suggestions,omitempty"`
}

// Generate takes a Score and returns a Report.
// Returns an empty Report if nothing triggered.
func Generate(s risk.Score) Report {
	triggered := make([]risk.SignalResult, 0, len(s.Signals))
	for _, sig := range s.Signals {
		if sig.Triggered {
			triggered = append(triggered, sig)
		}
	}

	if len(triggered) == 0 {
		return Report{}
	}

	r := Report{
		Summary: buildSummary(s),
	}

	for _, sig := range triggered {
		if sig.Reason != "" {
			r.Signals = append(r.Signals, sig.Reason)
		} else {
			r.Signals = append(r.Signals, fmt.Sprintf("rule %q fired", sig.Name))
		}
		if sug, ok := signalSuggestions[sig.Name]; ok {
			r.Suggestions = appendUnique(r.Suggestions, sug)
		}
	}

	// fall back to a generic suggestion when none of the signal names matched.
	if len(r.Suggestions) == 0 {
		r.Suggestions = append(r.Suggestions, genericSuggestion(s.Level))
	}

	// don't drown the operator in suggestions — three is enough.
	if len(r.Suggestions) > 3 {
		r.Suggestions = r.Suggestions[:3]
	}

	return r
}

// buildSummary writes the one-sentence summary based on score level.
func buildSummary(s risk.Score) string {
	count := 0
	for _, sig := range s.Signals {
		if sig.Triggered {
			count++
		}
	}

	switch s.Level {
	case risk.RiskLow:
		return "This request shows minor risk indicators and appears legitimate."
	case risk.RiskMedium:
		return fmt.Sprintf(
			"This request shows %s unusual pattern%s that warrant closer attention.",
			countWord(count), plural(count),
		)
	case risk.RiskHigh:
		return fmt.Sprintf(
			"This request shows %s indicator%s of automated or suspicious activity.",
			countWord(count), plural(count),
		)
	default: // RiskCritical
		return "This request is very likely automated or originating from a compromised client."
	}
}

func countWord(n int) string {
	words := []string{"one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"}
	if n >= 1 && n <= len(words) {
		return words[n-1]
	}
	return fmt.Sprintf("%d", n)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func appendUnique(s []string, v string) []string {
	for _, existing := range s {
		if existing == v {
			return s
		}
	}
	return append(s, v)
}

func genericSuggestion(level risk.RiskLevel) string {
	switch level {
	case risk.RiskHigh:
		return "Consider requiring additional verification for this request."
	case risk.RiskCritical:
		return "Block or challenge this request and review surrounding traffic."
	default:
		return "Monitor this session for further anomalous behaviour."
	}
}

// signalSuggestions maps known rule names to a single actionable suggestion.
var signalSuggestions = map[string]string{
	"geo_tz_mismatch":       "Verify the user's physical location matches their claimed timezone.",
	"webdriver":             "Block this request; WebDriver flag indicates automated browser control.",
	"headless_mode":         "Require CAPTCHA or step-up authentication for headless browser clients.",
	"phantomjs":             "Block this request; PhantomJS is a known automation tool.",
	"selenium":              "Block this request; Selenium is a known automation framework.",
	"canvas_hash_blocklist": "Request additional authentication factors from the user.",
	"ip_timezone_mismatch":  "Verify the user's location via a secondary channel.",
	"platform_ua_mismatch":  "Log this session for manual review; platform and user-agent conflict.",
	"swiftshader_renderer":  "Investigate whether this client is running in a virtual machine.",
	"llvmpipe_renderer":     "Investigate whether this client is running in a headless environment.",
	"software_webgl_vendor": "Consider blocking or challenging requests from software-rendered clients.",
	"no_fonts_detected":     "This is consistent with a headless or privacy-hardened browser.",
	"no_plugins_on_desktop": "Consider this signal alongside others before blocking.",
}
