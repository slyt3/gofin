// Package risk scores a fingerprint and returns what fired and why.
// No network calls, no global state, no external deps.
package risk

// Category is the type of problem a signal is flagging.
type Category string

const (
	// CategoryAutomation covers definitive bot markers — things like
	// navigator.webdriver being true or PhantomJS globals in the page.
	CategoryAutomation Category = "automation"

	// CategorySpoofing covers cases where something doesn't add up —
	// the browser says one thing and the IP geo or TLS layer says another.
	CategorySpoofing Category = "spoofing"

	// CategoryPrivacy covers fingerprinting APIs that are blocked or
	// randomised. Not necessarily malicious, but worth knowing.
	CategoryPrivacy Category = "privacy"

	// CategoryConsistency covers field combinations no real browser produces.
	CategoryConsistency Category = "consistency"

	// CategoryNetwork covers signals from TLS and HTTP/2 metadata.
	CategoryNetwork Category = "network"
)

// Signal is the result of running one detection rule.
// Rules always return one of these. If the rule didn't fire, Triggered is false
// and the rest is just context about what was checked.
type Signal struct {
	// ID is the rule name in snake_case. Stable across versions.
	ID string `json:"id"`

	// Category is which bucket this rule falls into.
	Category Category `json:"category"`

	// Weight is how much this adds to the total score if it fires (1–35).
	// All weights are additive and the total is capped at 100.
	Weight int `json:"weight"`

	// Triggered is true when the rule actually matched.
	Triggered bool `json:"triggered"`

	// Description is a short label for the rule.
	Description string `json:"description"`

	// Detail has the specific values that caused it to fire.
	// Only set when Triggered is true.
	Detail string `json:"detail,omitempty"`
}

// RiskLevel is the bucket we put a score into once it's been calculated.
type RiskLevel string

const (
	RiskLow      RiskLevel = "low"      // 0–20
	RiskMedium   RiskLevel = "medium"   // 21–50
	RiskHigh     RiskLevel = "high"     // 51–80
	RiskCritical RiskLevel = "critical" // 81–100
)

// Result is everything the scorer returns. Marshal it to JSON, store it,
// forward it — whatever you need.
type Result struct {
	// Score is the overall risk value, 0–100. Higher is worse.
	Score int `json:"score"`

	// Risk is the human-friendly name for the score range.
	Risk RiskLevel `json:"risk"`

	// Signals has every rule that ran, including ones that didn't fire.
	// That way you can see what was checked, not just what triggered.
	Signals []Signal `json:"signals"`

	// Categories shows how much each category contributed to the total.
	Categories map[string]int `json:"categories"`

	// Explanation is filled in by gofin.Analyze or gofin.AnalyzeJSON.
	// If you call risk.Evaluate directly, it'll be empty — that's expected.
	Explanation string `json:"explanation,omitempty"`
}
