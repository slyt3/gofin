package risk

import (
	"github.com/slyt/gofin/fingerprint"
)

// Rule is what a custom detection rule looks like.
// Keep your rules stateless — everything they need comes in through Payload.
type Rule interface {
	// Name is the rule's identifier, shows up in SignalResult.Name.
	Name() string

	// Category is the broad risk bucket this rule belongs to.
	Category() string

	// Weight is how much this rule contributes to the total if it fires.
	// Keep it in (0, 1] — the engine sums triggered weights and caps at 1.0.
	Weight() float64

	// Evaluate inspects the payload and returns whether the rule fired.
	Evaluate(p *fingerprint.Payload) SignalResult
}

// RuleFunc lets you define a rule as an inline function instead of a named struct.
// Handy for simple rules that don't need their own type.
type RuleFunc struct {
	name     string
	category string
	weight   float64
	fn       func(*fingerprint.Payload) SignalResult
}

// NewRuleFunc wraps a plain function as a Rule.
//
// Example — canvas hash blocklist:
//
//	blocklist := map[string]bool{"d41d8cd98f00b204e9800998ecf8427e": true}
//	rule := risk.NewRuleFunc("canvas_hash_blocklist", "spoofing", 0.9,
//	    func(p *fingerprint.Payload) risk.SignalResult {
//	        if p.Browser == nil || !blocklist[p.Browser.CanvasHash] {
//	            return risk.SignalResult{Name: "canvas_hash_blocklist"}
//	        }
//	        return risk.SignalResult{
//	            Name:      "canvas_hash_blocklist",
//	            Triggered: true,
//	            Reason:    "canvas hash matched known automation tool",
//	        }
//	    })
func NewRuleFunc(name, category string, weight float64, fn func(*fingerprint.Payload) SignalResult) RuleFunc {
	return RuleFunc{name: name, category: category, weight: weight, fn: fn}
}

// Name implements Rule.
func (r RuleFunc) Name() string { return r.name }

// Category implements Rule.
func (r RuleFunc) Category() string { return r.category }

// Weight implements Rule.
func (r RuleFunc) Weight() float64 { return r.weight }

// Evaluate implements Rule.
func (r RuleFunc) Evaluate(p *fingerprint.Payload) SignalResult { return r.fn(p) }

// Engine runs a set of Rules against a Payload and adds up the scores.
type Engine struct {
	rules []Rule
}

// NewEngine returns an empty Engine. Add rules with AddRule before calling Run.
func NewEngine() *Engine {
	return &Engine{}
}

// AddRule adds a rule to the engine. Rules run in the order they were added.
func (e *Engine) AddRule(r Rule) {
	e.rules = append(e.rules, r)
}

// Run evaluates every rule against p and returns a Score.
// The total is capped at 1.0 even if your rules add up past it.
func (e *Engine) Run(p *fingerprint.Payload) Score {
	signals := make([]SignalResult, 0, len(e.rules))
	total := 0.0

	for _, r := range e.rules {
		result := r.Evaluate(p)
		signals = append(signals, result)
		if result.Triggered {
			total += r.Weight()
		}
	}

	if total > 1.0 {
		total = 1.0
	}

	return Score{
		Total:   total,
		Level:   floatToRiskLevel(total),
		Signals: signals,
	}
}

// floatToRiskLevel maps a 0–1 score to a risk bucket.
func floatToRiskLevel(t float64) RiskLevel {
	switch {
	case t <= 0.20:
		return RiskLow
	case t <= 0.50:
		return RiskMedium
	case t <= 0.80:
		return RiskHigh
	default:
		return RiskCritical
	}
}
