package risk

import "github.com/slyt/gofin/fingerprint"

// Evaluate runs all the detection rules against fp and returns a Result.
// Explanation is intentionally left empty here — call explain.Explain on
// the result if you need the human-readable narrative.
func Evaluate(fp *fingerprint.Fingerprint) Result {
	rules := allRules()
	signals := make([]Signal, 0, len(rules))
	catScores := make(map[string]int, 5)

	total := 0
	for _, rule := range rules {
		sig := rule(fp)
		signals = append(signals, sig)
		if sig.Triggered {
			total += sig.Weight
			catScores[string(sig.Category)] += sig.Weight
		}
	}

	// Cap at 100 so the math stays sane.
	if total > 100 {
		total = 100
	}

	return Result{
		Score:      total,
		Risk:       scoreToLevel(total),
		Signals:    signals,
		Categories: catScores,
	}
}

// scoreToLevel converts a raw number into a risk bucket.
func scoreToLevel(score int) RiskLevel {
	switch {
	case score <= 20:
		return RiskLow
	case score <= 50:
		return RiskMedium
	case score <= 80:
		return RiskHigh
	default:
		return RiskCritical
	}
}
