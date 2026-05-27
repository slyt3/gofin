// Package explain turns a risk.Result into a plain-English narrative.
// It imports the risk package for types but has no knowledge of fingerprint
// internals — it only reads the pre-scored signals.
package explain

import (
	"fmt"
	"sort"
	"strings"

	"github.com/slyt3/gofin/risk"
)

// Explain generates a human-readable analysis report from a scored Result.
// The output is deterministic for a given Result value.
func Explain(r risk.Result) string {
	var b strings.Builder

	//  Header 
	fmt.Fprintf(&b, "Risk score: %d/100 (%s)\n", r.Score, r.Risk)

	// Separate triggered from untriggered signals.
	var triggered []risk.Signal
	for _, s := range r.Signals {
		if s.Triggered {
			triggered = append(triggered, s)
		}
	}

	if len(triggered) == 0 {
		b.WriteString("\nNo risk signals detected. The fingerprint appears consistent with a standard browser environment.\n")
		return b.String()
	}

	//  Group by category, respecting a fixed display order 
	catOrder := []risk.Category{
		risk.CategoryAutomation,
		risk.CategorySpoofing,
		risk.CategoryConsistency,
		risk.CategoryPrivacy,
		risk.CategoryNetwork,
	}

	catLabel := map[risk.Category]string{
		risk.CategoryAutomation:  "Automation indicators",
		risk.CategorySpoofing:    "Spoofing indicators",
		risk.CategoryConsistency: "Consistency anomalies",
		risk.CategoryPrivacy:     "Privacy tool indicators",
		risk.CategoryNetwork:     "Network anomalies",
	}

	grouped := make(map[risk.Category][]risk.Signal, len(catOrder))
	for _, s := range triggered {
		grouped[s.Category] = append(grouped[s.Category], s)
	}

	// Within each category, sort by weight descending so the most significant
	// signal is listed first.
	for cat := range grouped {
		sigs := grouped[cat]
		sort.Slice(sigs, func(i, j int) bool {
			if sigs[i].Weight != sigs[j].Weight {
				return sigs[i].Weight > sigs[j].Weight
			}
			return sigs[i].ID < sigs[j].ID
		})
		grouped[cat] = sigs
	}

	var cleanCats []string
	for _, cat := range catOrder {
		sigs, ok := grouped[cat]
		if !ok || len(sigs) == 0 {
			cleanCats = append(cleanCats, strings.ToLower(catLabel[cat]))
			continue
		}

		countNote := ""
		if len(sigs) > 1 {
			countNote = fmt.Sprintf(" (%d signals)", len(sigs))
		}
		fmt.Fprintf(&b, "\n%s%s:\n", catLabel[cat], countNote)

		for _, s := range sigs {
			fmt.Fprintf(&b, "  • %s [weight: %d]", s.Description, s.Weight)
			if s.Detail != "" {
				// Indent continuation lines to align under the bullet text.
				detail := strings.ReplaceAll(s.Detail, "\n", "\n    ")
				fmt.Fprintf(&b, "\n    %s", detail)
			}
			b.WriteByte('\n')
		}
	}

	if len(cleanCats) > 0 {
		fmt.Fprintf(&b, "\nNo %s detected.\n", joinNatural(cleanCats))
	}

	return b.String()
}

// joinNatural joins a slice of strings with Oxford-comma style natural language.
//
//	[]{"a"}              → "a"
//	[]{"a","b"}          → "a or b"
//	[]{"a","b","c"}      → "a, b, or c"
func joinNatural(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	case 2:
		return parts[0] + " or " + parts[1]
	default:
		return strings.Join(parts[:len(parts)-1], ", ") + ", or " + parts[len(parts)-1]
	}
}
