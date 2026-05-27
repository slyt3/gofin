// Package entropy measures how "real" a fingerprint looks.
//
// Very low entropy usually means fields were synthesised or minimally filled in —
// common in bots that only populate what they know about. Suspiciously high
// entropy in normally stable fields (like platform) can mean a privacy tool
// is randomising values.
package entropy

import (
	"math"
	"strings"

	"github.com/slyt/gofin/fingerprint"
)

// Report is what Measure returns.
type Report struct {
	// StringEntropy is the average Shannon entropy across all non-empty string
	// fields, in bits per character. Real browsers usually land between 3.5–4.5.
	// Much lower than that suggests synthetic or templated strings.
	StringEntropy float64 `json:"string_entropy"`

	// FieldCoverage is the fraction of expected fields that were populated (0–1).
	// Headless sessions that only fill what the framework supports tend to score
	// low here.
	FieldCoverage float64 `json:"field_coverage"`

	// PopulatedFields is how many fields had values.
	PopulatedFields int `json:"populated_fields"`

	// TotalFields is how many fields we checked.
	TotalFields int `json:"total_fields"`
}

// Measure analyses a Fingerprint and returns an entropy report.
// Pure function, no side effects.
func Measure(fp *fingerprint.Fingerprint) Report {
	// Collect all string values that should carry real information.
	stringFields := []string{
		fp.UserAgent,
		fp.Platform,
		fp.Timezone,
		fp.Language,
		fp.WebGLVendor,
		fp.WebGLRenderer,
		fp.CanvasHash,
		fp.WebGLHash,
		fp.AudioHash,
		fp.JA3Hash,
		fp.AcceptLanguage,
		fp.AcceptEncoding,
	}

	// Field coverage: every named field that "should" be present in a
	// typical browser fingerprint is counted as expected.
	type fieldCheck struct {
		present bool
	}
	checks := []fieldCheck{
		{fp.UserAgent != ""},
		{fp.Platform != ""},
		{fp.ScreenWidth > 0},
		{fp.ScreenHeight > 0},
		{fp.ColorDepth > 0},
		{fp.Timezone != ""},
		{fp.TimezoneOffset != nil},
		{fp.Language != ""},
		{fp.HardwareConcurrency > 0},
		{fp.CanvasHash != ""},
		{fp.WebGLVendor != "" || fp.WebGLRenderer != ""},
		{fp.AudioHash != ""},
		{len(fp.Fonts) > 0},
		{len(fp.Plugins) > 0},
	}

	populated := 0
	for _, c := range checks {
		if c.present {
			populated++
		}
	}

	// Average Shannon entropy across non-empty string fields.
	var totalEntropy float64
	counted := 0
	for _, s := range stringFields {
		if s == "" {
			continue
		}
		totalEntropy += shannonEntropy(s)
		counted++
	}
	avgEntropy := 0.0
	if counted > 0 {
		avgEntropy = totalEntropy / float64(counted)
	}

	return Report{
		StringEntropy:   round(avgEntropy, 4),
		FieldCoverage:   round(float64(populated)/float64(len(checks)), 4),
		PopulatedFields: populated,
		TotalFields:     len(checks),
	}
}

// shannonEntropy returns the Shannon entropy of s in bits per character.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int, 64)
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, count := range freq {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

// round rounds f to decimalPlaces decimal places.
func round(f float64, decimalPlaces int) float64 {
	pow := math.Pow(10, float64(decimalPlaces))
	return math.Round(f*pow) / pow
}

// Classify returns a human-readable label for an entropy Report.
func Classify(r Report) string {
	var notes []string

	switch {
	case r.StringEntropy < 2.0 && r.StringEntropy > 0:
		notes = append(notes, "unusually low string entropy (possible synthetic values)")
	case r.StringEntropy > 5.5:
		notes = append(notes, "unusually high string entropy (possible randomised values)")
	}

	switch {
	case r.FieldCoverage < 0.4:
		notes = append(notes, "sparse payload (fewer than 40% of expected fields populated)")
	case r.FieldCoverage >= 0.9:
		notes = append(notes, "dense payload (90%+ of expected fields populated)")
	}

	if len(notes) == 0 {
		return "entropy within normal range"
	}
	return strings.Join(notes, "; ")
}
