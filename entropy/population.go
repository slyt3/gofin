package entropy

import (
	"fmt"
	"math"
	"strings"

	"github.com/slyt/gofin/fingerprint"
)

// refPopSize is the reference browser population for uniqueness estimates.
// A fingerprint is considered unique when its entropy exceeds log2(refPopSize) ≈ 16.6 bits.
const refPopSize = 100_000

// RareBitsThreshold is the per-field entropy above which a value is considered rare.
// log2(8192) ≈ 13 means fewer than 1-in-8192 browsers share the same value.
const RareBitsThreshold = 13.0

// PopScore holds the entropy contribution of a single fingerprint field.
type PopScore struct {
	// Field is a human-readable field name (e.g. "screen_resolution").
	Field string `json:"field"`

	// Value is the observed field value formatted as a string.
	Value string `json:"value"`

	// Frequency is the estimated fraction of browsers that report this value.
	Frequency float64 `json:"frequency"`

	// Bits is -log2(Frequency) — the information content of this value.
	// 50% browsers → 1 bit. 0.001% browsers → ~17 bits.
	Bits float64 `json:"bits"`

	// Rare is true when Bits > RareBitsThreshold.
	Rare bool `json:"rare"`
}

// PopReport is what MeasurePopulation returns.
type PopReport struct {
	// Fields contains one PopScore per scored fingerprint field.
	Fields []PopScore `json:"fields"`

	// TotalBits is the sum of Bits across all scored fields. Higher = more unique.
	TotalBits float64 `json:"total_bits"`

	// EstimatedUnique is true when TotalBits ≥ log2(refPopSize), which suggests
	// this fingerprint is likely unique in the reference population.
	EstimatedUnique bool `json:"estimated_unique"`

	// ScoredFields is the number of fields that contributed to TotalBits.
	ScoredFields int `json:"scored_fields"`
}

// MeasurePopulation estimates how rare each field value is relative to the
// reference browser population.
//
// Frequency estimates come from public browser telemetry (Statcounter,
// HTTP Archive, AmIUnique.org). They're intentionally conservative.
func MeasurePopulation(fp *fingerprint.Fingerprint) PopReport {
	var scores []PopScore

	// add scores one field at a time.  freq must be in (0, 1]; values below
	// 1/refPopSize are clamped so Bits never exceeds log2(refPopSize).
	add := func(field, value string, freq float64) {
		if value == "" {
			return
		}
		const minFreq = 1.0 / refPopSize
		if freq <= 0 || freq < minFreq {
			freq = minFreq
		}
		bits := -math.Log2(freq)
		scores = append(scores, PopScore{
			Field:     field,
			Value:     value,
			Frequency: round(freq, 6),
			Bits:      round(bits, 4),
			Rare:      bits > RareBitsThreshold,
		})
	}

	if fp.UserAgent != "" {
		fam := uaBrowserFamily(fp.UserAgent)
		add("ua_browser_family", fam, popUAFamily[fam])
	}

	if fp.Platform != "" {
		freq, ok := popPlatform[fp.Platform]
		if !ok {
			freq = 0.005 // rare / unknown platform
		}
		add("platform", fp.Platform, freq)
	}

	if fp.ScreenWidth > 0 && fp.ScreenHeight > 0 {
		key := fmt.Sprintf("%dx%d", fp.ScreenWidth, fp.ScreenHeight)
		freq, ok := popResolution[key]
		if !ok {
			freq = 0.003 // uncommon resolution
		}
		add("screen_resolution", key, freq)
	}

	if fp.ColorDepth > 0 {
		freq, ok := popColorDepth[fp.ColorDepth]
		if !ok {
			freq = 0.002
		}
		add("color_depth", fmt.Sprintf("%d", fp.ColorDepth), freq)
	}

	if fp.PixelRatio > 0 {
		key := fmt.Sprintf("%.3g", fp.PixelRatio) // "1", "1.5", "1.25", "2", "3" …
		freq, ok := popPixelRatio[key]
		if !ok {
			freq = 0.01
		}
		add("pixel_ratio", key, freq)
	}

	if fp.HardwareConcurrency > 0 {
		freq, ok := popHWConcurrency[fp.HardwareConcurrency]
		if !ok {
			freq = 0.005
		}
		add("hardware_concurrency", fmt.Sprintf("%d", fp.HardwareConcurrency), freq)
	}

	// DeviceMemory API reports discrete buckets: 0.25, 0.5, 1, 2, 4, 8, 16 GiB.
	if fp.DeviceMemory > 0 {
		key := fmt.Sprintf("%.3g", fp.DeviceMemory) // "0.25", "0.5", "1", "8" …
		freq, ok := popDeviceMemory[key]
		if !ok {
			freq = 0.01
		}
		add("device_memory_gib", key, freq)
	}

	if fp.Language != "" {
		freq, ok := popLanguage[strings.ToLower(fp.Language)]
		if !ok {
			freq = 0.004
		}
		add("language", fp.Language, freq)
	}

	if fp.Timezone != "" {
		freq, ok := popTimezone[fp.Timezone]
		if !ok {
			freq = 0.003
		}
		add("timezone", fp.Timezone, freq)
	}

	// Only scored when we have evidence the JS probe ran (UserAgent present).
	if fp.UserAgent != "" {
		if fp.MaxTouchPoints > 0 || fp.TouchSupport {
			add("touch_support", "yes", 0.32)
		} else {
			add("touch_support", "no", 0.68)
		}
	}

	// Only scored when at least one font was detected (probe clearly ran).
	if len(fp.Fonts) > 0 {
		bucket, freq := popFontBucket(len(fp.Fonts))
		add("fonts_count_range", bucket, freq)
	}

	// Only scored when we have evidence the JS probe ran.
	if fp.UserAgent != "" {
		bucket, freq := popPluginsBucket(len(fp.Plugins))
		add("plugins_count_range", bucket, freq)
	}

	var total float64
	for _, s := range scores {
		total += s.Bits
	}

	uniqueThreshold := math.Log2(refPopSize) // ≈ 16.6 bits

	return PopReport{
		Fields:          scores,
		TotalBits:       round(total, 4),
		EstimatedUnique: total >= uniqueThreshold,
		ScoredFields:    len(scores),
	}
}

// ClassifyPop returns a human-readable label for a PopReport.
func ClassifyPop(r PopReport) string {
	switch {
	case r.TotalBits < 8:
		return "low uniqueness — fingerprint matches many common browser profiles"
	case r.TotalBits < 16:
		return "moderate uniqueness — distinguishable within a large population"
	case r.EstimatedUnique:
		return "high uniqueness — likely unique within the reference population"
	default:
		return "high uniqueness — rare signal combination detected"
	}
}

// All values are approximate fractions of the global browser population.
// Sources: Statcounter GlobalStats, HTTP Archive, AmIUnique.org (2024).

// uaBrowserFamily extracts a coarse browser family name from a User-Agent string.
func uaBrowserFamily(ua string) string {
	lower := strings.ToLower(ua)
	switch {
	case strings.Contains(lower, "edg/") || strings.Contains(lower, "edge/"):
		return "Edge"
	case strings.Contains(lower, "opr/") || strings.Contains(lower, "opera"):
		return "Opera"
	case strings.Contains(lower, "brave"):
		return "Brave"
	case strings.Contains(lower, "firefox"):
		return "Firefox"
	case strings.Contains(lower, "safari") && !strings.Contains(lower, "chrome"):
		return "Safari"
	case strings.Contains(lower, "chrome") || strings.Contains(lower, "chromium"):
		return "Chrome"
	default:
		return "Other"
	}
}

var popUAFamily = map[string]float64{
	"Chrome":  0.65,
	"Firefox": 0.10,
	"Safari":  0.18,
	"Edge":    0.04,
	"Opera":   0.01,
	"Brave":   0.01,
	"Other":   0.01,
}

var popPlatform = map[string]float64{
	"Win32":         0.65,
	"MacIntel":      0.22,
	"Linux x86_64":  0.05,
	"iPhone":        0.04,
	"iPad":          0.01,
	"Linux armv8l":  0.005,
	"Linux aarch64": 0.005,
	"MacPPC":        0.001,
	"Win64":         0.002,
}

var popResolution = map[string]float64{
	"1920x1080": 0.25,
	"1536x864":  0.13,
	"1366x768":  0.10,
	"1440x900":  0.07,
	"1600x900":  0.03,
	"1280x800":  0.02,
	"1280x1024": 0.02,
	"1280x720":  0.04,
	"1920x1200": 0.03,
	"2560x1440": 0.06,
	"2560x1600": 0.02,
	"3840x2160": 0.02,
	"2880x1800": 0.01,
	"2048x1152": 0.01,
	"1680x1050": 0.02,
	"1360x768":  0.01,
	"1024x768":  0.01,
	"1400x1050": 0.005,
}

var popColorDepth = map[int]float64{
	24: 0.97,
	32: 0.02,
	16: 0.005,
	8:  0.002,
}

// popPixelRatio keys use fmt.Sprintf("%.3g", value):
//
//	1.0 → "1", 1.25 → "1.25", 1.5 → "1.5", 2.0 → "2", 3.0 → "3"
var popPixelRatio = map[string]float64{
	"1":    0.48,
	"2":    0.35,
	"1.5":  0.06,
	"1.25": 0.04,
	"3":    0.05,
	"1.75": 0.01,
	"2.5":  0.005,
	"4":    0.002,
}

var popHWConcurrency = map[int]float64{
	1:  0.005,
	2:  0.05,
	4:  0.28,
	6:  0.08,
	8:  0.32,
	10: 0.04,
	12: 0.08,
	14: 0.02,
	16: 0.08,
	20: 0.01,
	24: 0.01,
	32: 0.005,
}

// popDeviceMemory keys use fmt.Sprintf("%.3g", value):
//
//	0.25 → "0.25", 0.5 → "0.5", 1 → "1", 8 → "8", 16 → "16"
var popDeviceMemory = map[string]float64{
	"0.25": 0.005,
	"0.5":  0.01,
	"1":    0.04,
	"2":    0.12,
	"4":    0.28,
	"8":    0.40,
	"16":   0.10,
	"32":   0.025,
}

var popLanguage = map[string]float64{
	"en-us": 0.43,
	"en-gb": 0.08,
	"zh-cn": 0.06,
	"de-de": 0.05,
	"fr-fr": 0.04,
	"es-es": 0.03,
	"ja":    0.03,
	"pt-br": 0.03,
	"ru":    0.03,
	"ko":    0.02,
	"it":    0.02,
	"pl":    0.01,
	"nl":    0.01,
	"tr":    0.01,
	"sv":    0.005,
	"da":    0.005,
	"fi":    0.004,
	"nb":    0.004,
	"cs":    0.004,
	"hu":    0.003,
	"ro":    0.003,
	"el":    0.003,
	"uk":    0.003,
	"he":    0.003,
	"ar":    0.005,
	"th":    0.003,
	"vi":    0.003,
	"id":    0.004,
	"ms":    0.003,
	"en":    0.02,
	"zh":    0.02,
	"de":    0.02,
	"fr":    0.015,
	"es":    0.015,
	"pt":    0.01,
}

var popTimezone = map[string]float64{
	"America/New_York":     0.14,
	"America/Chicago":      0.06,
	"America/Denver":       0.02,
	"America/Los_Angeles":  0.10,
	"America/Toronto":      0.03,
	"America/Vancouver":    0.01,
	"America/Sao_Paulo":    0.03,
	"America/Mexico_City":  0.02,
	"America/Bogota":       0.01,
	"America/Lima":         0.01,
	"America/Buenos_Aires": 0.01,
	"America/Santiago":     0.005,
	"America/Caracas":      0.003,
	"America/Montevideo":   0.003,
	"Europe/London":        0.08,
	"Europe/Paris":         0.05,
	"Europe/Berlin":        0.04,
	"Europe/Rome":          0.02,
	"Europe/Madrid":        0.02,
	"Europe/Warsaw":        0.01,
	"Europe/Moscow":        0.04,
	"Europe/Istanbul":      0.02,
	"Europe/Kyiv":          0.01,
	"Europe/Amsterdam":     0.01,
	"Europe/Stockholm":     0.01,
	"Europe/Vienna":        0.01,
	"Europe/Zurich":        0.005,
	"Europe/Prague":        0.005,
	"Europe/Athens":        0.005,
	"Europe/Helsinki":      0.005,
	"Europe/Lisbon":        0.005,
	"Europe/Dublin":        0.005,
	"Europe/Bucharest":     0.004,
	"Europe/Sofia":         0.003,
	"Europe/Belgrade":      0.003,
	"Asia/Tokyo":           0.04,
	"Asia/Shanghai":        0.06,
	"Asia/Kolkata":         0.05,
	"Asia/Seoul":           0.02,
	"Asia/Jakarta":         0.02,
	"Asia/Singapore":       0.01,
	"Asia/Hong_Kong":       0.01,
	"Asia/Bangkok":         0.01,
	"Asia/Taipei":          0.01,
	"Asia/Karachi":         0.01,
	"Asia/Dubai":           0.01,
	"Asia/Riyadh":          0.01,
	"Asia/Tehran":          0.005,
	"Asia/Dhaka":           0.005,
	"Asia/Ho_Chi_Minh":     0.003,
	"Asia/Manila":          0.005,
	"Asia/Kuala_Lumpur":    0.005,
	"Asia/Colombo":         0.003,
	"Asia/Kathmandu":       0.003,
	"Asia/Tashkent":        0.003,
	"Asia/Almaty":          0.003,
	"Australia/Sydney":     0.02,
	"Australia/Melbourne":  0.01,
	"Australia/Brisbane":   0.005,
	"Australia/Perth":      0.005,
	"Pacific/Auckland":     0.005,
	"Pacific/Honolulu":     0.003,
	"Africa/Cairo":         0.005,
	"Africa/Lagos":         0.005,
	"Africa/Nairobi":       0.003,
	"Africa/Johannesburg":  0.004,
	"Africa/Casablanca":    0.003,
}

func popFontBucket(n int) (string, float64) {
	switch {
	case n <= 20:
		return "1–20", 0.05
	case n <= 50:
		return "21–50", 0.15
	case n <= 100:
		return "51–100", 0.30
	case n <= 150:
		return "101–150", 0.25
	default:
		return "150+", 0.17
	}
}

func popPluginsBucket(n int) (string, float64) {
	switch {
	case n == 0:
		return "0", 0.40
	case n <= 3:
		return "1–3", 0.35
	case n <= 10:
		return "4–10", 0.20
	default:
		return "10+", 0.05
	}
}
