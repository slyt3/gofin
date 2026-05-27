// Command basic demonstrates the full gofin analysis pipeline.
//
// It accepts a JSON fingerprint on stdin (or uses a built-in bot fixture) and
// prints the risk score, category breakdown, and explanation to stdout.
//
// Usage:
//
//	go run ./examples/basic                        # uses bundled bot fixture
//	echo '{"user_agent":"..."}' | go run ./examples/basic
//	cat my_payload.json | go run ./examples/basic
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/slyt/gofin"
	"github.com/slyt/gofin/entropy"
	"github.com/slyt/gofin/fingerprint"
)

func main() {
	data := readInput()

	result, err := gofin.AnalyzeJSON(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(result.Explanation)

	if len(result.Categories) > 0 {
		fmt.Println("Category scores:")
		for cat, score := range result.Categories {
			fmt.Printf("  %-14s %d\n", cat, score)
		}
		fmt.Println()
	}

	fp, _ := fingerprint.Parse(data)
	if fp != nil {
		er := entropy.Measure(fp)
		fmt.Printf(
			"Entropy: %.4f bits/char | Field coverage: %.0f%% (%d/%d fields)\n",
			er.StringEntropy,
			er.FieldCoverage*100,
			er.PopulatedFields,
			er.TotalFields,
		)
		fmt.Println("Entropy classification:", entropy.Classify(er))
		fmt.Println()
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "json encode: %v\n", err)
		os.Exit(1)
	}
}

// readInput reads from stdin if data is piped, otherwise returns the built-in
// bot fixture so the example is runnable without any arguments.
func readInput() []byte {
	info, _ := os.Stdin.Stat()
	if (info.Mode() & os.ModeCharDevice) == 0 {
		// Data is being piped in.
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read stdin: %v\n", err)
			os.Exit(1)
		}
		return raw
	}
	return botFixture
}

// botFixture is a synthetic fingerprint that represents a headless-Chrome bot
// running in a CI/CD pipeline.  It deliberately triggers several high-weight
// signals so the example output is illustrative.
var botFixture = []byte(`{
  "user_agent":             "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
  "platform":               "Linux x86_64",
  "screen_width":           0,
  "screen_height":          0,
  "color_depth":            24,
  "pixel_ratio":            1,
  "viewport_width":         1280,
  "viewport_height":        720,
  "timezone":               "America/New_York",
  "timezone_offset":        0,
  "language":               "en-US",
  "languages":              ["en-US", "en"],
  "hardware_concurrency":   0,
  "device_memory":          0,
  "ip":                     "203.0.113.42",
  "ip_country":             "US",
  "ip_timezone":            "America/New_York",
  "canvas_hash":            "",
  "webgl_hash":             "",
  "webgl_vendor":           "Google Inc. (Google)",
  "webgl_renderer":         "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader)",
  "audio_hash":             "",
  "fonts":                  [],
  "plugins":                [],
  "touch_support":          false,
  "max_touch_points":       0,
  "cookie_enabled":         true,
  "do_not_track":           "unspecified",
  "webdriver":              true,
  "headless_mode":          true,
  "phantom_js":             false,
  "selenium":               false,
  "ja3_hash":               "cd08e31494f9531f560d64c695473da9",
  "accept_language":        "en-US,en;q=0.9",
  "accept_encoding":        "gzip, deflate, br"
}`)
