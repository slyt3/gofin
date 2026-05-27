package explain_test

import (
	"strings"
	"testing"

	"github.com/slyt3/gofin/explain"
	"github.com/slyt3/gofin/risk"
)

func TestGenerate(t *testing.T) {
	tests := []struct {
		name           string
		score          risk.Score
		wantEmpty      bool
		wantSummaryPfx string
		wantSignalLen  int
		wantSugLen     int
	}{
		{
			name: "no signals triggered: empty Report",
			score: risk.Score{
				Total: 0,
				Level: risk.RiskLow,
				Signals: []risk.SignalResult{
					{Name: "webdriver", Triggered: false},
				},
			},
			wantEmpty: true,
		},
		{
			name: "single automation signal",
			score: risk.Score{
				Total: 0.35,
				Level: risk.RiskMedium,
				Signals: []risk.SignalResult{
					{
						Name:      "webdriver",
						Triggered: true,
						Reason:    "WebDriver flag is set",
					},
				},
			},
			wantSummaryPfx: "This request shows",
			wantSignalLen:  1,
			wantSugLen:     1,
		},
		{
			name: "multiple triggered signals produce capped suggestions",
			score: risk.Score{
				Total: 0.95,
				Level: risk.RiskCritical,
				Signals: []risk.SignalResult{
					{Name: "webdriver", Triggered: true, Reason: "WebDriver set"},
					{Name: "headless_mode", Triggered: true, Reason: "Headless mode set"},
					{Name: "phantomjs", Triggered: true, Reason: "PhantomJS detected"},
					{Name: "selenium", Triggered: true, Reason: "Selenium detected"},
				},
			},
			wantSummaryPfx: "This request is very likely",
			wantSignalLen:  4,
			wantSugLen:     3, // capped at 3
		},
		{
			name: "unknown signal name uses generic suggestion",
			score: risk.Score{
				Total: 0.6,
				Level: risk.RiskHigh,
				Signals: []risk.SignalResult{
					{
						Name:      "custom_rule_xyz",
						Triggered: true,
						Reason:    "custom condition fired",
					},
				},
			},
			wantSummaryPfx: "This request shows",
			wantSignalLen:  1,
			wantSugLen:     1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := explain.Generate(tc.score)

			if tc.wantEmpty {
				if got.Summary != "" || len(got.Signals) != 0 || len(got.Suggestions) != 0 {
					t.Errorf("expected empty Report, got %+v", got)
				}
				return
			}

			if tc.wantSummaryPfx != "" && !strings.HasPrefix(got.Summary, tc.wantSummaryPfx) {
				t.Errorf("Summary: want prefix %q, got %q", tc.wantSummaryPfx, got.Summary)
			}
			if len(got.Signals) != tc.wantSignalLen {
				t.Errorf("Signals len: want %d, got %d (%v)", tc.wantSignalLen, len(got.Signals), got.Signals)
			}
			if len(got.Suggestions) != tc.wantSugLen {
				t.Errorf("Suggestions len: want %d, got %d (%v)", tc.wantSugLen, len(got.Suggestions), got.Suggestions)
			}
		})
	}
}
