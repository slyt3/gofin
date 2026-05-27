package risk_test

import (
	"testing"

	"github.com/slyt/gofin/fingerprint"
	"github.com/slyt/gofin/risk"
)

func TestGeoMismatchRule(t *testing.T) {
	rule := risk.GeoMismatchRule()

	tests := []struct {
		name      string
		payload   *fingerprint.Payload
		triggered bool
	}{
		{
			name: "match: US timezone with US country",
			payload: &fingerprint.Payload{
				Browser: &fingerprint.BrowserFingerprint{Timezone: "America/New_York"},
				Network: &fingerprint.NetworkSignals{Country: "US"},
			},
			triggered: false,
		},
		{
			name: "mismatch: America timezone with CN country",
			payload: &fingerprint.Payload{
				Browser: &fingerprint.BrowserFingerprint{Timezone: "America/New_York"},
				Network: &fingerprint.NetworkSignals{Country: "CN"},
			},
			triggered: true,
		},
		{
			name: "nil browser: rule does not fire",
			payload: &fingerprint.Payload{
				Network: &fingerprint.NetworkSignals{Country: "US"},
			},
			triggered: false,
		},
		{
			name: "nil network: rule does not fire",
			payload: &fingerprint.Payload{
				Browser: &fingerprint.BrowserFingerprint{Timezone: "America/New_York"},
			},
			triggered: false,
		},
		{
			name: "unknown timezone prefix: rule does not fire",
			payload: &fingerprint.Payload{
				Browser: &fingerprint.BrowserFingerprint{Timezone: "Antarctica/McMurdo"},
				Network: &fingerprint.NetworkSignals{Country: "CN"},
			},
			triggered: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := rule.Evaluate(tc.payload)
			if result.Triggered != tc.triggered {
				t.Errorf("Triggered: want %v, got %v (reason: %q)",
					tc.triggered, result.Triggered, result.Reason)
			}
			if result.Name != "geo_tz_mismatch" {
				t.Errorf("Name: want %q, got %q", "geo_tz_mismatch", result.Name)
			}
		})
	}
}
