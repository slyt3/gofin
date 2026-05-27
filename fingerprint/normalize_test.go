package fingerprint_test

import (
	"errors"
	"testing"

	"github.com/slyt/gofin/fingerprint"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name    string
		input   *fingerprint.Payload
		wantErr error
		check   func(t *testing.T, p *fingerprint.Payload)
	}{
		{
			name:    "nil payload returns ErrEmptyPayload",
			input:   nil,
			wantErr: fingerprint.ErrEmptyPayload,
		},
		{
			name:    "all-nil sub-structs returns ErrEmptyPayload",
			input:   &fingerprint.Payload{},
			wantErr: fingerprint.ErrEmptyPayload,
		},
		{
			name: "browser-only: strings trimmed, language lowercased",
			input: &fingerprint.Payload{
				Browser: &fingerprint.BrowserFingerprint{
					UserAgent: "  Mozilla/5.0  ",
					Language:  "  EN-US  ",
					Languages: []string{"  EN-US  ", "  FR  "},
				},
			},
			check: func(t *testing.T, p *fingerprint.Payload) {
				if got := p.Browser.UserAgent; got != "Mozilla/5.0" {
					t.Errorf("UserAgent: want %q, got %q", "Mozilla/5.0", got)
				}
				if got := p.Browser.Language; got != "en-us" {
					t.Errorf("Language: want %q, got %q", "en-us", got)
				}
				if got := p.Browser.Languages[1]; got != "fr" {
					t.Errorf("Languages[1]: want %q, got %q", "fr", got)
				}
			},
		},
		{
			name: "full payload: country uppercased, JA3 hash lowercased",
			input: &fingerprint.Payload{
				Browser: &fingerprint.BrowserFingerprint{UserAgent: "Chrome"},
				TLS:     &fingerprint.TLSFingerprint{JA3Hash: "  ABC123  "},
				Network: &fingerprint.NetworkSignals{Country: "  us  "},
			},
			check: func(t *testing.T, p *fingerprint.Payload) {
				if got := p.TLS.JA3Hash; got != "abc123" {
					t.Errorf("JA3Hash: want %q, got %q", "abc123", got)
				}
				if got := p.Network.Country; got != "US" {
					t.Errorf("Country: want %q, got %q", "US", got)
				}
			},
		},
		{
			name: "malformed user agent (excess whitespace) is trimmed without error",
			input: &fingerprint.Payload{
				Browser: &fingerprint.BrowserFingerprint{
					UserAgent: "\t  Mozilla/5.0 (compatible; Googlebot/2.1)  \n",
				},
			},
			check: func(t *testing.T, p *fingerprint.Payload) {
				want := "Mozilla/5.0 (compatible; Googlebot/2.1)"
				if got := p.Browser.UserAgent; got != want {
					t.Errorf("UserAgent: want %q, got %q", want, got)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := fingerprint.Normalize(tc.input)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error: want %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
}
