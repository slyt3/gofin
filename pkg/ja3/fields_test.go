package ja3_test

import (
	"testing"

	"github.com/slyt3/gofin/pkg/ja3"
)

// TestCompute verifies that Compute(Fields) produces the correct JA3 raw
// string and MD5 hash.
func TestCompute(t *testing.T) {
	// The raw string from the existing round-trip test; we know the expected hash.
	raw := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"

	// Parse the string to build a Fields value from known data.
	ch, err := ja3.ParseJA3String(raw)
	if err != nil {
		t.Fatalf("ParseJA3String: %v", err)
	}

	f := ja3.Fields{
		Version:    ch.SSLVersion,
		Ciphers:    ch.Ciphers,
		Extensions: ch.Extensions,
		Curves:     ch.EllipticCurves,
		PointFmts:  ch.EllipticCurveFormats,
	}

	gotRaw, gotHash := ja3.Compute(f)

	if gotRaw != raw {
		t.Errorf("raw string mismatch:\n  want: %s\n   got: %s", raw, gotRaw)
	}

	// Cross-check: Hash() of the same ParsedClientHello must match.
	wantHash := ja3.Hash(ch)
	if gotHash != wantHash {
		t.Errorf("hash mismatch: want %s, got %s", wantHash, gotHash)
	}
}

// TestMatch verifies the browser lookup helper.
func TestMatch(t *testing.T) {
	tests := []struct {
		name        string
		hash        string
		wantBrowser string
		wantOK      bool
	}{
		{
			name:        "known Chrome 120 hash",
			hash:        "8aa30e7d9bd94e0dbe9ab98b4dd46bd4",
			wantBrowser: "Chrome 120",
			wantOK:      true,
		},
		{
			name:        "known Chrome hash with extra whitespace",
			hash:        "  8aa30e7d9bd94e0dbe9ab98b4dd46bd4  ",
			wantBrowser: "Chrome 120",
			wantOK:      true,
		},
		{
			name:        "known Firefox 121 hash",
			hash:        "336212b7e2f40ba9c9eba5c87882461d",
			wantBrowser: "Firefox 121",
			wantOK:      true,
		},
		{
			name:   "unknown hash returns false",
			hash:   "00000000000000000000000000000000",
			wantOK: false,
		},
		{
			name:   "empty hash returns false",
			hash:   "",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			browser, ok := ja3.Match(tc.hash)
			if ok != tc.wantOK {
				t.Fatalf("ok: want %v, got %v", tc.wantOK, ok)
			}
			if tc.wantOK && browser != tc.wantBrowser {
				t.Errorf("browser: want %q, got %q", tc.wantBrowser, browser)
			}
		})
	}
}
