package ja3_test

import (
	"testing"

	"github.com/slyt/gofin/pkg/ja3"
)

// TestJA3StringRoundTrip verifies ParseJA3String → BuildString is stable.
func TestJA3StringRoundTrip(t *testing.T) {
	raw := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
	ch, err := ja3.ParseJA3String(raw)
	if err != nil {
		t.Fatalf("ParseJA3String: %v", err)
	}
	rebuilt := ja3.BuildString(ch)
	if rebuilt != raw {
		t.Errorf("round-trip mismatch:\n  want: %s\n   got: %s", raw, rebuilt)
	}
	hash := ja3.Hash(ch)
	t.Logf("Hash: %s", hash)
}

// TestNameLookups exercises CipherName / ExtensionName / CurveName.
func TestNameLookups(t *testing.T) {
	tests := []struct {
		fn   func(uint16) string
		id   uint16
		want string
	}{
		{ja3.CipherName, 0x1301, "TLS_AES_128_GCM_SHA256"},
		{ja3.CipherName, 0xDEAD, "unknown(0xdead)"},
		{ja3.ExtensionName, 0, "server_name (SNI)"},
		{ja3.ExtensionName, 65281, "renegotiation_info"},
		{ja3.CurveName, 29, "x25519"},
		{ja3.CurveName, 23, "secp256r1 (P-256)"},
		{ja3.CurveName, 9999, "unknown(0x270f)"},
	}
	for _, tc := range tests {
		got := tc.fn(tc.id)
		if got != tc.want {
			t.Errorf("id=%d: want %q, got %q", tc.id, tc.want, got)
		}
	}
}

// TestParseRawClientHello verifies the binary parser against a hand-crafted body.
func TestParseRawClientHello(t *testing.T) {
	// Hand-crafted minimal ClientHello body:
	//   legacy_version = 0x0303 (TLS 1.2)
	//   random         = 32 zero bytes
	//   session_id_len = 0
	//   cipher_suites  = [0x1301]  (TLS_AES_128_GCM_SHA256)
	//   compression    = [0x00]
	//   extensions_len = 0
	body := []byte{
		0x03, 0x03, // legacy_version
	}
	body = append(body, make([]byte, 32)...) // random
	body = append(body,
		0x00,       // session_id_len
		0x00, 0x02, // cipher_suites_len = 2
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x01, 0x00, // compression_methods: len=1, value=0x00
		0x00, 0x00, // extensions_len = 0
	)

	ch, err := ja3.ParseRawClientHello(body)
	if err != nil {
		t.Fatalf("ParseRawClientHello: %v", err)
	}
	if ch.SSLVersion != 0x0303 {
		t.Errorf("SSLVersion: want 0x0303, got 0x%04x", ch.SSLVersion)
	}
	if len(ch.Ciphers) != 1 || ch.Ciphers[0] != 0x1301 {
		t.Errorf("Ciphers: want [0x1301], got %v", ch.Ciphers)
	}
	if len(ch.Extensions) != 0 {
		t.Errorf("Extensions: want [], got %v", ch.Extensions)
	}

	hash := ja3.Hash(ch)
	t.Logf("Hash: %s", hash)
}

// TestParseRawClientHelloWithHandshakeHeader tests the Handshake layer stripping.
func TestParseRawClientHelloWithHandshakeHeader(t *testing.T) {
	inner := []byte{
		0x03, 0x03,
	}
	inner = append(inner, make([]byte, 32)...)
	inner = append(inner,
		0x00,
		0x00, 0x02,
		0x13, 0x01,
		0x01, 0x00,
		0x00, 0x00,
	)

	// Wrap in Handshake header: type=0x01, length=3 bytes (big-endian)
	hsLen := len(inner)
	wrapped := []byte{
		0x01,                                             // ClientHello type
		byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen), // 24-bit length
	}
	wrapped = append(wrapped, inner...)

	ch, err := ja3.ParseRawClientHello(wrapped)
	if err != nil {
		t.Fatalf("ParseRawClientHello (handshake wrapped): %v", err)
	}
	if ch.SSLVersion != 0x0303 {
		t.Errorf("SSLVersion: want 0x0303, got 0x%04x", ch.SSLVersion)
	}
}

// TestExplain ensures Explain runs without panicking and returns non-empty output.
func TestExplain(t *testing.T) {
	raw := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
	ch, _ := ja3.ParseJA3String(raw)
	out := ja3.Explain(ch)
	if len(out) == 0 {
		t.Error("Explain returned empty string")
	}
	t.Logf("Explain output:\n%s", out)
}

// TestCheckConsistency spot-checks the three logic branches.
func TestCheckConsistency(t *testing.T) {
	// Unknown hash → assume-innocent (Consistent=true, low confidence 0.40).
	unknownHash := "00000000000000000000000000000000" // not in any table
	res := ja3.CheckConsistency(unknownHash, "Mozilla/5.0 (Windows NT 10.0) Chrome/120")
	if !res.Consistent {
		t.Error("unknown hash should default to Consistent=true (assume innocent)")
	}
	if res.Confidence > 0.5 {
		t.Errorf("unknown hash confidence should be low, got %.2f", res.Confidence)
	}

	// Lookup a known bot entry, then pass a browser UA
	bots := ja3.AllKnown()
	if len(bots) > 0 {
		res2 := ja3.CheckConsistency(bots[0].Hash, "Mozilla/5.0 Chrome/120")
		// Bot hash with browser-like UA should be flagged inconsistent
		if res2.Consistent {
			t.Errorf("bot hash %q with browser UA should be inconsistent", bots[0].Hash)
		}
	}
}
