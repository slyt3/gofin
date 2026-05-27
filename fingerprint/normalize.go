package fingerprint

import (
	"errors"
	"strings"
)

// ErrEmptyPayload is returned by Normalize when all sub-struct pointers
// in the Payload are nil — i.e. the caller passed in nothing useful.
var ErrEmptyPayload = errors.New("fingerprint: payload has no data fields set")

// Normalize cleans up a Payload in-place before running it through the engine.
// It trims whitespace, lowercases language codes and JA3 hashes, and
// uppercases country codes. Returns ErrEmptyPayload if there's nothing there.
func Normalize(p *Payload) (*Payload, error) {
	if p == nil || (p.Browser == nil && p.TLS == nil && p.Network == nil && p.Behavior == nil) {
		return nil, ErrEmptyPayload
	}

	if b := p.Browser; b != nil {
		b.UserAgent = strings.TrimSpace(b.UserAgent)
		b.Platform = strings.TrimSpace(b.Platform)
		b.Language = strings.ToLower(strings.TrimSpace(b.Language))
		for i, l := range b.Languages {
			b.Languages[i] = strings.ToLower(strings.TrimSpace(l))
		}
		b.Timezone = strings.TrimSpace(b.Timezone)
		b.CanvasHash = strings.TrimSpace(b.CanvasHash)
		b.WebGLHash = strings.TrimSpace(b.WebGLHash)
		b.WebGLVendor = strings.TrimSpace(b.WebGLVendor)
		b.WebGLRenderer = strings.TrimSpace(b.WebGLRenderer)
		b.AudioHash = strings.TrimSpace(b.AudioHash)
		b.DoNotTrack = strings.TrimSpace(b.DoNotTrack)
	}

	if t := p.TLS; t != nil {
		t.JA3Hash = strings.ToLower(strings.TrimSpace(t.JA3Hash))
		t.JA3FullString = strings.TrimSpace(t.JA3FullString)
	}

	if n := p.Network; n != nil {
		n.IP = strings.TrimSpace(n.IP)
		n.Country = strings.ToUpper(strings.TrimSpace(n.Country))
		n.Region = strings.TrimSpace(n.Region)
		n.City = strings.TrimSpace(n.City)
		n.ASNOrg = strings.TrimSpace(n.ASNOrg)
		n.IPTimezone = strings.TrimSpace(n.IPTimezone)
	}

	return p, nil
}
