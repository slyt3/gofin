package ja3

import "strings"

// Fields holds the five JA3 inputs. Use this when you already have the TLS
// values parsed out and just want to compute the hash.
// Starting from raw TLS bytes? Use ParseRawClientHello instead.
type Fields struct {
	// Version is the legacy_version from the ClientHello. 771 = TLS 1.2.
	Version uint16

	// Ciphers is the cipher suite list in the order the client sent them.
	Ciphers []uint16

	// Extensions is the list of extension type IDs.
	Extensions []uint16

	// Curves is the supported_groups extension content.
	Curves []uint16

	// PointFmts is the ec_point_formats extension content.
	PointFmts []uint8
}

// Compute returns both the raw JA3 string and its MD5 hash.
// GREASE values (RFC 8701) are stripped automatically.
func Compute(f Fields) (rawString string, hash string) {
	ch := ParsedClientHello{
		SSLVersion:           f.Version,
		Ciphers:              f.Ciphers,
		Extensions:           f.Extensions,
		EllipticCurves:       f.Curves,
		EllipticCurveFormats: f.PointFmts,
	}
	rawString = BuildString(ch)
	hash = Hash(ch)
	return
}

// Match looks up a JA3 hash in the known browser table and returns the browser
// name and version if found (e.g. "Chrome 120", "Firefox 121").
func Match(hash string) (browser string, ok bool) {
	entry, found := LookupBrowser(strings.ToLower(strings.TrimSpace(hash)))
	if !found {
		return "", false
	}
	s := entry.Browser
	if entry.Version != "" {
		s += " " + entry.Version
	}
	return s, true
}
