package risk

import (
	"fmt"
	"strings"

	"github.com/slyt3/gofin/fingerprint"
)

// geoMismatchRule fires when the browser's IANA timezone doesn't match
// the country we see from the IP.
type geoMismatchRule struct{}

// GeoMismatchRule returns a ready-to-use Rule for timezone/country mismatch.
// Weight is 0.75 because geo-IP data is pretty reliable.
func GeoMismatchRule() Rule {
	return geoMismatchRule{}
}

func (geoMismatchRule) Name() string     { return "geo_tz_mismatch" }
func (geoMismatchRule) Category() string { return string(CategorySpoofing) }
func (geoMismatchRule) Weight() float64  { return 0.75 }

// Evaluate checks if the browser's reported timezone makes sense for the
// country we got from the IP.
func (geoMismatchRule) Evaluate(p *fingerprint.Payload) SignalResult {
	name := "geo_tz_mismatch"

	if p.Browser == nil || p.Network == nil {
		return SignalResult{Name: name}
	}

	tz := strings.TrimSpace(p.Browser.Timezone)
	country := strings.ToUpper(strings.TrimSpace(p.Network.Country))

	if tz == "" || country == "" {
		return SignalResult{Name: name}
	}

	// pull the continent/region prefix out of the IANA timezone name.
	prefix := tzPrefix(tz)
	if prefix == "" {
		// no prefix means we can't classify it, so don't flag it.
		return SignalResult{Name: name}
	}

	allowed, ok := tzCountryMap[prefix]
	if !ok {
		return SignalResult{Name: name}
	}

	for _, c := range allowed {
		if c == country {
			return SignalResult{Name: name}
		}
	}

	return SignalResult{
		Name:      name,
		Triggered: true,
		Reason: fmt.Sprintf(
			"timezone prefix %q is not associated with country %q",
			prefix, country,
		),
	}
}

// tzPrefix pulls the first path segment from an IANA timezone string.
// "America/New_York" → "America", "Europe/London" → "Europe".
func tzPrefix(tz string) string {
	if i := strings.IndexByte(tz, '/'); i > 0 {
		return tz[:i]
	}
	return ""
}

// tzCountryMap maps IANA timezone prefixes to the ISO country codes that
// are plausible for that region. Deliberately broad to avoid false positives.
var tzCountryMap = map[string][]string{
	"America": {
		"US", "CA", "MX", "BR", "AR", "CL", "CO", "PE", "VE", "EC",
		"BO", "PY", "UY", "SR", "GY", "GF", "PA", "CR", "NI", "HN",
		"GT", "BZ", "SV", "CU", "JM", "HT", "DO", "PR", "TT", "BB",
		"LC", "VC", "GD", "AG", "DM", "KN", "AI", "AW", "BQ", "CW",
		"SX", "VG", "VI", "TC", "BS", "KY", "MS", "GP", "MQ", "MF",
		"BL", "PM", "GL", "FK",
	},
	"Europe": {
		"GB", "FR", "DE", "ES", "IT", "NL", "BE", "CH", "AT", "SE",
		"NO", "DK", "FI", "PL", "CZ", "SK", "HU", "RO", "BG", "HR",
		"SI", "RS", "BA", "ME", "MK", "AL", "GR", "PT", "IE", "LU",
		"LT", "LV", "EE", "BY", "UA", "MD", "RU", "IS", "MT", "CY",
		"TR", "GE", "AM", "AZ", "AD", "MC", "SM", "VA", "LI", "XK",
	},
	"Asia": {
		"CN", "JP", "KR", "IN", "ID", "TH", "VN", "MY", "PH", "SG",
		"HK", "TW", "MO", "PK", "BD", "LK", "NP", "MM", "KH", "LA",
		"BT", "MV", "AF", "IR", "IQ", "SA", "AE", "QA", "KW", "BH",
		"OM", "YE", "JO", "LB", "SY", "IL", "PS", "KZ", "UZ", "TM",
		"TJ", "KG", "MN", "RU",
	},
	"Africa": {
		"NG", "ET", "EG", "DZ", "ZA", "KE", "TZ", "GH", "MZ", "MG",
		"AO", "CM", "CI", "NE", "BF", "ML", "MW", "ZM", "ZW", "SO",
		"SN", "TD", "GN", "RW", "BI", "SS", "SL", "TG", "BJ", "ER",
		"LY", "MA", "TN", "SD", "MR", "LR", "CF", "CG", "CD", "GA",
		"GQ", "ST", "CV", "GM", "GW", "MU", "SC", "KM", "DJ", "NA",
		"BW", "LS", "SZ", "RE", "YT",
	},
	"Pacific": {
		"AU", "NZ", "PG", "FJ", "SB", "VU", "WS", "TO", "KI", "FM",
		"PW", "MH", "NR", "TV", "CK", "NU", "WF", "AS", "GU", "MP",
		"PF", "NC", "TK", "PN",
	},
	"Australia": {"AU"},
	"Indian":    {"IN", "MU", "MV", "SC", "RE", "YT", "TF"},
	"Atlantic":  {"IS", "PT", "CV", "GL", "FK", "SH", "GS", "AW", "BQ", "CW", "SX"},
	"Arctic":    {"NO"},
	// Antarctica timezones (e.g. Antarctica/McMurdo) are deliberately omitted.
	// International research stations cannot be reliably associated with a
	// single country, so the rule never fires for the Antarctica prefix.
}
