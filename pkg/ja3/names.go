package ja3

import "fmt"

// CipherName returns the IANA name for a TLS cipher suite ID, or a
// formatted fallback string for unknown IDs.
func CipherName(id uint16) string {
	if name, ok := cipherNames[id]; ok {
		return name
	}
	return fmt.Sprintf("unknown(0x%04x)", id)
}

// ExtensionName returns the IANA name for a TLS extension type ID.
func ExtensionName(id uint16) string {
	if name, ok := extensionNames[id]; ok {
		return name
	}
	return fmt.Sprintf("unknown(0x%04x)", id)
}

// CurveName returns the IANA name for a TLS supported group (named curve) ID.
func CurveName(id uint16) string {
	if name, ok := curveNames[id]; ok {
		return name
	}
	return fmt.Sprintf("unknown(0x%04x)", id)
}

// Source: IANA TLS Cipher Suite Registry + RFC 8446 (TLS 1.3)

var cipherNames = map[uint16]string{
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0x1304: "TLS_AES_128_CCM_SHA256",
	0x1305: "TLS_AES_128_CCM_8_SHA256",

	0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",

	0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",

	0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",

	0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
	0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x003B: "TLS_RSA_WITH_NULL_SHA256",

	0x0004: "TLS_RSA_WITH_RC4_128_MD5",
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x000D: "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
	0x0010: "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
	0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
	0x0000: "TLS_NULL_WITH_NULL_NULL",

	0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
	0x5600: "TLS_FALLBACK_SCSV",
}

// Source: IANA TLS ExtensionType Values registry

var extensionNames = map[uint16]string{
	0:     "server_name (SNI)",
	1:     "max_fragment_length",
	2:     "client_certificate_url",
	3:     "trusted_ca_keys",
	4:     "truncated_hmac",
	5:     "status_request (OCSP stapling)",
	6:     "user_mapping",
	7:     "client_authz",
	8:     "server_authz",
	9:     "cert_type",
	10:    "supported_groups (elliptic_curves)",
	11:    "ec_point_formats",
	12:    "srp",
	13:    "signature_algorithms",
	14:    "use_srtp",
	15:    "heartbeat",
	16:    "application_layer_protocol_negotiation (ALPN)",
	17:    "status_request_v2",
	18:    "signed_certificate_timestamp (SCT)",
	19:    "client_certificate_type",
	20:    "server_certificate_type",
	21:    "padding",
	22:    "encrypt_then_mac",
	23:    "session_ticket",
	24:    "TLMSP",
	25:    "TLMSP_proxying",
	26:    "TLMSP_delegate",
	27:    "compress_certificate",
	28:    "record_size_limit",
	29:    "pwd_protect",
	30:    "pwd_clear",
	31:    "password_salt",
	32:    "ticket_pinning",
	33:    "tls_cert_with_extern_psk",
	34:    "delegated_credential",
	35:    "session_ticket (RFC 5077)",
	36:    "TLMSP",
	41:    "pre_shared_key",
	42:    "early_data",
	43:    "supported_versions",
	44:    "cookie",
	45:    "psk_key_exchange_modes",
	47:    "certificate_authorities",
	48:    "oid_filters",
	49:    "post_handshake_auth",
	50:    "signature_algorithms_cert",
	51:    "key_share",
	52:    "transparency_info",
	53:    "connection_id (deprecated)",
	54:    "connection_id",
	55:    "external_id_hash",
	56:    "external_session_id",
	57:    "quic_transport_parameters",
	58:    "ticket_request",
	59:    "dnssec_chain",
	60:    "sequence_number_encryption_algorithms",
	17513: "application_settings (ALPS)",
	65281: "renegotiation_info",
}

// Source: IANA TLS Supported Groups registry

var curveNames = map[uint16]string{
	19: "secp192r1",
	21: "secp224r1",
	23: "secp256r1 (P-256)",
	24: "secp384r1 (P-384)",
	25: "secp521r1 (P-521)",

	18: "secp192k1",
	20: "secp224k1",
	22: "secp256k1",

	29: "x25519",
	30: "x448",

	26: "brainpoolP256r1",
	27: "brainpoolP384r1",
	28: "brainpoolP512r1",

	256:   "ffdhe2048",
	257:   "ffdhe3072",
	258:   "ffdhe4096",
	259:   "ffdhe6144",
	260:   "ffdhe8192",
	65281: "arbitrary_explicit_prime_curves",
	65282: "arbitrary_explicit_char2_curves",
}
