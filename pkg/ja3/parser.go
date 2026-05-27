package ja3

import "fmt"

// ParseRawClientHello parses a binary TLS ClientHello message and extracts
// the five fields required to compute a JA3 fingerprint.
//
// data may begin at any of the following layers; the parser auto-detects:
//
//   - TLS record layer   (starts with 0x16 = Handshake content type)
//   - TLS Handshake layer (starts with 0x01 = ClientHello handshake type)
//   - ClientHello body   (starts with the 2-byte legacy_version field)
//
// This function is intentionally lenient: it does not enforce TLS record
// boundaries beyond what is needed to locate the ClientHello body.
func ParseRawClientHello(data []byte) (ParsedClientHello, error) {
	if len(data) == 0 {
		return ParsedClientHello{}, fmt.Errorf("ja3: empty input")
	}

	r := &tlsReader{buf: data}

	// 1-byte content type 0x16, 2-byte version, 2-byte length
	if r.peek() == 0x16 {
		if err := r.skip(1); err != nil { // content type
			return ParsedClientHello{}, fmt.Errorf("ja3: record header: %w", err)
		}
		if err := r.skip(2); err != nil { // record version
			return ParsedClientHello{}, fmt.Errorf("ja3: record version: %w", err)
		}
		recLen, err := r.readUint16()
		if err != nil {
			return ParsedClientHello{}, fmt.Errorf("ja3: record length: %w", err)
		}
		// Clamp the remaining reader to the declared record payload.
		if int(recLen) > r.remaining() {
			return ParsedClientHello{}, fmt.Errorf(
				"ja3: record declares %d bytes but only %d remain", recLen, r.remaining())
		}
		r.buf = r.buf[:r.pos+int(recLen)]
	}

	// 1-byte type (0x01 = ClientHello), 3-byte length
	if r.peek() == 0x01 {
		if err := r.skip(1); err != nil { // handshake type
			return ParsedClientHello{}, fmt.Errorf("ja3: handshake type: %w", err)
		}
		hsLen, err := r.readUint24()
		if err != nil {
			return ParsedClientHello{}, fmt.Errorf("ja3: handshake length: %w", err)
		}
		if int(hsLen) > r.remaining() {
			return ParsedClientHello{}, fmt.Errorf(
				"ja3: handshake declares %d bytes but only %d remain", hsLen, r.remaining())
		}
		r.buf = r.buf[:r.pos+int(hsLen)]
	}

	return parseClientHelloBody(r)
}

// parseClientHelloBody reads a TLS ClientHello starting at legacy_version.
//
// ClientHello structure (RFC 8446 §4.1.2 / RFC 5246 §7.4.1.2):
//
//	struct {
//	    ProtocolVersion legacy_version;          // 2 bytes
//	    Random random;                           // 32 bytes
//	    opaque legacy_session_id<0..32>;         // 1-byte len + data
//	    CipherSuite cipher_suites<2..2^16-2>;    // 2-byte len + 2-byte entries
//	    opaque legacy_compression_methods<1..2^8-1>; // 1-byte len + data
//	    Extension extensions<8..2^16-1>;         // 2-byte len + extensions
//	} ClientHello;
func parseClientHelloBody(r *tlsReader) (ParsedClientHello, error) {
	// legacy_version  (2 bytes) — SSLVersion field in JA3
	version, err := r.readUint16()
	if err != nil {
		return ParsedClientHello{}, fmt.Errorf("ja3: legacy_version: %w", err)
	}

	// random  (32 bytes, skip)
	if err := r.skip(32); err != nil {
		return ParsedClientHello{}, fmt.Errorf("ja3: random: %w", err)
	}

	// legacy_session_id  (1-byte length prefix)
	sidLen, err := r.readUint8()
	if err != nil {
		return ParsedClientHello{}, fmt.Errorf("ja3: session_id length: %w", err)
	}
	if err := r.skip(int(sidLen)); err != nil {
		return ParsedClientHello{}, fmt.Errorf("ja3: session_id: %w", err)
	}

	// cipher_suites  (2-byte length prefix, each suite 2 bytes)
	csLen, err := r.readUint16()
	if err != nil {
		return ParsedClientHello{}, fmt.Errorf("ja3: cipher_suites length: %w", err)
	}
	if csLen%2 != 0 {
		return ParsedClientHello{}, fmt.Errorf("ja3: cipher_suites length %d must be even", csLen)
	}
	nCiphers := int(csLen) / 2
	ciphers := make([]uint16, nCiphers)
	for i := 0; i < nCiphers; i++ {
		ciphers[i], err = r.readUint16()
		if err != nil {
			return ParsedClientHello{}, fmt.Errorf("ja3: cipher_suite[%d]: %w", i, err)
		}
	}

	// legacy_compression_methods  (1-byte length prefix, skip)
	compLen, err := r.readUint8()
	if err != nil {
		return ParsedClientHello{}, fmt.Errorf("ja3: compression_methods length: %w", err)
	}
	if err := r.skip(int(compLen)); err != nil {
		return ParsedClientHello{}, fmt.Errorf("ja3: compression_methods: %w", err)
	}

	// extensions are optional (TLS < 1.0 may omit them)
	if r.remaining() < 2 {
		return ParsedClientHello{
			SSLVersion: version,
			Ciphers:    ciphers,
		}, nil
	}

	// extensions total length (2 bytes)
	extTotalLen, err := r.readUint16()
	if err != nil {
		return ParsedClientHello{}, fmt.Errorf("ja3: extensions length: %w", err)
	}
	if int(extTotalLen) > r.remaining() {
		return ParsedClientHello{}, fmt.Errorf(
			"ja3: extensions length %d exceeds remaining %d bytes", extTotalLen, r.remaining())
	}

	var (
		extIDs  []uint16
		curves  []uint16
		formats []uint8
	)

	extEnd := r.pos + int(extTotalLen)
	for r.pos < extEnd {
		extType, err := r.readUint16()
		if err != nil {
			return ParsedClientHello{}, fmt.Errorf("ja3: extension type: %w", err)
		}
		extLen, err := r.readUint16()
		if err != nil {
			return ParsedClientHello{}, fmt.Errorf("ja3: extension length: %w", err)
		}
		if r.pos+int(extLen) > extEnd {
			return ParsedClientHello{}, fmt.Errorf(
				"ja3: extension 0x%04x length %d overflows extension block", extType, extLen)
		}

		extData := r.buf[r.pos : r.pos+int(extLen)]
		r.pos += int(extLen)

		extIDs = append(extIDs, extType)

		switch extType {
		case 0x000a: // supported_groups — EllipticCurves in JA3
			curves, err = parseSupportedGroups(extData)
			if err != nil {
				return ParsedClientHello{}, fmt.Errorf("ja3: supported_groups: %w", err)
			}
		case 0x000b: // ec_point_formats — EllipticCurvePointFormats in JA3
			formats, err = parseECPointFormats(extData)
			if err != nil {
				return ParsedClientHello{}, fmt.Errorf("ja3: ec_point_formats: %w", err)
			}
		}
	}

	return ParsedClientHello{
		SSLVersion:           version,
		Ciphers:              ciphers,
		Extensions:           extIDs,
		EllipticCurves:       curves,
		EllipticCurveFormats: formats,
	}, nil
}

// parseSupportedGroups parses the content of the supported_groups extension.
//
//	struct {
//	    NamedGroup named_group_list<2..2^16-1>;  // 2-byte len + 2-byte entries
//	} NamedGroupList;
func parseSupportedGroups(data []byte) ([]uint16, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("too short for supported_groups list length")
	}
	listLen := int(data[0])<<8 | int(data[1])
	if len(data) < 2+listLen {
		return nil, fmt.Errorf("supported_groups truncated: need %d bytes, have %d", 2+listLen, len(data))
	}
	if listLen%2 != 0 {
		return nil, fmt.Errorf("supported_groups list length %d must be even", listLen)
	}
	groups := make([]uint16, 0, listLen/2)
	for i := 0; i < listLen/2; i++ {
		g := uint16(data[2+i*2])<<8 | uint16(data[3+i*2])
		groups = append(groups, g)
	}
	return groups, nil
}

// parseECPointFormats parses the content of the ec_point_formats extension.
//
//	struct {
//	    ECPointFormat ec_point_format_list<1..2^8-1>;  // 1-byte len + 1-byte entries
//	} ECPointFormatList;
func parseECPointFormats(data []byte) ([]uint8, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("too short for ec_point_formats length")
	}
	listLen := int(data[0])
	if len(data) < 1+listLen {
		return nil, fmt.Errorf("ec_point_formats truncated: need %d bytes, have %d", 1+listLen, len(data))
	}
	formats := make([]uint8, listLen)
	copy(formats, data[1:1+listLen])
	return formats, nil
}


// tlsReader is a stateful cursor over a byte slice.  All reads advance pos.
type tlsReader struct {
	buf []byte
	pos int
}

func (r *tlsReader) remaining() int { return len(r.buf) - r.pos }

func (r *tlsReader) peek() byte {
	if r.pos >= len(r.buf) {
		return 0
	}
	return r.buf[r.pos]
}

func (r *tlsReader) skip(n int) error {
	if r.pos+n > len(r.buf) {
		return fmt.Errorf("unexpected EOF: need %d bytes, have %d", n, r.remaining())
	}
	r.pos += n
	return nil
}

func (r *tlsReader) readUint8() (uint8, error) {
	if r.pos >= len(r.buf) {
		return 0, fmt.Errorf("unexpected EOF reading uint8")
	}
	v := r.buf[r.pos]
	r.pos++
	return v, nil
}

func (r *tlsReader) readUint16() (uint16, error) {
	if r.pos+2 > len(r.buf) {
		return 0, fmt.Errorf("unexpected EOF reading uint16")
	}
	v := uint16(r.buf[r.pos])<<8 | uint16(r.buf[r.pos+1])
	r.pos += 2
	return v, nil
}

// readUint24 reads a big-endian 3-byte (24-bit) unsigned integer.
// Used for the Handshake message length field.
func (r *tlsReader) readUint24() (uint32, error) {
	if r.pos+3 > len(r.buf) {
		return 0, fmt.Errorf("unexpected EOF reading uint24")
	}
	v := uint32(r.buf[r.pos])<<16 |
		uint32(r.buf[r.pos+1])<<8 |
		uint32(r.buf[r.pos+2])
	r.pos += 3
	return v, nil
}
