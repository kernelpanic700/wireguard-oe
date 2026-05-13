package common

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrNotClientHello is returned by DeobfuscateClientHello when the input
// does not conform to the expected TLS ClientHello wrapper format.
var ErrNotClientHello = errors.New("not a valid WG-OE TLS ClientHello")

// TLS mimicry constants (Stage 4 — Lite, no uTLS dependency).
const (
	// GREASE extension type (RFC 8701).
	greaseExtension uint16 = 0xFAFA

	// Magic bytes embedded inside the GREASE extension payload to mark "our" packets.
	tlsMagic0 byte = 0xD4
	tlsMagic1 byte = 0x1F

	// Static cipher suites (Chrome 120-like selection).
	cipherSuiteTLS_ECDHE_RSA_AES128_GCM          uint16 = 0xC02F
	cipherSuiteTLS_ECDHE_ECDSA_AES128_GCM        uint16 = 0xC02B
	cipherSuiteTLS_ECDHE_RSA_AES256_GCM          uint16 = 0xC030
	cipherSuiteTLS_ECDHE_ECDSA_CHACHA20_POLY1305 uint16 = 0xCCA9
)

// ObfuscateClientHello wraps arbitrary data inside a TLS 1.2 ClientHello
// message that mimics a standard HTTPS connection.
//
// Packet structure:
//
//  RFC 5246 TLS Record Layer:
//    [0x16]               ContentType: Handshake
//    [0x03 0x03]          Version: TLS 1.2
//    [RecordLen 2B]
//
//  Handshake — ClientHello:
//    [0x01]               HandshakeType: ClientHello
//    [HsLen 3B]
//    [0x03 0x03]          Client Version: TLS 1.2
//    [Random 32B]         crypto/rand (fresh each call)
//    [SessionID Len 1B]
//    [SessionID 0–32B]    crypto/rand
//    [CipherSuites 10B]   4 static suites (Chrome-like)
//    [Compression 2B]     null
//    [Extensions Len 2B]
//
//  Extensions:
//    SNI (0x0000)         — configurable hostname, default "cloudflare.com"
//    SupportedGroups      — x25519 + secp256r1
//    ALPN                 — h2 + http/1.1
//    GREASE (0xFAFA)      — [Magic 0xD4 0x1F | WG Handshake Data]
//
// The returned packet starts with 0x16 0x03 0x03 ... making it indistinguishable
// from a real TLS handshake to simple DPI.
//
// Parameters:
//   - data: the data to hide (typically a WireGuard handshake initiation).
//   - sni:  SNI hostname to advertise (e.g. "cloudflare.com" or "www.google.com").
//           Empty string falls back to the default.
func ObfuscateClientHello(data []byte, sni string) ([]byte, error) {
	if len(data) > 65535-200 {
		return nil, fmt.Errorf("data too large: %d bytes (max ~65335)", len(data))
	}
	if sni == "" {
		sni = "cloudflare.com"
	}
	if len(sni) > 255 {
		return nil, fmt.Errorf("SNI too long: %d bytes (max 255)", len(sni))
	}

	// --- Random session ID (0–32 bytes) ---
	var rng [1]byte
	if _, err := rand.Read(rng[:]); err != nil {
		return nil, fmt.Errorf("crypto/rand session: %w", err)
	}
	sessionIDLen := int(rng[0]) % 33
	sessionID := make([]byte, sessionIDLen)
	if sessionIDLen > 0 {
		if _, err := rand.Read(sessionID); err != nil {
			return nil, fmt.Errorf("crypto/rand session bytes: %w", err)
		}
	}

	// --- Client random (32 bytes) ---
	clientRandom := make([]byte, 32)
	if _, err := rand.Read(clientRandom); err != nil {
		return nil, fmt.Errorf("crypto/rand client.random: %w", err)
	}

	// --- Static cipher suites (4 suites × 2 bytes = 8 bytes) ---
	cipherSuitesData := make([]byte, 10)
	binary.BigEndian.PutUint16(cipherSuitesData[0:], 8) // length
	binary.BigEndian.PutUint16(cipherSuitesData[2:], cipherSuiteTLS_ECDHE_RSA_AES128_GCM)
	binary.BigEndian.PutUint16(cipherSuitesData[4:], cipherSuiteTLS_ECDHE_ECDSA_AES128_GCM)
	binary.BigEndian.PutUint16(cipherSuitesData[6:], cipherSuiteTLS_ECDHE_RSA_AES256_GCM)
	binary.BigEndian.PutUint16(cipherSuitesData[8:], cipherSuiteTLS_ECDHE_ECDSA_CHACHA20_POLY1305)

	// --- Compression: null ---
	compressionData := []byte{0x01, 0x00}

	// --- Build SNI extension ---
	// Type(0x0000) + Len + ServerNameList
	sniExtLen := 2 + 2 + 1 + 2 + len(sni) // = 7 + len(sni)
	sniExt := make([]byte, 4+sniExtLen)
	binary.BigEndian.PutUint16(sniExt[0:], 0x0000)                    // server_name
	binary.BigEndian.PutUint16(sniExt[2:], uint16(sniExtLen))          // extension length
	binary.BigEndian.PutUint16(sniExt[4:], uint16(len(sni)+3))        // SN list length
	sniExt[6] = 0x00                                                     // name_type: host_name
	binary.BigEndian.PutUint16(sniExt[7:], uint16(len(sni)))           // hostname length
	copy(sniExt[9:], sni)

	// --- Build SupportedGroups extension ---
	supportedGroupsExt := []byte{
		0x00, 0x0A, 0x00, 0x06, // type + len
		0x00, 0x04,             // groups length
		0x00, 0x1D, // x25519
		0x00, 0x17, // secp256r1
	}

	// --- Build ALPN extension ---
	alpnData := []byte{
		0x00, 0x10, 0x00, 0x0E, // type + len
		0x00, 0x0C, // alpn list length
		0x02, 'h', '2',
		0x08, 'h', 't', 't', 'p', '/', '1', '.', '1',
	}

	// --- Build GREASE extension ---
	// Type(0xFAFA) + Len(2+len(data)) + Magic(0xD4 0x1F) + data
	greaseDataLen := 2 + len(data)
	greaseExt := make([]byte, 4+greaseDataLen)
	binary.BigEndian.PutUint16(greaseExt[0:], greaseExtension)
	binary.BigEndian.PutUint16(greaseExt[2:], uint16(greaseDataLen))
	greaseExt[4] = tlsMagic0
	greaseExt[5] = tlsMagic1
	copy(greaseExt[6:], data)

	// --- Calculate total size ---
	// Fixed: Record(5) + HsType(1) + HsLen(3) + Version(2) + Random(32) +
	//        SessionIDLen(1) + sessionIDLen + CipherSuites(10) + Compression(2)
	beforeExt := 5 + 1 + 3 + 2 + 32 + 1 + sessionIDLen + 10 + 2

	extensionsData := make([]byte, 0,
		len(sniExt)+len(supportedGroupsExt)+len(alpnData)+len(greaseExt))
	extensionsData = append(extensionsData, sniExt...)
	extensionsData = append(extensionsData, supportedGroupsExt...)
	extensionsData = append(extensionsData, alpnData...)
	extensionsData = append(extensionsData, greaseExt...)

	totalSize := beforeExt + 2 + len(extensionsData) // +2 for extensions length field
	buf := make([]byte, totalSize)

	// --- Assemble packet ---
	pos := 0

	// Record layer header
	buf[pos] = 0x16 // ContentType: Handshake
	binary.BigEndian.PutUint16(buf[pos+1:], 0x0303)               // Version: TLS 1.2
	binary.BigEndian.PutUint16(buf[pos+3:], uint16(totalSize-5))   // record length
	pos += 5

	// Handshake header
	buf[pos] = 0x01 // HandshakeType: ClientHello
	buf[pos+1] = byte((totalSize - 5 - 4) >> 16)
	buf[pos+2] = byte((totalSize - 5 - 4) >> 8)
	buf[pos+3] = byte(totalSize - 5 - 4)
	pos += 4

	// Client version
	binary.BigEndian.PutUint16(buf[pos:], 0x0303)
	pos += 2

	// Client random
	copy(buf[pos:], clientRandom)
	pos += 32

	// Session ID
	buf[pos] = byte(sessionIDLen)
	pos++
	if sessionIDLen > 0 {
		copy(buf[pos:], sessionID)
		pos += sessionIDLen
	}

	// Cipher suites
	copy(buf[pos:], cipherSuitesData)
	pos += len(cipherSuitesData)

	// Compression
	copy(buf[pos:], compressionData)
	pos += len(compressionData)

	// Extensions length + data
	binary.BigEndian.PutUint16(buf[pos:], uint16(len(extensionsData)))
	pos += 2
	copy(buf[pos:], extensionsData)

	return buf, nil
}

// DeobfuscateClientHello extracts the hidden data from a TLS ClientHello
// wrapper. It performs zero allocations — the returned slice is a sub-slice
// of the input.
//
// Validation steps:
//  1. Record type must be 0x16 (Handshake)
//  2. TLS version must be 0x0303 (TLS 1.2)
//  3. Record length must be consistent with total length
//  4. Handshake type must be 0x01 (ClientHello)
//  5. Client version must be 0x0303
//  6. Variable-length fields (session ID, cipher suites, compression) are walked
//     with bounds checks
//  7. Extensions are scanned for GREASE (0xFAFA) containing magic 0xD4 0x1F
//  8. The sub-slice after the magic is returned
//
// Returns ErrNotClientHello for any malformed, truncated, or non-GREASE input.
// This function is designed to never panic, regardless of input.
func DeobfuscateClientHello(data []byte) ([]byte, error) {
	// Absolute minimum: 5(record) + 4(handshake) + 2(version) + 32(random) = 43 bytes.
	const minLen = 5 + 4 + 2 + 32
	if len(data) < minLen {
		return nil, ErrNotClientHello
	}

	pos := 0

	// 1. Record type: must be 0x16 (Handshake).
	if data[pos] != 0x16 {
		return nil, ErrNotClientHello
	}
	pos++

	// 2. TLS version: must be 0x0303 (TLS 1.2).
	if binary.BigEndian.Uint16(data[pos:]) != 0x0303 {
		return nil, ErrNotClientHello
	}
	pos += 2

	// 3. Record length.
	recordLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2
	if 5+recordLen != len(data) {
		return nil, ErrNotClientHello
	}

	// 4. Handshake type: must be 0x01 (ClientHello).
	if data[pos] != 0x01 {
		return nil, ErrNotClientHello
	}
	pos++

	// 5. Handshake body length (3 bytes, big-endian).
	if pos+3 > len(data) {
		return nil, ErrNotClientHello
	}
	hsBodyLen := int(uint32(data[pos])<<16 | uint32(data[pos+1])<<8 | uint32(data[pos+2]))
	pos += 3
	if pos+hsBodyLen != len(data) {
		return nil, ErrNotClientHello
	}

	// 6. Client version: must be 0x0303.
	if pos+2 > len(data) {
		return nil, ErrNotClientHello
	}
	if binary.BigEndian.Uint16(data[pos:]) != 0x0303 {
		return nil, ErrNotClientHello
	}
	pos += 2

	// 7. Client random (skip 32 bytes).
	if pos+32 > len(data) {
		return nil, ErrNotClientHello
	}
	pos += 32

	// 8. Session ID.
	if pos >= len(data) {
		return nil, ErrNotClientHello
	}
	sessLen := int(data[pos])
	pos++
	if pos+sessLen > len(data) {
		return nil, ErrNotClientHello
	}
	pos += sessLen

	// 9. Cipher suites.
	if pos+2 > len(data) {
		return nil, ErrNotClientHello
	}
	csLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2
	if pos+csLen > len(data) {
		return nil, ErrNotClientHello
	}
	pos += csLen

	// 10. Compression methods.
	if pos+1 > len(data) {
		return nil, ErrNotClientHello
	}
	compLen := int(data[pos])
	pos++
	if pos+compLen > len(data) {
		return nil, ErrNotClientHello
	}
	pos += compLen

	// 11. Extensions length.
	if pos+2 > len(data) {
		return nil, ErrNotClientHello
	}
	extLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2
	extEnd := pos + extLen
	if extEnd > len(data) {
		return nil, ErrNotClientHello
	}

	// 12. Scan extensions for GREASE (0xFAFA).
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[pos:])
		extDataLen := int(binary.BigEndian.Uint16(data[pos+2:]))
		if pos+4+extDataLen > extEnd {
			return nil, ErrNotClientHello
		}

		if extType == greaseExtension {
			// GREASE must contain at least magic (2 bytes) + 1 byte of data.
			if extDataLen < 3 {
				return nil, ErrNotClientHello
			}
			magicStart := pos + 4
			if data[magicStart] != tlsMagic0 || data[magicStart+1] != tlsMagic1 {
				return nil, ErrNotClientHello
			}
			// Zero allocation: return sub-slice.
			return data[magicStart+2 : magicStart+extDataLen], nil
		}

		pos += 4 + extDataLen
	}

	// GREASE extension with correct magic not found.
	return nil, ErrNotClientHello
}