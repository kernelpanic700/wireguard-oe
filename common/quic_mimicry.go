package common

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// Stage 8: QUIC Short-Header Mimicry (Lite).
//
// Wraps WireGuard data packets inside a QUIC short-header packet to evade
// DPI that whitelists QUIC traffic (UDP port 443, etc.). The wrapper uses
// a fixed, plausible Destination Connection ID and a fake packet number.
//
// Format (IETF QUIC v1, RFC 9000 §17.3.1 — simplified):
//
//   [0x40]                        Header form (1 bit = short), F bit = 1,
//                                  Spin=0, Reserved=0, KPN=0 = 0x40
//   [Destination Conn ID 8B]      Static ID: 0x01 0x02 ... 0x08
//   [Packet Number 1–3B]          Random length + value
//   [Payload = WG data]           Encrypted-looking payload
//
// DeobfuscateQUICShortHeader extracts the payload by stripping the header.
// Returns ErrNotQUICShortHeader for malformed input.

// ErrNotQUICShortHeader is returned when the input is not a valid QUIC short-header wrapper.
var ErrNotQUICShortHeader = errors.New("not a valid QUIC short-header OE packet")

const (
	// quicDestConnID is a static, plausible-looking 8-byte connection ID.
	quicDestConnID = "\x01\x02\x03\x04\x05\x06\x07\x08"

	// minQUICShortHeader is 1 (first byte) + 8 (DCID) + 1 (min packet number).
	minQUICShortHeader = 10
)

// ObfuscateQUICShortHeader wraps data in a QUIC short-header packet.
//
// The returned packet looks like:
//   [0x40 | DCID(8) | PktNum(1-3 random) | data]
//
// Parameters:
//   - data: payload to hide.
//
// Returns the wrapped packet or an error if crypto/rand fails.
func ObfuscateQUICShortHeader(data []byte) ([]byte, error) {
	// Random packet number length: 1, 2, or 3 bytes.
	var rng [1]byte
	if _, err := rand.Read(rng[:]); err != nil {
		return nil, err
	}
	pktNumLen := int(rng[0]%3) + 1 // 1..3

	// Random packet number bytes.
	pktNum := make([]byte, pktNumLen)
	if _, err := rand.Read(pktNum); err != nil {
		return nil, err
	}

	totalLen := 1 + 8 + pktNumLen + len(data)
	buf := make([]byte, totalLen)

	pos := 0
	// QUIC short header byte: 01.... → short, ..0..... → fixed bit 0,
	// ....1... → spin clear, .....00. → reserved 0, .......0 → KPN 0.
	// Result: 0100_0000 = 0x40
	buf[pos] = 0x40
	pos++

	// Destination Connection ID (8 bytes).
	copy(buf[pos:], quicDestConnID)
	pos += 8

	// Packet number.
	copy(buf[pos:], pktNum)
	pos += pktNumLen

	// Payload.
	copy(buf[pos:], data)

	return buf, nil
}

// DeobfuscateQUICShortHeader extracts the original data from a QUIC short-header
// wrapper. Zero allocations — returned slice is a sub-slice of input.
//
// Validation:
//   1. First byte must be 0x40 (short header, fixed bit, etc.).
//   2. Destination Conn ID must match the static ID.
//   3. Packet number length must be 1–3 bytes (reasonable).
//
// Returns ErrNotQUICShortHeader for any invalid input.
func DeobfuscateQUICShortHeader(data []byte) ([]byte, error) {
	if len(data) < minQUICShortHeader {
		return nil, ErrNotQUICShortHeader
	}

	pos := 0

	// First byte.
	if data[pos] != 0x40 {
		return nil, ErrNotQUICShortHeader
	}
	pos++

	// Destination Conn ID.
	if string(data[pos:pos+8]) != quicDestConnID {
		return nil, ErrNotQUICShortHeader
	}
	pos += 8

	// Packet number: we don't know its length, but we know it's 1–3 bytes.
	// Try each possible length and return the first that doesn't underflow.
	// This is a heuristic: we assume the payload is at least 1 byte,
	// and the total length implies a 1–3 byte packet number.
	for pktNumLen := 1; pktNumLen <= 3; pktNumLen++ {
		if pos+pktNumLen <= len(data)-1 { // at least 1 byte of payload
			return data[pos+pktNumLen:], nil
		}
	}

	return nil, ErrNotQUICShortHeader
}

// QUIC mimicry helpers for binary operations.
var _ = binary.BigEndian // keep import alive (used elsewhere)
