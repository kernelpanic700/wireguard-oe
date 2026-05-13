// Package common provides the core obfuscation primitives shared across server,
// client, and Android builds. This file implements the Stage 3 padding engine.
package common

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// WireGuard-OE Stage 3 packet format:
//
//   [ Random Prefix (0–16 bytes) | Original Data | Magic 0xD4 0x1F |
//     Random Padding (P bytes) | PadLen (1 byte) | PrefLen (1 byte) ]
//
// PrefLen  = last byte:        length of the random prefix (0–16)
// PadLen   = second-last byte: length of the random padding (0–255)
// Magic    = 0xD4 0x1F:        discriminator to distinguish OE packets from noise
//
// Minimum overhead = 4 bytes (PrefLen=0, PadLen=0).
// Maximum overhead = 275 bytes (PrefLen=16, PadLen=255).

const (
	// maxPrefix is the upper bound for the random prefix length.
	maxPrefix = 16

	// magic0 and magic1 form the 2-byte discriminator placed before the padding.
	magic0 = 0xD4
	magic1 = 0x1F

	// fixedOverhead is the number of bytes always added regardless of padding sizes:
	// 2 magic + 1 padLen + 1 prefLen = 4.
	fixedOverhead = 4
)

// ErrInvalidPadding is returned by RemovePadding when the input does not
// conform to the Stage 3 packet format. This covers truncated packets,
// wrong magic bytes, or invalid length fields.
var ErrInvalidPadding = errors.New("invalid padding: not a WireGuard-OE packet")

// AddPadding appends a random prefix, a magic discriminator, and random padding
// to the input data according to the Stage 3 format.
//
// Parameters:
//   - data:   the original WG packet to obfuscate.
//   - minPad: minimum padding length (inclusive), must be ≥ 0 and ≤ maxPad.
//   - maxPad: maximum padding length (inclusive), must be ≤ 255.
//
// The returned slice is a newly allocated buffer; the input slice is not mutated.
func AddPadding(data []byte, minPad, maxPad int) ([]byte, error) {
	if minPad < 0 || maxPad < 0 {
		return nil, fmt.Errorf("padding range must be non-negative: [%d, %d]", minPad, maxPad)
	}
	if minPad > maxPad {
		return nil, fmt.Errorf("minPad (%d) > maxPad (%d)", minPad, maxPad)
	}
	if maxPad > 255 {
		return nil, fmt.Errorf("maxPad (%d) exceeds 255", maxPad)
	}

	// Read 2 random bytes: one for PrefLen, one for PadLen (scaled).
	var rng [2]byte
	if _, err := rand.Read(rng[:]); err != nil {
		return nil, fmt.Errorf("crypto/rand: %w", err)
	}

	prefLen := int(rng[0]) % (maxPrefix + 1)       // 0..16
	padLen := int(rng[1])%(maxPad-minPad+1) + minPad // minPad..maxPad

	totalLen := len(data) + prefLen + padLen + fixedOverhead
	buf := make([]byte, totalLen)

	// 1. Random prefix
	if prefLen > 0 {
		if _, err := rand.Read(buf[:prefLen]); err != nil {
			return nil, fmt.Errorf("crypto/rand prefix: %w", err)
		}
	}

	// 2. Copy original data
	copy(buf[prefLen:], data)

	// 3. Magic discriminator
	pos := prefLen + len(data)
	buf[pos] = magic0
	buf[pos+1] = magic1

	// 4. Random padding
	padStart := pos + 2
	if padLen > 0 {
		if _, err := rand.Read(buf[padStart : padStart+padLen]); err != nil {
			return nil, fmt.Errorf("crypto/rand padding: %w", err)
		}
	}

	// 5. PadLen and PrefLen
	buf[totalLen-2] = byte(padLen)
	buf[totalLen-1] = byte(prefLen)

	return buf, nil
}

// RemovePadding strips the Stage 3 obfuscation layer and returns the original
// payload. It performs zero allocations — the returned slice is a sub-slice of
// the input.
//
// Returns ErrInvalidPadding for any malformed input (wrong magic, truncated
// packet, invalid length fields).
func RemovePadding(data []byte) ([]byte, error) {
	n := len(data)
	if n < fixedOverhead {
		return nil, ErrInvalidPadding
	}

	prefLen := int(data[n-1])
	if prefLen > maxPrefix {
		return nil, ErrInvalidPadding
	}

	padLen := int(data[n-2])
	// padLen can be 0..255, no upper bound check beyond what the total len enforces.

	if n < prefLen+padLen+fixedOverhead {
		return nil, ErrInvalidPadding
	}

	// Magic bytes are located right after prefix+original_data.
	magicPos := n - 2 - padLen - 2
	if magicPos < prefLen || magicPos+1 >= n {
		return nil, ErrInvalidPadding
	}
	if data[magicPos] != magic0 || data[magicPos+1] != magic1 {
		return nil, ErrInvalidPadding
	}

	// Return the original data: slice between prefix and magic.
	return data[prefLen:magicPos], nil
}