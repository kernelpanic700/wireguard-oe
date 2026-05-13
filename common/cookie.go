package common

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

// CookieLen is the fixed length of a MaxMode cookie in bytes.
const CookieLen = 8

// TimestampLen is the fixed length of the Unix timestamp embedded alongside the cookie.
const TimestampLen = 8

// DefaultCookieWindow is the default time window (±seconds) for cookie validation.
const DefaultCookieWindow = 90

// ErrInvalidCookie is returned by ValidateCookieBytes when an HMAC check fails.
var ErrInvalidCookie = errors.New("invalid cookie: HMAC mismatch")

// ErrCookieExpired is returned when a cookie timestamp is outside the valid window.
var ErrCookieExpired = errors.New("cookie expired: timestamp outside window")

// GenerateCookie produces an 8-byte cookie from data using HMAC-SHA256(key, data).
//
// The cookie is the first CookieLen bytes of the HMAC output. This is sufficient
// for a quick authenticity check without transmitting the full 32-byte tag.
//
// Parameters:
//   - key:  Must be exactly 32 bytes (SHA-256 block size).
//   - data: The packet data to authenticate (typically timestamp + handshake).
//
// Returns:
//   - cookie: 8-byte HMAC prefix.
//   - error:  if key is not 32 bytes.
func GenerateCookie(key, data []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("cookie key must be exactly 32 bytes")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	sum := mac.Sum(nil)

	cookie := make([]byte, CookieLen)
	copy(cookie, sum[:CookieLen])
	return cookie, nil
}

// ValidateCookieBytes checks whether the provided cookie matches
// HMAC-SHA256(key, data) truncated to CookieLen bytes.
//
// Uses constant-time comparison (hmac.Equal) to prevent timing side-channel
// attacks on the cookie.
//
// Returns:
//   - nil if the cookie is valid.
//   - ErrInvalidCookie if the cookie does not match.
//   - error if key is not 32 bytes.
func ValidateCookieBytes(key, data, cookie []byte) error {
	if len(key) != 32 {
		return errors.New("cookie key must be exactly 32 bytes")
	}
	if len(cookie) != CookieLen {
		return ErrInvalidCookie
	}

	expected, err := GenerateCookie(key, data)
	if err != nil {
		return err
	}

	if !hmac.Equal(expected, cookie) {
		return ErrInvalidCookie
	}
	return nil
}

// EmbedCookiePayload builds the GREASE extension payload for MaxMode.
//
// Format: [timestamp 8B | cookie 8B | data]
//
// The timestamp is the current Unix time in seconds (big-endian).
// The cookie is HMAC-SHA256(key, timestamp || data)[:8].
//
// This payload is placed after the magic bytes inside the GREASE extension.
func EmbedCookiePayload(key, data []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("cookie key must be exactly 32 bytes")
	}

	now := time.Now().Unix()
	ts := make([]byte, TimestampLen)
	binary.BigEndian.PutUint64(ts, uint64(now))

	// cookie = HMAC-SHA256(key, timestamp || data)[:8]
	authInput := make([]byte, TimestampLen+len(data))
	copy(authInput[0:TimestampLen], ts)
	copy(authInput[TimestampLen:], data)

	cookie, err := GenerateCookie(key, authInput)
	if err != nil {
		return nil, err
	}

	// Build payload: timestamp + cookie + data
	payload := make([]byte, TimestampLen+CookieLen+len(data))
	copy(payload[0:TimestampLen], ts)
	copy(payload[TimestampLen:TimestampLen+CookieLen], cookie)
	copy(payload[TimestampLen+CookieLen:], data)

	return payload, nil
}

// ExtractCookiePayload extracts and validates the timestamp, cookie, and data
// from a MaxMode GREASE extension payload.
//
// Format: [timestamp 8B | cookie 8B | data]
//
// Validation steps:
//  1. Payload must be at least TimestampLen + CookieLen bytes.
//  2. Cookie must match HMAC-SHA256(key, timestamp || data)[:8].
//  3. Timestamp must be within ±window seconds of the current time.
//
// Returns the original data on success, or an error on failure.
func ExtractCookiePayload(key, payload []byte, window int64) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("cookie key must be exactly 32 bytes")
	}
	if len(payload) < TimestampLen+CookieLen {
		return nil, ErrInvalidCookie
	}

	ts := payload[0:TimestampLen]
	cookie := payload[TimestampLen : TimestampLen+CookieLen]
	data := payload[TimestampLen+CookieLen:]

	// Validate HMAC
	authInput := make([]byte, TimestampLen+len(data))
	copy(authInput[0:TimestampLen], ts)
	copy(authInput[TimestampLen:], data)

	if err := ValidateCookieBytes(key, authInput, cookie); err != nil {
		return nil, err
	}

	// Check time window
	timestamp := int64(binary.BigEndian.Uint64(ts))
	if !CheckTimeWindow(timestamp, window) {
		return nil, ErrCookieExpired
	}

	return data, nil
}

// CheckTimeWindow returns true if the given timestamp is within ±window seconds
// of the current time.
func CheckTimeWindow(timestamp int64, window int64) bool {
	now := time.Now().Unix()
	diff := now - timestamp
	if diff < 0 {
		diff = -diff
	}
	return diff <= window
}
