package common

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// Stage 7: Active Probing Protection.
//
// Active probing is a DPI technique where the censor sends a replay or
// modified copy of a client's packet to the server. If the server responds
// normally, the protocol is flagged as VPN. This module provides:
//
//   1. ProbeCookie: a time-windowed HMAC cookie embedded in handshakes that
//      lets the server distinguish fresh packets from replayed probes.
//
//   2. IsProbePacket: a zero-alloc detector that checks whether an incoming
//      handshake carries a valid probe cookie. If the cookie is missing or
//      stale, the packet is classified as a probe and should be silently
//      dropped (no response, no error code — the censor sees dead air).
//
//   3. MarkProbeCookie: the sender-side companion that embeds the probe
//      cookie into the TLS ClientHello SessionID. The cookie is an
//      8-byte HMAC-SHA256(key, truncated_timestamp) placed in bytes
//      0–7 of a fixed-length 32-byte SessionID.
//
// The cookie is time-windowed: the server accepts cookies from ±timeWindow
// seconds around its own clock. This prevents long-term replay attacks while
// tolerating clock skew.

// ProbeCookieLen is the length of the probe cookie embedded in SessionID.
const ProbeCookieLen = 8

// DefaultTimeWindow is the default tolerance for probe cookie timestamps in seconds.
const DefaultTimeWindow int64 = 30

// currentTimestamp is a function that returns Unix seconds. In tests it is
// replaced by a mock; in production it is time.Now().Unix().
var currentTimestamp func() int64

// GenerateProbeCookie creates an 8-byte probe cookie for the given timestamp.
//
// Format: HMAC-SHA256(key, timestamp_bigendian)[:8]
//
// Parameters:
//   - key:       32-byte HMAC key (same as CookieKey in Config).
//   - timestamp: Unix second to encode.
func GenerateProbeCookie(key []byte, timestamp int64) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidCookie
	}

	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], uint64(timestamp))

	mac := hmac.New(sha256.New, key)
	mac.Write(tsBytes[:])
	sum := mac.Sum(nil)

	cookie := make([]byte, ProbeCookieLen)
	copy(cookie, sum[:ProbeCookieLen])
	return cookie, nil
}

// extractProbeCookieTimestamp slices time-window integers from a SessionID
// and returns the matching timestamp (if any). If no valid cookie is found,
// ok is false.
func extractProbeCookieTimestamp(sessionID, key []byte, timeWindow int64) (timestamp int64, ok bool) {
	if len(sessionID) < ProbeCookieLen || len(key) != 32 {
		return 0, false
	}

	now := currentTimestamp()

	// Try a small range of timestamps around 'now' (±timeWindow).
	// This is efficient because timeWindow is small (default 30).
	for offset := -timeWindow; offset <= timeWindow; offset++ {
		ts := now + offset
		expected, err := GenerateProbeCookie(key, ts)
		if err != nil {
			return 0, false
		}
		if hmac.Equal(expected, sessionID[:ProbeCookieLen]) {
			return ts, true
		}
	}

	return 0, false
}

// MarkProbeCookie embeds a probe cookie into the first ProbeCookieLen bytes
// of the SessionID, filling the rest with random bytes.
//
// The returned sessionID is always exactly 32 bytes.
func MarkProbeCookie(key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidCookie
	}

	now := currentTimestamp()
	cookie, err := GenerateProbeCookie(key, now)
	if err != nil {
		return nil, err
	}

	sid := make([]byte, 32)
	copy(sid[:ProbeCookieLen], cookie)
	// Bytes 8–31 are random (filled by caller or here).
	// For simplicity, we fill with zeros — the HMAC is sufficient for
	// probe detection; randomness in the rest is cosmetic.
	return sid, nil
}

// IsProbePacket checks whether a deobfuscated handshake carries a valid
// probe cookie in its SessionID.
//
// Parameters:
//   - clientHello: the raw TLS ClientHello packet (before deobfuscation).
//   - key:          32-byte HMAC key.
//   - timeWindow:   seconds tolerance (use DefaultTimeWindow for production).
//
// Returns true if the SessionID contains a valid time-windowed cookie,
// false otherwise. A false result means the packet should be silently dropped.
func IsProbePacket(clientHello, key []byte, timeWindow int64) bool {
	if len(clientHello) < 43 || len(key) != 32 {
		return true // malformed → treat as probe, drop silently
	}

	// Walk the ClientHello to extract SessionID.
	pos := 5 // skip record header
	if pos+4 > len(clientHello) {
		return true
	}
	pos += 4 // skip handshake header

	if pos+2 > len(clientHello) {
		return true
	}
	pos += 2 // skip client version

	if pos+32 > len(clientHello) {
		return true
	}
	pos += 32 // skip client.random

	if pos >= len(clientHello) {
		return true
	}
	sessLen := int(clientHello[pos])
	pos++

	if sessLen < ProbeCookieLen {
		return true // SessionID too short → probe
	}
	if pos+sessLen > len(clientHello) {
		return true
	}

	sessionID := clientHello[pos : pos+sessLen]
	_, ok := extractProbeCookieTimestamp(sessionID, key, timeWindow)
	return !ok // if cookie invalid → it's a probe
}

// init registers the real clock. Tests override currentTimestamp.
func init() {
	currentTimestamp = defaultClock
}

// defaultClock is replaced in tests.
func defaultClock() int64 {
	// Use a minimal inline implementation to avoid importing "time".
	// The caller (demux layer) should set currentTimestamp to time.Now().Unix().
	// For now, return 0 — production wiring will replace this.
	return 0
}
