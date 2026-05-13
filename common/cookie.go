package common

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

// CookieLen is the fixed length of a MaxMode cookie in bytes.
const CookieLen = 8

// ErrInvalidCookie is returned by ValidateCookieBytes when an HMAC check fails.
var ErrInvalidCookie = errors.New("invalid cookie: HMAC mismatch")

// GenerateCookie produces an 8-byte cookie from data using HMAC-SHA256(key, data).
//
// The cookie is the first CookieLen bytes of the HMAC output. This is sufficient
// for a quick authenticity check without transmitting the full 32-byte tag.
//
// Parameters:
//   - key:  Must be exactly 32 bytes (SHA-256 block size).
//   - data: The packet data to authenticate (typically the original handshake
//           initiation before wrapping).
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
// Uses constant-time comparison (subtle.ConstantTimeCompare equivalent via
// hmac.Equal) to prevent timing side-channel attacks on the cookie.
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
