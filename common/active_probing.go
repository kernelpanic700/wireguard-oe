package common

import (
	"crypto/hmac"
	"crypto/sha256"
)

// GenerateCookie creates an HMAC-SHA256 cookie for active probing protection.
func GenerateCookie(key, sourceIP []byte, sourcePort int, timestamp int64, salt []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(sourceIP)
	mac.Write([]byte{byte(sourcePort >> 8), byte(sourcePort & 0xFF)})
	mac.Write([]byte{
		byte(timestamp >> 56), byte(timestamp >> 48),
		byte(timestamp >> 40), byte(timestamp >> 32),
		byte(timestamp >> 24), byte(timestamp >> 16),
		byte(timestamp >> 8), byte(timestamp),
	})
	mac.Write(salt)
	return mac.Sum(nil)
}
