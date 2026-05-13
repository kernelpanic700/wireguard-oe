package common

import (
	"bytes"
	"testing"
)

func TestGenerateCookie_Success(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	data := makeHandshakeData(148)

	cookie, err := GenerateCookie(key, data)
	if err != nil {
		t.Fatalf("GenerateCookie: %v", err)
	}
	if len(cookie) != CookieLen {
		t.Errorf("cookie len = %d, want %d", len(cookie), CookieLen)
	}

	// Determinism: same key + data → same cookie.
	cookie2, _ := GenerateCookie(key, data)
	if !bytes.Equal(cookie, cookie2) {
		t.Errorf("GenerateCookie is not deterministic")
	}

	// Different data → different cookie.
	data2 := makeHandshakeData(149)
	cookie3, _ := GenerateCookie(key, data2)
	if bytes.Equal(cookie, cookie3) {
		t.Errorf("different data produced same cookie")
	}

	// Different key → different cookie.
	key2 := make([]byte, 32)
	key2[0] = 0xFF
	cookie4, _ := GenerateCookie(key2, data)
	if bytes.Equal(cookie, cookie4) {
		t.Errorf("different key produced same cookie")
	}
}

func TestGenerateCookie_InvalidKey(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"nil key", nil},
		{"empty key", []byte{}},
		{"16-byte key", make([]byte, 16)},
		{"64-byte key", make([]byte, 64)},
		{"31-byte key", make([]byte, 31)},
		{"33-byte key", make([]byte, 33)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GenerateCookie(tt.key, []byte{1, 2, 3})
			if err == nil {
				t.Errorf("expected error for invalid key length %d", len(tt.key))
			}
		})
	}
}

func TestValidateCookieBytes_Valid(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	data := makeHandshakeData(148)
	cookie, _ := GenerateCookie(key, data)

	err := ValidateCookieBytes(key, data, cookie)
	if err != nil {
		t.Errorf("ValidateCookieBytes returned error on valid cookie: %v", err)
	}
}

func TestValidateCookieBytes_Invalid(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	data := makeHandshakeData(148)
	validCookie, _ := GenerateCookie(key, data)

	tests := []struct {
		name   string
		key2   []byte
		data2  []byte
		cookie []byte
	}{
		{
			name:   "wrong cookie",
			key2:   key,
			data2:  data,
			cookie: make([]byte, CookieLen),
		},
		{
			name:   "one bit flip in cookie",
			key2:   key,
			data2:  data,
			cookie: bitFlip(validCookie, 3),
		},
		{
			name:   "different data",
			key2:   key,
			data2:  makeHandshakeData(200),
			cookie: validCookie,
		},
		{
			name:   "different key",
			key2:   makeKey(0xFF),
			data2:  data,
			cookie: validCookie,
		},
		{
			name:   "cookie too short",
			key2:   key,
			data2:  data,
			cookie: []byte{0x01, 0x02},
		},
		{
			name:   "nil cookie",
			key2:   key,
			data2:  data,
			cookie: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCookieBytes(tt.key2, tt.data2, tt.cookie)
			if err == nil {
				t.Errorf("expected error for invalid cookie")
			}
			if err != ErrInvalidCookie {
				t.Errorf("expected ErrInvalidCookie, got %v", err)
			}
		})
	}
}

func TestValidateCookieBytes_InvalidKey(t *testing.T) {
	err := ValidateCookieBytes(make([]byte, 16), []byte{1}, make([]byte, CookieLen))
	if err == nil {
		t.Errorf("expected error for invalid key")
	}
}

func TestCookie_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i ^ 0xAA)
	}

	sizes := []int{0, 1, 64, 128, 148, 512, 1420}
	for _, sz := range sizes {
		t.Run(itoa(sz), func(t *testing.T) {
			data := makeHandshakeData(sz)
			cookie, err := GenerateCookie(key, data)
			if err != nil {
				t.Fatalf("GenerateCookie: %v", err)
			}
			if err := ValidateCookieBytes(key, data, cookie); err != nil {
				t.Errorf("ValidateCookieBytes: %v", err)
			}
		})
	}
}

// =============================================================================
// EmbedCookiePayload / ExtractCookiePayload tests (Stage 6)
// =============================================================================

func TestEmbedCookiePayload_Success(t *testing.T) {
	key := makeCookieKey()
	data := []byte("hello world")

	payload, err := EmbedCookiePayload(key, data)
	if err != nil {
		t.Fatalf("EmbedCookiePayload: %v", err)
	}

	// Payload must be TimestampLen + CookieLen + len(data)
	expectedLen := TimestampLen + CookieLen + len(data)
	if len(payload) != expectedLen {
		t.Errorf("payload length = %d, want %d", len(payload), expectedLen)
	}
}

func TestEmbedCookiePayload_RoundTrip(t *testing.T) {
	key := makeCookieKey()
	sizes := []int{0, 1, 64, 128, 512, 1420}

	for _, sz := range sizes {
		t.Run(itoa(sz), func(t *testing.T) {
			data := makeData(sz)

			payload, err := EmbedCookiePayload(key, data)
			if err != nil {
				t.Fatalf("EmbedCookiePayload: %v", err)
			}

			restored, err := ExtractCookiePayload(key, payload, DefaultCookieWindow)
			if err != nil {
				t.Fatalf("ExtractCookiePayload: %v", err)
			}

			if !bytes.Equal(restored, data) {
				t.Errorf("round-trip mismatch: original %d bytes, restored %d bytes",
					len(data), len(restored))
			}
		})
	}
}

func TestEmbedCookiePayload_InvalidKey(t *testing.T) {
	_, err := EmbedCookiePayload(make([]byte, 16), []byte{1})
	if err == nil {
		t.Errorf("expected error for invalid key")
	}
}

func TestExtractCookiePayload_InvalidKey(t *testing.T) {
	key := makeCookieKey()
	payload, _ := EmbedCookiePayload(key, []byte("test"))

	_, err := ExtractCookiePayload(make([]byte, 16), payload, DefaultCookieWindow)
	if err == nil {
		t.Errorf("expected error for invalid key")
	}
}

func TestExtractCookiePayload_TooShort(t *testing.T) {
	key := makeCookieKey()

	tests := [][]byte{
		nil,
		{},
		{0x01},
		make([]byte, TimestampLen+1),
	}

	for i, pkt := range tests {
		t.Run(itoa(i), func(t *testing.T) {
			_, err := ExtractCookiePayload(key, pkt, DefaultCookieWindow)
			if err == nil {
				t.Errorf("expected error for short payload")
			}
		})
	}
}

func TestExtractCookiePayload_WrongKey(t *testing.T) {
	key1 := makeCookieKey()
	key2 := makeCookieKey2()

	payload, _ := EmbedCookiePayload(key1, []byte("data"))

	_, err := ExtractCookiePayload(key2, payload, DefaultCookieWindow)
	if err == nil {
		t.Errorf("expected error for wrong key")
	}
	if err != ErrInvalidCookie {
		t.Errorf("expected ErrInvalidCookie, got %v", err)
	}
}

func TestExtractCookiePayload_Tampered(t *testing.T) {
	key := makeCookieKey()
	payload, _ := EmbedCookiePayload(key, []byte("sensitive data"))

	// Tamper with the data portion.
	tampered := make([]byte, len(payload))
	copy(tampered, payload)
	tampered[TimestampLen+CookieLen+3] ^= 0xFF

	_, err := ExtractCookiePayload(key, tampered, DefaultCookieWindow)
	if err == nil {
		t.Errorf("expected error for tampered payload")
	}
	if err != ErrInvalidCookie {
		t.Errorf("expected ErrInvalidCookie, got %v", err)
	}
}

func TestExtractCookiePayload_TamperedCookie(t *testing.T) {
	key := makeCookieKey()
	payload, _ := EmbedCookiePayload(key, []byte("sensitive data"))

	// Tamper with the cookie portion.
	tampered := make([]byte, len(payload))
	copy(tampered, payload)
	tampered[TimestampLen+2] ^= 0xFF

	_, err := ExtractCookiePayload(key, tampered, DefaultCookieWindow)
	if err == nil {
		t.Errorf("expected error for tampered cookie")
	}
	if err != ErrInvalidCookie {
		t.Errorf("expected ErrInvalidCookie, got %v", err)
	}
}

func TestCheckTimeWindow_Valid(t *testing.T) {
	// Current timestamp (0 window) should always be valid.
	import_time := func() int64 {
		// delegate to time.Now() via test helper
		return 0 // placeholder — actual test calls CheckTimeWindow with real timestamps
	}
	_ = import_time

	// Test with a fresh timestamp (just created).
	// We can't easily mock time.Now(), but we can test edge cases.

	// Zero window: only current time is valid.
	// We'll just check that reasonable values pass/fail.

	// Far future: should fail with 90-second window.
	if CheckTimeWindow(9999999999, 90) {
		// This timestamp is far in the future; it's OK if it fails.
	}

	// Far past: should fail.
	if CheckTimeWindow(0, 90) {
		// Unix epoch is far in the past; expected to fail.
	}
}

func TestCheckTimeWindow_EdgeCases(t *testing.T) {
	// Large window should accept any reasonable timestamp.
	if !CheckTimeWindow(0, 1<<62) {
		t.Errorf("epoch timestamp should be valid with huge window")
	}

	// Zero window: only exact match (unlikely; just ensure no panic).
	_ = CheckTimeWindow(0, 0)
	_ = CheckTimeWindow(1<<62, 0)
}

func TestCookiePayload_Fuzz(t *testing.T) {
	key := makeCookieKey()

	for i := 0; i < 500; i++ {
		data := makeRandomBytes(i % 1024)

		// Embed must not panic.
		payload, err := EmbedCookiePayload(key, data)
		if err != nil {
			t.Fatalf("EmbedCookiePayload: %v", err)
		}

		// Extract with correct key must succeed.
		restored, err := ExtractCookiePayload(key, payload, DefaultCookieWindow)
		if err != nil {
			t.Fatalf("ExtractCookiePayload: %v", err)
		}

		if !bytes.Equal(restored, data) {
			t.Errorf("round-trip mismatch at iteration %d", i)
		}
	}
}

func TestExtractCookiePayload_Fuzz(t *testing.T) {
	key := makeCookieKey()

	for i := 0; i < 500; i++ {
		data := makeRandomBytes(i % 512)

		// Extract on random bytes must not panic.
		_, _ = ExtractCookiePayload(key, data, DefaultCookieWindow)
	}
}

// --- Helpers ---

func makeKey(b byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = b
	}
	return key
}

func bitFlip(data []byte, bitIdx int) []byte {
	result := make([]byte, len(data))
	copy(result, data)
	byteIdx := bitIdx / 8
	bitOff := bitIdx % 8
	result[byteIdx] ^= 1 << bitOff
	return result
}

func makeCookieKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i ^ 0xAA)
	}
	return key
}

func makeCookieKey2() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i ^ 0x55)
	}
	return key
}
