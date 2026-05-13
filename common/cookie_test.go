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
