package common

import "testing"

func TestGenerateCookie(t *testing.T) {
	key := []byte("test-key-12345678")
	cookie := GenerateCookie(key, []byte("127.0.0.1"), 51820, 1720000000, []byte("salt"))
	if cookie == nil || len(cookie) != 32 {
		t.Errorf("expected 32-byte cookie, got %d bytes", len(cookie))
	}
}
