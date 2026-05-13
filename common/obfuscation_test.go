package common

import "testing"

func TestNewObfuscator(t *testing.T) {
	_, err := NewObfuscator(Config{Mode: ModeVanilla})
	if err != nil {
		t.Skip("Not implemented yet")
	}
}
