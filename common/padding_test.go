package common

import "testing"

func TestPadAndTrimPad(t *testing.T) {
	original := []byte("hello")
	padded, err := Pad(original, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(padded) != 16 {
		t.Errorf("expected length 16, got %d", len(padded))
	}
	trimmed := TrimPad(padded, len(original))
	if string(trimmed) != "hello" {
		t.Errorf("expected 'hello', got '%s'", string(trimmed))
	}
}
