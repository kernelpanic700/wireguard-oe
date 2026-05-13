package common

import (
	"bytes"
	"testing"
)

func TestWrapWebSocket_Basic(t *testing.T) {
	sizes := []int{0, 1, 64, 125, 126, 256, 1420}

	for _, sz := range sizes {
		t.Run(itoa(sz), func(t *testing.T) {
			original := makeData(sz)
			frame, err := WrapWebSocket(original)
			if err != nil {
				t.Fatalf("WrapWebSocket: %v", err)
			}

			// FIN=1, opcode=2
			if frame[0] != 0x82 {
				t.Errorf("first byte = 0x%02X, want 0x82", frame[0])
			}

			// Mask bit set
			if frame[1]&0x80 == 0 {
				t.Errorf("mask bit not set")
			}

			// Payload must be masked (not identical to original)
			payLen := sz
			headerLen := 2 + 4
			if payLen > 125 {
				headerLen += 2
			}
			if len(frame) != headerLen+payLen {
				t.Errorf("frame len = %d, want %d", len(frame), headerLen+payLen)
			}

			payload := frame[headerLen:]
			if payLen > 0 && bytes.Equal(payload, original) {
				t.Errorf("payload was not masked")
			}
		})
	}
}

func TestUnwrapWebSocket_Invalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short (5 bytes)", []byte{0x82, 0x80, 0x01, 0x02, 0x03}},
		{"wrong opcode", []byte{0x81, 0x80, 0x00, 0x00, 0x00, 0x00}},
		{"unmasked frame", []byte{0x82, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"random 50 bytes", makeRandomBytes(50)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UnwrapWebSocket(tt.data)
			if err == nil {
				t.Errorf("expected error, got result=%x", result)
			}
			if err != ErrNotWebSocketFrame {
				t.Errorf("expected ErrNotWebSocketFrame, got %v", err)
			}
		})
	}
}

func TestWebSocket_RoundTrip(t *testing.T) {
	sizes := []int{0, 1, 64, 125, 126, 256, 512, 1420}

	for _, sz := range sizes {
		t.Run(itoa(sz), func(t *testing.T) {
			original := makeData(sz)
			frame, err := WrapWebSocket(original)
			if err != nil {
				t.Fatalf("WrapWebSocket: %v", err)
			}

			extracted, err := UnwrapWebSocket(frame)
			if err != nil {
				t.Fatalf("UnwrapWebSocket: %v", err)
			}

			if !bytes.Equal(extracted, original) {
				t.Errorf("round-trip mismatch: original %d bytes, extracted %d bytes",
					len(original), len(extracted))
			}
		})
	}
}

func TestWebSocket_Overhead(t *testing.T) {
	// Payload ≤125 → 6 bytes overhead (2 header + 4 mask).
	// Payload 126–65535 → 8 bytes overhead (4 header + 4 mask).

	tests := []struct {
		payloadSize int
		expectedOv  int
	}{
		{0, 6},
		{1, 6},
		{125, 6},
		{126, 8},
		{256, 8},
		{1420, 8},
		{65535, 8},
	}

	for _, tt := range tests {
		t.Run(itoa(tt.payloadSize), func(t *testing.T) {
			data := makeData(tt.payloadSize)
			frame, err := WrapWebSocket(data)
			if err != nil {
				t.Fatalf("WrapWebSocket: %v", err)
			}
			overhead := len(frame) - tt.payloadSize
			if overhead != tt.expectedOv {
				t.Errorf("overhead = %d, want %d", overhead, tt.expectedOv)
			}
		})
	}
}

// --- Benchmarks ---

func BenchmarkWrapWebSocket(b *testing.B) {
	data := makeData(1420)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = WrapWebSocket(data)
	}
}

func BenchmarkUnwrapWebSocket(b *testing.B) {
	frame, _ := WrapWebSocket(makeData(1420))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Need fresh frame because UnwrapWebSocket mutates in-place.
		fresh := make([]byte, len(frame))
		copy(fresh, frame)
		_, _ = UnwrapWebSocket(fresh)
	}
}
