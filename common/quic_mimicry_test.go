package common

import (
	"bytes"
	"testing"
)

func TestObfuscateQUICShortHeader_Basic(t *testing.T) {
	sizes := []int{0, 1, 64, 128, 1420}

	for _, sz := range sizes {
		t.Run(itoa(sz), func(t *testing.T) {
			original := makeData(sz)
			wrapped, err := ObfuscateQUICShortHeader(original)
			if err != nil {
				t.Fatalf("ObfuscateQUICShortHeader: %v", err)
			}

			// Basic structural checks.
			if len(wrapped) < minQUICShortHeader+len(original) {
				t.Errorf("result too small: %d < %d", len(wrapped), minQUICShortHeader+len(original))
			}
			// First byte must be 0x40.
			if wrapped[0] != 0x40 {
				t.Errorf("first byte = 0x%02X, want 0x40", wrapped[0])
			}
			// Destination Connection ID must match.
			if string(wrapped[1:9]) != quicDestConnID {
				t.Errorf("DCID mismatch")
			}
			// Packet number length must be 1–3.
			pktNumLen := len(wrapped) - 9 - len(original)
			if pktNumLen < 1 || pktNumLen > 3 {
				t.Errorf("packet number len = %d, want 1–3", pktNumLen)
			}
		})
	}
}

func TestDeobfuscateQUICShortHeader_Invalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short (5 bytes)", []byte{0x40, 0x01, 0x02, 0x03, 0x04}},
		{"too short (9 bytes)", []byte{0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
		{"wrong first byte", corruptQUICFirstByte()},
		{"wrong DCID", corruptQUICDCID()},
		{"random 50 bytes", makeRandomBytes(50)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DeobfuscateQUICShortHeader(tt.data)
			if err == nil {
				t.Errorf("expected error, got result=%x", result)
			}
			if err != ErrNotQUICShortHeader {
				t.Errorf("expected ErrNotQUICShortHeader, got %v", err)
			}
		})
	}
}

func TestQUICShortHeader_RoundTrip(t *testing.T) {
	sizes := []int{0, 1, 64, 128, 512, 1420}

	for _, sz := range sizes {
		t.Run(itoa(sz), func(t *testing.T) {
			original := makeData(sz)
			wrapped, err := ObfuscateQUICShortHeader(original)
			if err != nil {
				t.Fatalf("ObfuscateQUICShortHeader: %v", err)
			}
			extracted, err := DeobfuscateQUICShortHeader(wrapped)
			if err != nil {
				t.Fatalf("DeobfuscateQUICShortHeader: %v", err)
			}
			if !bytes.Equal(extracted, original) {
				t.Errorf("round-trip mismatch: original %d bytes, extracted %d bytes",
					len(original), len(extracted))
			}
		})
	}
}

func FuzzDeobfuscateQUICShortHeader(f *testing.F) {
	// Seed corpus.
	for _, sz := range []int{0, 1, 64, 148, 1420} {
		data := makeData(sz)
		wrapped, _ := ObfuscateQUICShortHeader(data)
		f.Add(wrapped)
	}
	f.Add([]byte{})
	f.Add([]byte{0x40})
	f.Add(makeRandomBytes(50))

	f.Fuzz(func(t *testing.T, data []byte) {
		result, err := DeobfuscateQUICShortHeader(data)
		if err != nil {
			if err != ErrNotQUICShortHeader {
				t.Errorf("unexpected error type: %v", err)
			}
			return
		}
		// Result must be a sub-slice (zero alloc).
		if len(result) > 0 && len(data) > 0 {
			if &result[0:1][0] < &data[0:1][0] || &result[len(result)-1:][0] > &data[len(data)-1:][0] {
				t.Errorf("result is not a sub-slice of input")
			}
		}
		if len(result) >= len(data) {
			t.Errorf("result len %d >= input len %d", len(result), len(data))
		}
	})
}

// --- Benchmarks ---

func BenchmarkObfuscateQUICShortHeader(b *testing.B) {
	data := makeData(1420)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ObfuscateQUICShortHeader(data)
	}
}

func BenchmarkDeobfuscateQUICShortHeader(b *testing.B) {
	wrapped, _ := ObfuscateQUICShortHeader(makeData(1420))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DeobfuscateQUICShortHeader(wrapped)
	}
}

// --- Helpers ---

func corruptQUICFirstByte() []byte {
	wrapped, _ := ObfuscateQUICShortHeader(makeData(64))
	wrapped[0] = 0x00
	return wrapped
}

func corruptQUICDCID() []byte {
	wrapped, _ := ObfuscateQUICShortHeader(makeData(64))
	wrapped[1] = 0xFF
	return wrapped
}
