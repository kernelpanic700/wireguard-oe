package common

import (
	"bytes"
	"math/rand"
	"testing"
)

// makeData creates a deterministic payload of the given size.
func makeData(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 251) // avoid 0xD4 0x1F collisions where possible
	}
	return data
}

func TestAddPadding_Basic(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		minPad  int
		maxPad  int
		wantErr bool
	}{
		{"empty data, zero padding", []byte{}, 0, 0, false},
		{"single byte, zero padding", []byte{0x01}, 0, 0, false},
		{"handshake-sized, range 8-64", makeData(148), 8, 64, false},
		{"mtu-sized, range 0-255", makeData(1420), 0, 255, false},
		{"negative minPad", []byte{1}, -1, 10, true},
		{"minPad > maxPad", []byte{1}, 10, 5, true},
		{"maxPad > 255", []byte{1}, 0, 256, true},
		{"nil data, zero padding", nil, 0, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := AddPadding(tt.data, tt.minPad, tt.maxPad)
			if (err != nil) != tt.wantErr {
				t.Fatalf("AddPadding() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			// Verify the structure: result must be longer than input by at least fixedOverhead.
			if len(result) < len(tt.data)+fixedOverhead {
				t.Errorf("result too short: %d < %d+%d", len(result), len(tt.data), fixedOverhead)
			}

			prefLen := int(result[len(result)-1])
			padLen := int(result[len(result)-2])

			if prefLen < 0 || prefLen > maxPrefix {
				t.Errorf("prefLen = %d, want 0–%d", prefLen, maxPrefix)
			}
			if padLen < tt.minPad || padLen > tt.maxPad {
				t.Errorf("padLen = %d, want [%d, %d]", padLen, tt.minPad, tt.maxPad)
			}

			expectedLen := len(tt.data) + prefLen + padLen + fixedOverhead
			if len(result) != expectedLen {
				t.Errorf("len(result) = %d, expected %d", len(result), expectedLen)
			}

			// Check magic at correct position.
			magicPos := len(result) - 2 - padLen - 2
			if result[magicPos] != magic0 || result[magicPos+1] != magic1 {
				t.Errorf("magic bytes mismatch at pos %d: got [%02x %02x], want [%02x %02x]",
					magicPos, result[magicPos], result[magicPos+1], magic0, magic1)
			}

			// Verify original data is preserved starting at prefLen.
			if !bytes.Equal(result[prefLen:prefLen+len(tt.data)], tt.data) {
				t.Errorf("original data not preserved")
			}
		})
	}
}

func TestRemovePadding_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		errWant error
	}{
		{"nil", nil, ErrInvalidPadding},
		{"empty", []byte{}, ErrInvalidPadding},
		{"one byte", []byte{0x00}, ErrInvalidPadding},
		{"two bytes", []byte{0x01, 0x02}, ErrInvalidPadding},
		{"three bytes", []byte{0x01, 0x02, 0x03}, ErrInvalidPadding},
		{"prefLen > 16", []byte{0xD4, 0x1F, 0x00, 0x00, 0x00, 0xFF}, ErrInvalidPadding},
		{"truncated — not enough for claimed lengths", makeTruncatedPacket(), ErrInvalidPadding},
		{"wrong magic 1", makeWrongMagicPacket(0xAA, 0x1F), ErrInvalidPadding},
		{"wrong magic 2", makeWrongMagicPacket(0xD4, 0xFE), ErrInvalidPadding},
		{"both magic wrong", makeWrongMagicPacket(0x00, 0x00), ErrInvalidPadding},
		{"random 40 bytes", makeRandomBytes(40), ErrInvalidPadding},
		{"correct format — should succeed", nil, nil}, // special marker for success
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.data == nil && tt.errWant == nil {
				// Special case: generate valid packet and ensure it succeeds.
				testData := makeData(100)
				padded, err := AddPadding(testData, 0, 16)
				if err != nil {
					t.Fatalf("AddPadding failed: %v", err)
				}
				result, err := RemovePadding(padded)
				if err != nil {
					t.Errorf("RemovePadding returned error on valid packet: %v", err)
				}
				if !bytes.Equal(result, testData) {
					t.Errorf("round-trip failed")
				}
				return
			}

			_, err := RemovePadding(tt.data)
			if err != tt.errWant {
				t.Errorf("RemovePadding() error = %v, want %v", err, tt.errWant)
			}
		})
	}
}

func TestAddRemove_RoundTrip(t *testing.T) {
	sizes := []int{0, 1, 64, 128, 512, 1420}
	ranges := []struct {
		minPad, maxPad int
	}{
		{0, 0},
		{0, 16},
		{4, 32},
		{8, 64},
		{16, 128},
		{0, 255},
	}

	for _, sz := range sizes {
		for _, r := range ranges {
			name := "size=" + itoa(sz) + "_pad=" + itoa(r.minPad) + "-" + itoa(r.maxPad)
			t.Run(name, func(t *testing.T) {
				original := makeData(sz)
				padded, err := AddPadding(original, r.minPad, r.maxPad)
				if err != nil {
					t.Fatalf("AddPadding: %v", err)
				}
				restored, err := RemovePadding(padded)
				if err != nil {
					t.Fatalf("RemovePadding: %v", err)
				}
				if !bytes.Equal(restored, original) {
					t.Errorf("round-trip mismatch: original %d bytes, restored %d bytes",
						len(original), len(restored))
				}
			})
		}
	}
}

func TestAddPadding_Distribution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping distribution test in short mode")
	}

	minPad, maxPad := 8, 64
	n := 2000
	buckets := maxPad - minPad + 1
	counts := make([]int, buckets)

	for i := 0; i < n; i++ {
		padded, err := AddPadding(makeData(128), minPad, maxPad)
		if err != nil {
			t.Fatalf("AddPadding: %v", err)
		}
		padLen := int(padded[len(padded)-2])
		if padLen < minPad || padLen > maxPad {
			t.Fatalf("padLen %d out of range [%d,%d]", padLen, minPad, maxPad)
		}
		counts[padLen-minPad]++
	}

	// Chi-square test for uniformity (simplified: no bucket should be 0 for large n).
	expectedPerBucket := float64(n) / float64(buckets)
	for i, c := range counts {
		if c == 0 {
			t.Errorf("bucket %d (padLen=%d) has zero hits — distribution suspicious", i, i+minPad)
		}
		// Allow up to 3x expected deviation in small samples (this is a smoke check,
		// not a rigorous statistical test).
		if float64(c) > expectedPerBucket*3 {
			t.Logf("warning: bucket %d (padLen=%d) count=%d, expected~%.1f", i, i+minPad, c, expectedPerBucket)
		}
	}
}

func FuzzRemovePadding(f *testing.F) {
	// Seed corpus with valid packets.
	for _, sz := range []int{0, 1, 64, 128, 512, 1420} {
		for _, r := range [][2]int{{0, 0}, {8, 64}, {0, 255}} {
			padded, _ := AddPadding(makeData(sz), r[0], r[1])
			f.Add(padded)
		}
	}
	// Seed with edge cases.
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xD4, 0x1F, 0x00, 0x00})
	f.Add(makeRandomBytes(64))

	f.Fuzz(func(t *testing.T, data []byte) {
		// RemovePadding must never panic.
		result, err := RemovePadding(data)
		if err != nil {
			// Must always be ErrInvalidPadding.
			if err != ErrInvalidPadding {
				t.Errorf("unexpected error type: %v", err)
			}
			return
		}
		// If no error, result must be a sub-slice of input (zero alloc guarantee).
		if len(result) > 0 && len(data) > 0 {
			// Check overlapping memory: result[0] address should be >= data[0] and < data[len(data)-1]+1.
			if &result[0:1][0] < &data[0:1][0] || &result[0:1][0] > &data[len(data)-1:][0] {
				t.Errorf("result is not a sub-slice of input")
			}
		}
		// Result length must be less than input length.
		if len(result) >= len(data) {
			t.Errorf("result len %d >= input len %d", len(result), len(data))
		}
	})
}

// --- Benchmarks ---

func BenchmarkAddPadding(b *testing.B) {
	data := makeData(1420)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = AddPadding(data, 8, 64)
	}
}

func BenchmarkRemovePadding(b *testing.B) {
	padded, _ := AddPadding(makeData(1420), 8, 64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = RemovePadding(padded)
	}
}

func BenchmarkAddPadding_LargeRange(b *testing.B) {
	data := makeData(1420)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = AddPadding(data, 0, 255)
	}
}

func BenchmarkRemovePadding_LargeRange(b *testing.B) {
	padded, _ := AddPadding(makeData(1420), 0, 255)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = RemovePadding(padded)
	}
}

// --- Helpers ---

func makeTruncatedPacket() []byte {
	// Claim prefLen=5, padLen=10 but provide too few bytes.
	buf := make([]byte, 10)
	buf[len(buf)-2] = 10 // padLen
	buf[len(buf)-1] = 5  // prefLen
	return buf
}

func makeWrongMagicPacket(m0, m1 byte) []byte {
	testData := makeData(32)
	padded, _ := AddPadding(testData, 4, 4)
	// Corrupt the magic bytes.
	prefLen := int(padded[len(padded)-1])
	padLen := int(padded[len(padded)-2])
	magicPos := len(padded) - 2 - padLen - 2
	padded[magicPos] = m0
	padded[magicPos+1] = m1
	_ = prefLen // suppress unused warning
	return padded
}

func makeRandomBytes(n int) []byte {
	buf := make([]byte, n)
	// Use math/rand for speed in tests; not cryptographic.
	r := rand.New(rand.NewSource(42))
	for i := range buf {
		buf[i] = byte(r.Intn(256))
	}
	return buf
}

// itoa is a simple int-to-string helper to avoid strconv import in test names.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(byte('0'+n%10)) + digits
		n /= 10
	}
	return digits
}