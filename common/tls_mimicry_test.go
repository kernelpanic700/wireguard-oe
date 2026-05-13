package common

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
)

// makeHandshakeData creates a variable-length payload that looks like
// a WireGuard handshake initiation (starts with 0x01).
func makeHandshakeData(size int) []byte {
	data := make([]byte, size)
	data[0] = 0x01 // WG message type: handshake initiation
	for i := 1; i < size; i++ {
		data[i] = byte(i % 251)
	}
	return data
}

func TestObfuscateClientHello_Basic(t *testing.T) {
	sizes := []int{0, 1, 148, 256}
	snis := []string{"", "cloudflare.com", "www.google.com", "example.com"}

	for _, sz := range sizes {
		for _, sni := range snis {
			name := "size=" + itoa(sz) + "_sni=" + sni
			t.Run(name, func(t *testing.T) {
				original := makeHandshakeData(sz)
				wrapped, err := ObfuscateClientHello(original, sni)
				if err != nil {
					t.Fatalf("ObfuscateClientHello: %v", err)
				}

				// Basic structural checks.
				if len(wrapped) < 43 {
					t.Errorf("result too small: %d bytes", len(wrapped))
				}
				// Must start with TLS handshake record.
				if wrapped[0] != 0x16 {
					t.Errorf("first byte = 0x%02X, want 0x16", wrapped[0])
				}
				// TLS version must be 0x0303 at offset 1.
				v := uint16(wrapped[1])<<8 | uint16(wrapped[2])
				if v != 0x0303 {
					t.Errorf("version = 0x%04X, want 0x0303", v)
				}
				// Record length must match.
				recordLen := int(uint16(wrapped[3])<<8 | uint16(wrapped[4]))
				if 5+recordLen != len(wrapped) {
					t.Errorf("recordLen=%d, 5+recordLen=%d, actual len=%d",
						recordLen, 5+recordLen, len(wrapped))
				}
				// Handshake type must be 0x01.
				if wrapped[5] != 0x01 {
					t.Errorf("handshake type = 0x%02X, want 0x01", wrapped[5])
				}
			})
		}
	}
}

func TestObfuscateClientHello_Errors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		sni     string
		wantErr bool
	}{
		{"too large data", make([]byte, 65536-200+1), "", true},
		{"sni too long", makeHandshakeData(148), makeLongString(256), true},
		{"nil data ok", nil, "cloudflare.com", false},
		{"empty data ok", []byte{}, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ObfuscateClientHello(tt.data, tt.sni)
			if (err != nil) != tt.wantErr {
				t.Errorf("ObfuscateClientHello() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestDeobfuscateClientHello_Invalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short (1 byte)", []byte{0x16}},
		{"too short (5 bytes)", []byte{0x16, 0x03, 0x03, 0x00, 0x00}},
		{"wrong content type", corruptRecordType()},
		{"wrong TLS version", corruptTLSVersion()},
		{"wrong handshake type", corruptHandshakeType()},
		{"wrong client version", corruptClientVersion()},
		{"no GREASE extension", noGreasePacket()},
		{"wrong magic in GREASE", wrongMagicInGrease()},
		{"truncated GREASE", truncatedGrease()},
		{"random 150 bytes", makeRandomTLSBytes(150)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DeobfuscateClientHello(tt.data)
			if err == nil {
				t.Errorf("expected error, got result=%x", result)
			}
			if err != ErrNotClientHello {
				t.Errorf("expected ErrNotClientHello, got %v", err)
			}
		})
	}
}

func TestObfuscateDeobfuscate_RoundTrip(t *testing.T) {
	sizes := []int{0, 1, 64, 128, 148, 256, 512}
	snis := []string{"cloudflare.com", "www.google.com", "", "a.b.c.example.co.uk"}

	for _, sz := range sizes {
		for _, sni := range snis {
			name := "size=" + itoa(sz) + "_sni=" + sni
			t.Run(name, func(t *testing.T) {
				original := makeHandshakeData(sz)
				wrapped, err := ObfuscateClientHello(original, sni)
				if err != nil {
					t.Fatalf("ObfuscateClientHello: %v", err)
				}
				extracted, err := DeobfuscateClientHello(wrapped)
				if err != nil {
					t.Fatalf("DeobfuscateClientHello: %v", err)
				}
				if !bytes.Equal(extracted, original) {
					t.Errorf("round-trip mismatch: original %d bytes, extracted %d bytes",
						len(original), len(extracted))
				}
			})
		}
	}
}

func TestDeobfuscateClientHello_SessionIDVariation(t *testing.T) {
	// Generate 100 packets with random data; each must round-trip.
	for i := 0; i < 100; i++ {
		dataLen := i % 256 // 0–255
		original := makeHandshakeData(dataLen)
		sni := "test.example.com"

		wrapped, err := ObfuscateClientHello(original, sni)
		if err != nil {
			t.Fatalf("iter %d: ObfuscateClientHello: %v", i, err)
		}
		extracted, err := DeobfuscateClientHello(wrapped)
		if err != nil {
			// Dump packet for debugging.
			t.Fatalf("iter %d (dataLen=%d, wrappedLen=%d): DeobfuscateClientHello: %v\nwrapped hex: %x",
				i, dataLen, len(wrapped), err, wrapped[:min(len(wrapped), 80)])
		}
		if !bytes.Equal(extracted, original) {
			t.Fatalf("iter %d: round-trip mismatch", i)
		}
	}
}

func FuzzDeobfuscateClientHello(f *testing.F) {
	// Seed corpus with valid packets.
	for _, sz := range []int{0, 1, 148, 256} {
		for _, sni := range []string{"cloudflare.com", "www.google.com"} {
			data := makeHandshakeData(sz)
			wrapped, _ := ObfuscateClientHello(data, sni)
			f.Add(wrapped)
		}
	}
	// Edge cases.
	f.Add([]byte{})
	f.Add([]byte{0x16})
	f.Add([]byte{0x16, 0x03, 0x03})
	f.Add(makeRandomTLSBytes(100))
	f.Add(makeRandomTLSBytes(500))

	f.Fuzz(func(t *testing.T, data []byte) {
		// DeobfuscateClientHello must never panic.
		result, err := DeobfuscateClientHello(data)
		if err != nil {
			if err != ErrNotClientHello {
				t.Errorf("unexpected error type: %v", err)
			}
			return
		}
		// If no error, result must be a sub-slice of input (zero alloc).
		if len(result) > 0 && len(data) > 0 {
			// Pointer bounds check.
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

func BenchmarkObfuscateClientHello(b *testing.B) {
	data := makeHandshakeData(148)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ObfuscateClientHello(data, "cloudflare.com")
	}
}

func BenchmarkDeobfuscateClientHello(b *testing.B) {
	wrapped, _ := ObfuscateClientHello(makeHandshakeData(148), "cloudflare.com")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DeobfuscateClientHello(wrapped)
	}
}

func BenchmarkClientHello_RoundTrip(b *testing.B) {
	data := makeHandshakeData(148)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wrapped, _ := ObfuscateClientHello(data, "cloudflare.com")
		_, _ = DeobfuscateClientHello(wrapped)
	}
}

// --- Helpers ---

func corruptRecordType() []byte {
	wrapped, _ := ObfuscateClientHello(makeHandshakeData(148), "cloudflare.com")
	wrapped[0] = 0x17 // Application Data
	return wrapped
}

func corruptTLSVersion() []byte {
	wrapped, _ := ObfuscateClientHello(makeHandshakeData(148), "cloudflare.com")
	wrapped[1] = 0x03
	wrapped[2] = 0x01 // TLS 1.0
	return wrapped
}

func corruptHandshakeType() []byte {
	wrapped, _ := ObfuscateClientHello(makeHandshakeData(148), "cloudflare.com")
	wrapped[5] = 0x02 // ServerHello
	return wrapped
}

func corruptClientVersion() []byte {
	wrapped, _ := ObfuscateClientHello(makeHandshakeData(148), "cloudflare.com")
	vOff := 5 + 4 // after record + handshake header
	wrapped[vOff] = 0x03
	wrapped[vOff+1] = 0x02 // TLS 1.1
	return wrapped
}

func noGreasePacket() []byte {
	// Build a minimal valid TLS-looking packet without GREASE.
	buf := []byte{
		0x16,       // ContentType: Handshake
		0x03, 0x03, // Version: TLS 1.2
		0x00, 0x3B, // Record length
		0x01,             // HandshakeType: ClientHello
		0x00, 0x00, 0x36, // HsLen
		0x03, 0x03, // Client version
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // random (32 bytes)
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x00,       // session ID len
		0x00, 0x02, // cipher suites (1 suite)
		0x00, 0x2F, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x01, 0x00, // compression
		0x00, 0x00, // extensions length = 0
	}
	return buf
}

func wrongMagicInGrease() []byte {
	wrapped, _ := ObfuscateClientHello(makeHandshakeData(20), "cloudflare.com")
	// Find GREASE and corrupt its magic.
	for i := 0; i < len(wrapped)-4; i++ {
		if uint16(wrapped[i])<<8|uint16(wrapped[i+1]) == greaseExtension {
			wrapped[i+4] = 0x00
			wrapped[i+5] = 0x00
			return wrapped
		}
	}
	return wrapped
}

func truncatedGrease() []byte {
	wrapped, _ := ObfuscateClientHello(makeHandshakeData(50), "cloudflare.com")
	return wrapped[:len(wrapped)-1]
}

func makeRandomTLSBytes(n int) []byte {
	buf := make([]byte, n)
	for i := range buf {
		r, _ := rand.Int(rand.Reader, big.NewInt(256))
		buf[i] = byte(r.Int64())
	}
	return buf
}

func makeLongString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}