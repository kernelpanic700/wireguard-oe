package common

import (
	"bytes"
	"testing"
)

// Helper functions to create realistic WireGuard test packets.
// These simulate actual WG packet structure to verify VanillaMode
// passthrough behavior on real-world data shapes.

// makeHandshakeInit creates a fake WG handshake initiation packet.
// WireGuard handshake init: type(1) + reserved(3) + sender(4) +
// ephemeral(32) + static(32) + timestamp(12) + mac1(16) + mac2(16) = 148 bytes.
func makeHandshakeInit() []byte {
	pkt := make([]byte, 148)
	pkt[0] = 0x01 // message type: handshake initiation
	for i := 1; i < len(pkt); i++ {
		pkt[i] = byte(i % 256)
	}
	return pkt
}

// makeDataPacket creates a fake WG transport data packet.
// WireGuard data: type(4) + receiver(4) + counter(8) + encrypted payload.
func makeDataPacket() []byte {
	pkt := make([]byte, 80)
	pkt[0] = 0x04 // message type: data
	for i := 1; i < len(pkt); i++ {
		pkt[i] = byte(i % 256)
	}
	return pkt
}

// =============================================================================
// VanillaMode tests (Stage 2)
// =============================================================================

// TestVanillaMode_Passthrough verifies that all VanillaMode methods
// return the input bytes unchanged (bit-to-bit identical).
func TestVanillaMode_Passthrough(t *testing.T) {
	v := &VanillaMode{}

	packets := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"single byte", {0x00}},
		{"three bytes", {0x01, 0x02, 0x03}},
		{"handshake init", makeHandshakeInit()},
		{"data packet", makeDataPacket()},
	}

	for _, pkt := range packets {
		t.Run("ObfuscateHandshakeInit/"+pkt.name, func(t *testing.T) {
			result, err := v.ObfuscateHandshakeInit(pkt.data)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !bytes.Equal(result, pkt.data) {
				t.Errorf("packet was modified")
			}
		})

		t.Run("DeobfuscateHandshakeInit/"+pkt.name, func(t *testing.T) {
			result, err := v.DeobfuscateHandshakeInit(pkt.data)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !bytes.Equal(result, pkt.data) {
				t.Errorf("packet was modified")
			}
		})

		t.Run("ObfuscateData/"+pkt.name, func(t *testing.T) {
			result, err := v.ObfuscateData(pkt.data)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !bytes.Equal(result, pkt.data) {
				t.Errorf("packet was modified")
			}
		})

		t.Run("DeobfuscateData/"+pkt.name, func(t *testing.T) {
			result, err := v.DeobfuscateData(pkt.data)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !bytes.Equal(result, pkt.data) {
				t.Errorf("packet was modified")
			}
		})
	}
}

func TestVanillaMode_ValidateCookie(t *testing.T) {
	v := &VanillaMode{}

	tests := []struct {
		name   string
		packet []byte
		want   bool
	}{
		{"nil packet", nil, true},
		{"empty packet", []byte{}, true},
		{"random bytes", []byte{0xde, 0xad, 0xbe, 0xef}, true},
		{"handshake init", makeHandshakeInit(), true},
		{"data packet", makeDataPacket(), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := v.ValidateCookie(tt.packet); got != tt.want {
				t.Errorf("ValidateCookie() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVanillaMode_Mode(t *testing.T) {
	v := &VanillaMode{}
	if v.Mode() != ModeVanilla {
		t.Errorf("Mode() = %v, want ModeVanilla", v.Mode())
	}
}

func TestVanillaMode_ImplementsInterface(t *testing.T) {
	obf, err := NewObfuscator(Config{Mode: ModeVanilla})
	if err != nil {
		t.Fatalf("NewObfuscator() error = %v", err)
	}
	if obf == nil {
		t.Fatal("expected non-nil Obfuscator")
	}

	// Verify all methods are accessible and don't panic
	methods := []struct {
		name string
		fn   func()
	}{
		{"ObfuscateHandshakeInit", func() { _, _ = obf.ObfuscateHandshakeInit([]byte{1}) }},
		{"DeobfuscateHandshakeInit", func() { _, _ = obf.DeobfuscateHandshakeInit([]byte{1}) }},
		{"ObfuscateData", func() { _, _ = obf.ObfuscateData([]byte{1}) }},
		{"DeobfuscateData", func() { _, _ = obf.DeobfuscateData([]byte{1}) }},
		{"ValidateCookie", func() { _ = obf.ValidateCookie(nil) }},
		{"Mode", func() { _ = obf.Mode() }},
	}
	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			m.fn()
		})
	}
}

// =============================================================================
// LightMode tests (Stage 3)
// =============================================================================

func TestLightMode_HandshakePassthrough(t *testing.T) {
	m := &LightMode{minPad: 8, maxPad: 64}

	packets := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"single byte", {0x05}},
		{"handshake init", makeHandshakeInit()},
	}

	for _, pkt := range packets {
		t.Run("ObfuscateHandshakeInit/"+pkt.name, func(t *testing.T) {
			result, err := m.ObfuscateHandshakeInit(pkt.data)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !bytes.Equal(result, pkt.data) {
				t.Errorf("handshake init packet was modified")
			}
		})

		t.Run("DeobfuscateHandshakeInit/"+pkt.name, func(t *testing.T) {
			result, err := m.DeobfuscateHandshakeInit(pkt.data)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !bytes.Equal(result, pkt.data) {
				t.Errorf("handshake init packet was modified")
			}
		})
	}
}

func TestLightMode_DataRoundTrip(t *testing.T) {
	sizes := []int{0, 1, 64, 128, 512, 1420}
	ranges := []struct {
		minPad, maxPad int
	}{
		{0, 0},
		{4, 32},
		{8, 64},
		{16, 128},
		{0, 255},
	}

	for _, sz := range sizes {
		for _, r := range ranges {
			name := "size=" + itoa(sz) + "_pad=" + itoa(r.minPad) + "-" + itoa(r.maxPad)
			t.Run(name, func(t *testing.T) {
				m := &LightMode{minPad: r.minPad, maxPad: r.maxPad}
				original := makeData(sz)

				obfuscated, err := m.ObfuscateData(original)
				if err != nil {
					t.Fatalf("ObfuscateData: %v", err)
				}

				restored, err := m.DeobfuscateData(obfuscated)
				if err != nil {
					t.Fatalf("DeobfuscateData: %v", err)
				}

				if !bytes.Equal(restored, original) {
					t.Errorf("round-trip mismatch: original %d bytes, restored %d bytes",
						len(original), len(restored))
				}
			})
		}
	}
}

func TestLightMode_DeobfuscateInvalid(t *testing.T) {
	m := &LightMode{minPad: 8, maxPad: 64}

	invalidPackets := [][]byte{
		nil,
		{},
		{0x00},
		makeRandomBytes(20),
	}

	for i, pkt := range invalidPackets {
		t.Run(itoa(i), func(t *testing.T) {
			_, err := m.DeobfuscateData(pkt)
			if err == nil {
				t.Errorf("expected error for invalid packet, got nil")
			}
			if err != ErrInvalidPadding {
				t.Errorf("expected ErrInvalidPadding, got %v", err)
			}
		})
	}
}

func TestLightMode_ValidateCookie(t *testing.T) {
	m := &LightMode{minPad: 8, maxPad: 64}

	tests := [][]byte{
		nil,
		{},
		{0xde, 0xad, 0xbe, 0xef},
		makeHandshakeInit(),
	}

	for _, pkt := range tests {
		if !m.ValidateCookie(pkt) {
			t.Errorf("ValidateCookie(%v) = false, want true", pkt)
		}
	}
}

func TestLightMode_Mode(t *testing.T) {
	m := &LightMode{minPad: 8, maxPad: 64}
	if m.Mode() != ModeLight {
		t.Errorf("Mode() = %v, want ModeLight", m.Mode())
	}
}

func TestLightMode_ImplementsInterface(t *testing.T) {
	obf, err := NewObfuscator(Config{Mode: ModeLight, PaddingRange: [2]int{8, 64}})
	if err != nil {
		t.Fatalf("NewObfuscator() error = %v", err)
	}
	if obf == nil {
		t.Fatal("expected non-nil Obfuscator")
	}

	// Verify all methods are accessible and don't panic
	methods := []struct {
		name string
		fn   func()
	}{
		{"ObfuscateHandshakeInit", func() { _, _ = obf.ObfuscateHandshakeInit([]byte{1}) }},
		{"DeobfuscateHandshakeInit", func() { _, _ = obf.DeobfuscateHandshakeInit([]byte{1}) }},
		{"ObfuscateData", func() { _, _ = obf.ObfuscateData([]byte{1}) }},
		{"DeobfuscateData", func() { _, _ = obf.DeobfuscateData([]byte{1}) }},
		{"ValidateCookie", func() { _ = obf.ValidateCookie(nil) }},
		{"Mode", func() { _ = obf.Mode() }},
	}
	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			m.fn()
		})
	}
}

// =============================================================================
// Benchmarks — VanillaMode vs LightMode
// =============================================================================

func BenchmarkVanillaMode_ObfuscateData(b *testing.B) {
	v := &VanillaMode{}
	packet := makeDataPacket()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = v.ObfuscateData(packet)
	}
}

func BenchmarkVanillaMode_ObfuscateHandshakeInit(b *testing.B) {
	v := &VanillaMode{}
	packet := makeHandshakeInit()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = v.ObfuscateHandshakeInit(packet)
	}
}

func BenchmarkLightMode_ObfuscateData(b *testing.B) {
	m := &LightMode{minPad: 8, maxPad: 64}
	packet := makeData(1420)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		result, _ := m.ObfuscateData(packet)
		_ = result
	}
}

func BenchmarkLightMode_DeobfuscateData(b *testing.B) {
	m := &LightMode{minPad: 8, maxPad: 64}
	padded, _ := m.ObfuscateData(makeData(1420))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		result, _ := m.DeobfuscateData(padded)
		_ = result
	}
}

func BenchmarkLightMode_ObfuscateHandshakeInit(b *testing.B) {
	m := &LightMode{minPad: 8, maxPad: 64}
	packet := makeHandshakeInit()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.ObfuscateHandshakeInit(packet)
	}
}

// BenchmarkOverheadComparison measures the relative overhead of LightMode
// vs VanillaMode on MTU-sized data packets.
func BenchmarkOverheadComparison(b *testing.B) {
	data := makeData(1420)

	b.Run("VanillaMode_ObfuscateData", func(b *testing.B) {
		v := &VanillaMode{}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			result, _ := v.ObfuscateData(data)
			_ = result
		}
	})

	b.Run("LightMode_ObfuscateData", func(b *testing.B) {
		m := &LightMode{minPad: 8, maxPad: 64}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			result, _ := m.ObfuscateData(data)
			_ = result
		}
	})

	b.Run("LightMode_RoundTrip", func(b *testing.B) {
		m := &LightMode{minPad: 8, maxPad: 64}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			padded, _ := m.ObfuscateData(data)
			result, _ := m.DeobfuscateData(padded)
			_ = result
		}
	})
}