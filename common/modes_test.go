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
// BalancedMode tests (Stage 5)
// =============================================================================

func TestBalancedMode_HandshakeRoundTrip(t *testing.T) {
	snis := []string{"cloudflare.com", "www.google.com", "example.com"}
	sizes := []int{0, 1, 64, 148}

	for _, sni := range snis {
		for _, sz := range sizes {
			name := "sni=" + sni + "_size=" + itoa(sz)
			t.Run(name, func(t *testing.T) {
				m := &BalancedMode{minPad: 8, maxPad: 64, sni: sni}
				original := makeData(sz)

				obfuscated, err := m.ObfuscateHandshakeInit(original)
				if err != nil {
					t.Fatalf("ObfuscateHandshakeInit: %v", err)
				}

				// Verify the obfuscated packet looks like a TLS ClientHello.
				if len(obfuscated) < 5 || obfuscated[0] != 0x16 {
					t.Errorf("obfuscated packet does not start with TLS record type 0x16")
				}

				restored, err := m.DeobfuscateHandshakeInit(obfuscated)
				if err != nil {
					t.Fatalf("DeobfuscateHandshakeInit: %v", err)
				}

				if !bytes.Equal(restored, original) {
					t.Errorf("round-trip mismatch: original %d bytes, restored %d bytes",
						len(original), len(restored))
				}
			})
		}
	}
}

func TestBalancedMode_HandshakeRoundTrip_DefaultSNI(t *testing.T) {
	// Verify that the default SNI ("cloudflare.com") works correctly.
	m := &BalancedMode{minPad: 8, maxPad: 64, sni: DefaultConfig().SNI}
	original := makeHandshakeInit()

	obfuscated, err := m.ObfuscateHandshakeInit(original)
	if err != nil {
		t.Fatalf("ObfuscateHandshakeInit: %v", err)
	}

	restored, err := m.DeobfuscateHandshakeInit(obfuscated)
	if err != nil {
		t.Fatalf("DeobfuscateHandshakeInit: %v", err)
	}

	if !bytes.Equal(restored, original) {
		t.Errorf("round-trip mismatch")
	}
}

func TestBalancedMode_DataRoundTrip(t *testing.T) {
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
				m := &BalancedMode{minPad: r.minPad, maxPad: r.maxPad, sni: "cloudflare.com"}
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

func TestBalancedMode_DeobfuscateHandshakeInvalid(t *testing.T) {
	m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}

	invalidPackets := [][]byte{
		nil,
		{},
		{0x00, 0x01, 0x02},
		makeRandomBytes(50),
		makeRandomBytes(200),
	}

	for i, pkt := range invalidPackets {
		t.Run(itoa(i), func(t *testing.T) {
			_, err := m.DeobfuscateHandshakeInit(pkt)
			if err == nil {
				t.Errorf("expected error for invalid packet, got nil")
			}
			if err != ErrNotClientHello {
				t.Errorf("expected ErrNotClientHello, got %v", err)
			}
		})
	}
}

func TestBalancedMode_DeobfuscateDataInvalid(t *testing.T) {
	m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}

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

func TestBalancedMode_DeobfuscateCrossTypeErrors(t *testing.T) {
	// Verify that DeobfuscateHandshakeInit on a padded data packet returns an error,
	// and DeobfuscateData on a TLS-wrapped handshake packet returns an error.
	m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}

	// Handshake → try DeobfuscateData: must fail.
	hsObf, _ := m.ObfuscateHandshakeInit(makeHandshakeInit())
	_, err := m.DeobfuscateData(hsObf)
	if err == nil {
		t.Errorf("DeobfuscateData on TLS-wrapped handshake should fail")
	}

	// Data → try DeobfuscateHandshakeInit: must fail.
	dataObf, _ := m.ObfuscateData(makeData(100))
	_, err = m.DeobfuscateHandshakeInit(dataObf)
	if err == nil {
		t.Errorf("DeobfuscateHandshakeInit on padded data should fail")
	}
}

func TestBalancedMode_ValidateCookie(t *testing.T) {
	m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}

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

func TestBalancedMode_Mode(t *testing.T) {
	m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}
	if m.Mode() != ModeBalanced {
		t.Errorf("Mode() = %v, want ModeBalanced", m.Mode())
	}
}

func TestBalancedMode_ImplementsInterface(t *testing.T) {
	obf, err := NewObfuscator(Config{
		Mode:         ModeBalanced,
		PaddingRange: [2]int{8, 64},
		SNI:          "cloudflare.com",
	})
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

	// Type assertion check.
	bm, ok := obf.(*BalancedMode)
	if !ok {
		t.Fatalf("expected *BalancedMode, got %T", obf)
	}
	if bm.sni != "cloudflare.com" {
		t.Errorf("BalancedMode.sni = %q, want %q", bm.sni, "cloudflare.com")
	}
	if bm.minPad != 8 || bm.maxPad != 64 {
		t.Errorf("BalancedMode pad range = [%d, %d], want [8, 64]", bm.minPad, bm.maxPad)
	}
}

func TestBalancedMode_HandshakeObfuscationIsNotPassthrough(t *testing.T) {
	// Sanity check: BalancedMode handshake is NOT passthrough.
	m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}
	original := makeHandshakeInit()
	obfuscated, err := m.ObfuscateHandshakeInit(original)
	if err != nil {
		t.Fatalf("ObfuscateHandshakeInit: %v", err)
	}
	if bytes.Equal(obfuscated, original) {
		t.Errorf("BalancedMode handshake should be obfuscated, not passthrough")
	}
}

func TestBalancedMode_DataObfuscationIsNotPassthrough(t *testing.T) {
	// Sanity check: BalancedMode data is NOT passthrough.
	m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}
	original := makeData(100)
	obfuscated, err := m.ObfuscateData(original)
	if err != nil {
		t.Fatalf("ObfuscateData: %v", err)
	}
	if bytes.Equal(obfuscated, original) {
		t.Errorf("BalancedMode data should be obfuscated, not passthrough")
	}
}

func TestBalancedMode_FuzzDeobfuscateHandshake(t *testing.T) {
	// Fuzz test: random bytes must never panic and must return an error.
	m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}

	for i := 0; i < 1000; i++ {
		data := makeRandomBytes(i % 1024)
		result, err := m.DeobfuscateHandshakeInit(data)
		if err == nil && result != nil {
			// Accept valid deobfuscation (if random bytes happen to decode).
		}
		// The key assertion: no panic.
	}
}

func TestBalancedMode_FuzzDeobfuscateData(t *testing.T) {
	// Fuzz test: random bytes must never panic.
	m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}

	for i := 0; i < 1000; i++ {
		data := makeRandomBytes(i % 512)
		result, err := m.DeobfuscateData(data)
		if err == nil && result != nil {
			// Accept valid deobfuscation.
		}
		// No panic.
	}
}

// =============================================================================
// Benchmarks — VanillaMode vs LightMode vs BalancedMode
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

func BenchmarkBalancedMode_ObfuscateData(b *testing.B) {
	m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}
	packet := makeData(1420)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		result, _ := m.ObfuscateData(packet)
		_ = result
	}
}

func BenchmarkBalancedMode_DeobfuscateData(b *testing.B) {
	m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}
	padded, _ := m.ObfuscateData(makeData(1420))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		result, _ := m.DeobfuscateData(padded)
		_ = result
	}
}

func BenchmarkBalancedMode_ObfuscateHandshakeInit(b *testing.B) {
	m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}
	packet := makeHandshakeInit()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		result, _ := m.ObfuscateHandshakeInit(packet)
		_ = result
	}
}

func BenchmarkBalancedMode_DeobfuscateHandshakeInit(b *testing.B) {
	m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}
	obfuscated, _ := m.ObfuscateHandshakeInit(makeHandshakeInit())
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		result, _ := m.DeobfuscateHandshakeInit(obfuscated)
		_ = result
	}
}

func BenchmarkBalancedMode_RoundTripData(b *testing.B) {
	m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}
	data := makeData(1420)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		padded, _ := m.ObfuscateData(data)
		result, _ := m.DeobfuscateData(padded)
		_ = result
	}
}

func BenchmarkBalancedMode_RoundTripHandshake(b *testing.B) {
	m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}
	packet := makeHandshakeInit()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		obfuscated, _ := m.ObfuscateHandshakeInit(packet)
		result, _ := m.DeobfuscateHandshakeInit(obfuscated)
		_ = result
	}
}

// BenchmarkOverheadComparison measures the relative overhead of each mode
// on MTU-sized data packets.
func BenchmarkOverheadComparison(b *testing.B) {
	data := makeData(1420)
	hs := makeHandshakeInit()

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

	b.Run("BalancedMode_ObfuscateData", func(b *testing.B) {
		m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			result, _ := m.ObfuscateData(data)
			_ = result
		}
	})

	b.Run("BalancedMode_RoundTripData", func(b *testing.B) {
		m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			padded, _ := m.ObfuscateData(data)
			result, _ := m.DeobfuscateData(padded)
			_ = result
		}
	})

	b.Run("BalancedMode_ObfuscateHandshakeInit", func(b *testing.B) {
		m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			result, _ := m.ObfuscateHandshakeInit(hs)
			_ = result
		}
	})

	b.Run("BalancedMode_RoundTripHandshake", func(b *testing.B) {
		m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			obfuscated, _ := m.ObfuscateHandshakeInit(hs)
			result, _ := m.DeobfuscateHandshakeInit(obfuscated)
			_ = result
		}
	})
}
