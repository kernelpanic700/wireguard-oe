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
	sizes := []int{0, 1, 64, 128, 148, 256, 512}
	snis := []string{"cloudflare.com", "www.google.com", "example.org"}

	for _, sz := range sizes {
		for _, sni := range snis {
			name := "size=" + itoa(sz) + "_sni=" + sni
			t.Run(name, func(t *testing.T) {
				m := &BalancedMode{minPad: 8, maxPad: 64, sni: sni}
				original := makeHandshakeData(sz)

				obfuscated, err := m.ObfuscateHandshakeInit(original)
				if err != nil {
					t.Fatalf("ObfuscateHandshakeInit: %v", err)
				}

				// Must look like TLS ClientHello.
				if len(obfuscated) < 43 {
					t.Errorf("result too small: %d bytes", len(obfuscated))
				}
				if obfuscated[0] != 0x16 {
					t.Errorf("first byte = 0x%02X, want 0x16", obfuscated[0])
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

func TestBalancedMode_HandshakeInvalid(t *testing.T) {
	m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}

	invalidPackets := [][]byte{
		nil,
		{},
		{0x16},
		makeRandomTLSBytes(100),
		noGreasePacket(),
	}

	for i, pkt := range invalidPackets {
		t.Run(itoa(i), func(t *testing.T) {
			_, err := m.DeobfuscateHandshakeInit(pkt)
			if err == nil {
				t.Errorf("expected error for invalid handshake packet, got nil")
			}
			if err != ErrNotClientHello {
				t.Errorf("expected ErrNotClientHello, got %v", err)
			}
		})
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
				m := &BalancedMode{minPad: r.minPad, maxPad: r.maxPad, sni: "test.com"}
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

func TestBalancedMode_DataInvalid(t *testing.T) {
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
				t.Errorf("expected error for invalid data packet, got nil")
			}
			if err != ErrInvalidPadding {
				t.Errorf("expected ErrInvalidPadding, got %v", err)
			}
		})
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
		{"ObfuscateHandshakeInit", func() { _, _ = obf.ObfuscateHandshakeInit(makeHandshakeData(148)) }},
		{"DeobfuscateHandshakeInit", func() {
			wrapped, _ := ObfuscateClientHello(makeHandshakeData(148), "test.example.com")
			_, _ = obf.DeobfuscateHandshakeInit(wrapped)
		}},
		{"ObfuscateData", func() { _, _ = obf.ObfuscateData([]byte{1}) }},
		{"DeobfuscateData", func() { _, _ = obf.DeobfuscateData([]byte{0xD4, 0x1F, 0x00, 0x00}) }},
		{"ValidateCookie", func() { _ = obf.ValidateCookie(nil) }},
		{"Mode", func() { _ = obf.Mode() }},
	}
	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			m.fn()
		})
	}
}

func TestBalancedMode_DifferentSNI(t *testing.T) {
	// Verify SNI is embedded in the TLS wrapper.
	sni := "myvpn.example.com"
	m := &BalancedMode{minPad: 8, maxPad: 64, sni: sni}

	wrapped, err := m.ObfuscateHandshakeInit(makeHandshakeData(64))
	if err != nil {
		t.Fatalf("ObfuscateHandshakeInit: %v", err)
	}

	// Search for the SNI bytes in the wrapped packet.
	if !bytes.Contains(wrapped, []byte(sni)) {
		t.Errorf("SNI %q not found in wrapped packet", sni)
	}
}

// =============================================================================
// MaxMode tests (Stage 6)
// =============================================================================

func makeTestKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i ^ 0xAA)
	}
	return key
}

func TestMaxMode_HandshakeRoundTrip(t *testing.T) {
	key := makeTestKey()
	sizes := []int{0, 1, 64, 128, 148, 256, 512}
	snis := []string{"cloudflare.com", "www.google.com", "example.org"}

	for _, sz := range sizes {
		for _, sni := range snis {
			name := "size=" + itoa(sz) + "_sni=" + sni
			t.Run(name, func(t *testing.T) {
				m := &MaxMode{minPad: 8, maxPad: 64, sni: sni, key: key}
				original := makeHandshakeData(sz)

				obfuscated, err := m.ObfuscateHandshakeInit(original)
				if err != nil {
					t.Fatalf("ObfuscateHandshakeInit: %v", err)
				}

				// Must look like TLS ClientHello.
				if len(obfuscated) < 43+CookieLen {
					t.Errorf("result too small: %d bytes (want >= %d)", len(obfuscated), 43+CookieLen)
				}
				if obfuscated[0] != 0x16 {
					t.Errorf("first byte = 0x%02X, want 0x16", obfuscated[0])
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

func TestMaxMode_HandshakeInvalid(t *testing.T) {
	key := makeTestKey()
	m := &MaxMode{minPad: 8, maxPad: 64, sni: "cloudflare.com", key: key}

	invalidPackets := [][]byte{
		nil,
		{},
		{0x16},
		makeRandomTLSBytes(100),
		noGreasePacket(),
	}

	for i, pkt := range invalidPackets {
		t.Run(itoa(i), func(t *testing.T) {
			_, err := m.DeobfuscateHandshakeInit(pkt)
			if err == nil {
				t.Errorf("expected error for invalid handshake packet, got nil")
			}
			// Should be ErrNotClientHello for non-TLS wrappers.
			if err != ErrNotClientHello && err != ErrInvalidCookie {
				t.Errorf("expected ErrNotClientHello or ErrInvalidCookie, got %v", err)
			}
		})
	}
}

func TestMaxMode_WrongKey(t *testing.T) {
	key1 := makeTestKey()
	key2 := make([]byte, 32)
	for i := range key2 {
		key2[i] = byte(i ^ 0x55)
	}

	// Obfuscate with key1, try to deobfuscate with key2.
	m1 := &MaxMode{minPad: 8, maxPad: 64, sni: "cloudflare.com", key: key1}
	m2 := &MaxMode{minPad: 8, maxPad: 64, sni: "cloudflare.com", key: key2}

	original := makeHandshakeData(148)
	obfuscated, err := m1.ObfuscateHandshakeInit(original)
	if err != nil {
		t.Fatalf("ObfuscateHandshakeInit: %v", err)
	}

	_, err = m2.DeobfuscateHandshakeInit(obfuscated)
	if err == nil {
		t.Errorf("expected error when using wrong key, got nil")
	}
	if err != ErrInvalidCookie {
		t.Errorf("expected ErrInvalidCookie, got %v", err)
	}
}

func TestMaxMode_CookieTampering(t *testing.T) {
	key := makeTestKey()
	m := &MaxMode{minPad: 8, maxPad: 64, sni: "cloudflare.com", key: key}

	original := makeHandshakeData(148)
	obfuscated, err := m.ObfuscateHandshakeInit(original)
	if err != nil {
		t.Fatalf("ObfuscateHandshakeInit: %v", err)
	}

	// Tamper with one byte inside the GREASE payload (where cookie+data live).
	// The cookie is the first 8 bytes inside GREASE after magic.
	tampered := make([]byte, len(obfuscated))
	copy(tampered, obfuscated)

	// Find GREASE extension and flip a bit in the cookie.
	for i := 0; i < len(tampered)-6; i++ {
		if uint16(tampered[i])<<8|uint16(tampered[i+1]) == greaseExtension {
			// Magic is at i+4, i+5. Cookie starts at i+6, i+7.
			tampered[i+6] ^= 0x01
			break
		}
	}

	_, err = m.DeobfuscateHandshakeInit(tampered)
	if err == nil {
		t.Errorf("expected error for tampered cookie, got nil")
	}
	if err != ErrInvalidCookie {
		t.Errorf("expected ErrInvalidCookie, got %v", err)
	}
}

func TestMaxMode_ValidateCookie(t *testing.T) {
	key := makeTestKey()
	m := &MaxMode{minPad: 8, maxPad: 64, sni: "cloudflare.com", key: key}

	// Invalid packets should return false.
	invalidPackets := [][]byte{
		nil,
		{},
		{0x16},
		makeRandomTLSBytes(100),
	}

	for i, pkt := range invalidPackets {
		t.Run("invalid/"+itoa(i), func(t *testing.T) {
			if m.ValidateCookie(pkt) {
				t.Errorf("ValidateCookie should return false for invalid packet")
			}
		})
	}

	// Valid packet should return true.
	original := makeHandshakeData(148)
	obfuscated, err := m.ObfuscateHandshakeInit(original)
	if err != nil {
		t.Fatalf("ObfuscateHandshakeInit: %v", err)
	}
	if !m.ValidateCookie(obfuscated) {
		t.Errorf("ValidateCookie should return true for valid max mode packet")
	}

	// Tampered cookie should return false.
	tampered := make([]byte, len(obfuscated))
	copy(tampered, obfuscated)
	for i := 0; i < len(tampered)-6; i++ {
		if uint16(tampered[i])<<8|uint16(tampered[i+1]) == greaseExtension {
			tampered[i+6] ^= 0x01
			break
		}
	}
	if m.ValidateCookie(tampered) {
		t.Errorf("ValidateCookie should return false for tampered cookie")
	}
}

func TestMaxMode_DataRoundTrip(t *testing.T) {
	key := makeTestKey()
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
				m := &MaxMode{minPad: r.minPad, maxPad: r.maxPad, sni: "test.com", key: key}
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

func TestMaxMode_DataInvalid(t *testing.T) {
	key := makeTestKey()
	m := &MaxMode{minPad: 8, maxPad: 64, sni: "cloudflare.com", key: key}

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
				t.Errorf("expected error for invalid data packet, got nil")
			}
			if err != ErrInvalidPadding {
				t.Errorf("expected ErrInvalidPadding, got %v", err)
			}
		})
	}
}

func TestMaxMode_Mode(t *testing.T) {
	m := &MaxMode{minPad: 8, maxPad: 64, sni: "cloudflare.com", key: makeTestKey()}
	if m.Mode() != ModeMaximum {
		t.Errorf("Mode() = %v, want ModeMaximum", m.Mode())
	}
}

func TestMaxMode_ImplementsInterface(t *testing.T) {
	key := makeTestKey()
	obf, err := NewObfuscator(Config{
		Mode:         ModeMaximum,
		PaddingRange: [2]int{8, 64},
		SNI:          "cloudflare.com",
		CookieKey:    key,
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
		{"ObfuscateHandshakeInit", func() { _, _ = obf.ObfuscateHandshakeInit(makeHandshakeData(148)) }},
		{"DeobfuscateHandshakeInit", func() {
			wrapped, _ := ObfuscateClientHello(makeHandshakeData(148), "test.example.com")
			_, _ = obf.DeobfuscateHandshakeInit(wrapped)
		}},
		{"ObfuscateData", func() { _, _ = obf.ObfuscateData([]byte{1}) }},
		{"DeobfuscateData", func() { _, _ = obf.DeobfuscateData([]byte{0xD4, 0x1F, 0x00, 0x00}) }},
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
// Benchmarks — VanillaMode vs LightMode vs BalancedMode vs MaxMode
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

func BenchmarkBalancedMode_ObfuscateHandshakeInit(b *testing.B) {
	m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}
	packet := makeHandshakeData(148)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = m.ObfuscateHandshakeInit(packet)
	}
}

func BenchmarkBalancedMode_DeobfuscateHandshakeInit(b *testing.B) {
	m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}
	wrapped, _ := m.ObfuscateHandshakeInit(makeHandshakeData(148))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = m.DeobfuscateHandshakeInit(wrapped)
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

func BenchmarkMaxMode_ObfuscateHandshakeInit(b *testing.B) {
	m := &MaxMode{minPad: 8, maxPad: 64, sni: "cloudflare.com", key: makeTestKey()}
	packet := makeHandshakeData(148)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = m.ObfuscateHandshakeInit(packet)
	}
}

func BenchmarkMaxMode_DeobfuscateHandshakeInit(b *testing.B) {
	m := &MaxMode{minPad: 8, maxPad: 64, sni: "cloudflare.com", key: makeTestKey()}
	wrapped, _ := m.ObfuscateHandshakeInit(makeHandshakeData(148))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = m.DeobfuscateHandshakeInit(wrapped)
	}
}

func BenchmarkMaxMode_ObfuscateData(b *testing.B) {
	m := &MaxMode{minPad: 8, maxPad: 64, sni: "cloudflare.com", key: makeTestKey()}
	packet := makeData(1420)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		result, _ := m.ObfuscateData(packet)
		_ = result
	}
}

func BenchmarkMaxMode_DeobfuscateData(b *testing.B) {
	m := &MaxMode{minPad: 8, maxPad: 64, sni: "cloudflare.com", key: makeTestKey()}
	padded, _ := m.ObfuscateData(makeData(1420))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		result, _ := m.DeobfuscateData(padded)
		_ = result
	}
}

// BenchmarkOverheadComparison measures the relative overhead of all modes
// on MTU-sized data packets.
func BenchmarkOverheadComparison(b *testing.B) {
	data := makeData(1420)
	key := makeTestKey()

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

	b.Run("BalancedMode_RoundTrip", func(b *testing.B) {
		m := &BalancedMode{minPad: 8, maxPad: 64, sni: "cloudflare.com"}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			padded, _ := m.ObfuscateData(data)
			result, _ := m.DeobfuscateData(padded)
			_ = result
		}
	})

	b.Run("MaxMode_ObfuscateData", func(b *testing.B) {
		m := &MaxMode{minPad: 8, maxPad: 64, sni: "cloudflare.com", key: key}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			result, _ := m.ObfuscateData(data)
			_ = result
		}
	})

	b.Run("MaxMode_RoundTrip", func(b *testing.B) {
		m := &MaxMode{minPad: 8, maxPad: 64, sni: "cloudflare.com", key: key}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			padded, _ := m.ObfuscateData(data)
			result, _ := m.DeobfuscateData(padded)
			_ = result
		}
	})
}