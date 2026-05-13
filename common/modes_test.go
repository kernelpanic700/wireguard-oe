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

// Benchmarks — verify zero overhead characteristics of VanillaMode.

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