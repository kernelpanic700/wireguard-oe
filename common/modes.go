package common

import (
	"fmt"
)

// VanillaMode implements Obfuscator as a complete passthrough.
//
// VanillaMode is designed to be bit-for-bit identical to original WireGuard:
// every method returns the input packet unchanged. This ensures full
// compatibility with standard WireGuard peers and zero performance overhead.
//
// Use VanillaMode when:
//   - DPI circumvention is not needed (trusted network, permitted VPN use)
//   - Compatibility with unmodified WireGuard clients is required
//   - The user wants to disable obfuscation without changing the code path
//
// All methods are non-mutating: they return the original slice without copying.
// This is the ONLY mode fully implemented in Stage 2.
type VanillaMode struct{}

// Compile-time check: VanillaMode satisfies Obfuscator.
var _ Obfuscator = (*VanillaMode)(nil)

// ObfuscateHandshakeInit returns the handshake packet unchanged.
func (v *VanillaMode) ObfuscateHandshakeInit(in []byte) ([]byte, error) {
	return in, nil
}

// DeobfuscateHandshakeInit returns the handshake packet unchanged.
func (v *VanillaMode) DeobfuscateHandshakeInit(in []byte) ([]byte, error) {
	return in, nil
}

// ObfuscateData returns the data packet unchanged.
func (v *VanillaMode) ObfuscateData(in []byte) ([]byte, error) {
	return in, nil
}

// DeobfuscateData returns the data packet unchanged.
func (v *VanillaMode) DeobfuscateData(in []byte) ([]byte, error) {
	return in, nil
}

// ValidateCookie always returns true because VanillaMode has no cookie mechanism.
// In vanilla mode, packets do not carry obfuscation markers; validation is a no-op
// that accepts everything. This preserves compatibility with unmodified WireGuard.
func (v *VanillaMode) ValidateCookie(packet []byte) bool {
	return true
}

// Mode returns ModeVanilla.
func (v *VanillaMode) Mode() ObfuscationMode {
	return ModeVanilla
}

// --- LightMode: Stage 3 implementation ---

// LightMode provides minimal obfuscation with very low overhead (<3%).
//
// LightMode obfuscates data packets using variable-length padding with a
// random prefix and a magic discriminator (see common/padding.go for the
// packet format). Handshake packets pass through unmodified to avoid
// disrupting the WireGuard handshake.
//
// Overhead characteristics (DefaultConfig: minPad=8, maxPad=64):
//   - Per data packet: 12–83 bytes (avg ~40, ~2.8% on MTU 1420)
//   - Per handshake:   0 bytes (passthrough)
//   - Average per-flow: <3%
//
// This mode is suitable for networks with light DPI that only check for
// obvious VPN signatures.
type LightMode struct {
	minPad int
	maxPad int
}

// Compile-time check: LightMode satisfies Obfuscator.
var _ Obfuscator = (*LightMode)(nil)

// ObfuscateHandshakeInit returns the handshake packet unchanged (passthrough).
func (m *LightMode) ObfuscateHandshakeInit(in []byte) ([]byte, error) {
	return in, nil
}

// DeobfuscateHandshakeInit returns the handshake packet unchanged (passthrough).
func (m *LightMode) DeobfuscateHandshakeInit(in []byte) ([]byte, error) {
	return in, nil
}

// ObfuscateData wraps the data packet with the Stage 3 padding format.
func (m *LightMode) ObfuscateData(in []byte) ([]byte, error) {
	return AddPadding(in, m.minPad, m.maxPad)
}

// DeobfuscateData strips the Stage 3 padding and returns the original packet.
// Returns ErrInvalidPadding if the packet is not a valid Stage 3 padded packet.
func (m *LightMode) DeobfuscateData(in []byte) ([]byte, error) {
	return RemovePadding(in)
}

// ValidateCookie always returns true (no cookie mechanism in LightMode).
// Cookie-based validation will be added in Stage 6 (MaxMode).
func (m *LightMode) ValidateCookie(packet []byte) bool {
	return true
}

// Mode returns ModeLight.
func (m *LightMode) Mode() ObfuscationMode {
	return ModeLight
}

// --- BalancedMode: Stage 5 implementation ---

// BalancedMode provides moderate obfuscation (~5–7% overhead).
// It combines TLS ClientHello mimicry for handshake packets with
// variable-length padding for data packets.
//
// Handshake path:
//   ObfuscateHandshakeInit → ObfuscateClientHello(data, sni)
//   DeobfuscateHandshakeInit → DeobfuscateClientHello(data)
//
// Data path:
//   ObfuscateData → AddPadding(data, minPad, maxPad)
//   DeobfuscateData → RemovePadding(data)
//
// ValidateCookie always returns true (cookie validation added in Stage 6).
type BalancedMode struct {
	minPad int
	maxPad int
	sni    string
}

// Compile-time check: BalancedMode satisfies Obfuscator.
var _ Obfuscator = (*BalancedMode)(nil)

// ObfuscateHandshakeInit wraps the handshake packet in a TLS 1.2 ClientHello
// using the configured SNI hostname.
func (m *BalancedMode) ObfuscateHandshakeInit(in []byte) ([]byte, error) {
	return ObfuscateClientHello(in, m.sni)
}

// DeobfuscateHandshakeInit extracts the original handshake packet from the
// TLS ClientHello wrapper.
func (m *BalancedMode) DeobfuscateHandshakeInit(in []byte) ([]byte, error) {
	return DeobfuscateClientHello(in)
}

// ObfuscateData wraps the data packet with the Stage 3 padding format.
func (m *BalancedMode) ObfuscateData(in []byte) ([]byte, error) {
	return AddPadding(in, m.minPad, m.maxPad)
}

// DeobfuscateData strips the Stage 3 padding and returns the original packet.
// Returns ErrInvalidPadding if the packet is not a valid Stage 3 padded packet.
func (m *BalancedMode) DeobfuscateData(in []byte) ([]byte, error) {
	return RemovePadding(in)
}

// ValidateCookie always returns true (no cookie mechanism in BalancedMode).
// Cookie-based validation will be added in Stage 6 (MaxMode).
func (m *BalancedMode) ValidateCookie(packet []byte) bool {
	return true
}

// Mode returns ModeBalanced.
func (m *BalancedMode) Mode() ObfuscationMode {
	return ModeBalanced
}

// --- MaxMode: Stage 6 implementation ---

// MaxMode provides maximum obfuscation for the strictest DPI environments.
//
// MaxMode extends BalancedMode with active probing protection via HMAC-SHA256
// cookies embedded in the TLS ClientHello GREASE extension.
//
// Handshake path:
//   ObfuscateHandshakeInit:
//     1. EmbedCookiePayload(key, data) → timestamp(8) + cookie(8) + data
//     2. ObfuscateClientHello(combined, sni)
//   DeobfuscateHandshakeInit:
//     1. DeobfuscateClientHello(packet) → GREASE payload
//     2. ExtractCookiePayload(key, payload, 90) → data (or error)
//
// Data path (same as BalancedMode):
//   ObfuscateData → AddPadding(data, minPad, maxPad)
//   DeobfuscateData → RemovePadding(data)
//
// ValidateCookie performs real HMAC validation against the embedded cookie.
// If validation fails, the caller should treat the packet as a DPI probe
// and respond with random junk (not yet implemented — Stage 7).
type MaxMode struct {
	minPad    int
	maxPad    int
	sni       string
	cookieKey []byte // must be exactly 32 bytes
}

// Compile-time check: MaxMode satisfies Obfuscator.
var _ Obfuscator = (*MaxMode)(nil)

// ObfuscateHandshakeInit builds a cookie payload from the handshake data,
// then wraps everything in a TLS ClientHello.
func (m *MaxMode) ObfuscateHandshakeInit(in []byte) ([]byte, error) {
	payload, err := EmbedCookiePayload(m.cookieKey, in)
	if err != nil {
		return nil, fmt.Errorf("cookie payload: %w", err)
	}
	return ObfuscateClientHello(payload, m.sni)
}

// DeobfuscateHandshakeInit extracts the TLS wrapper, validates the cookie,
// and returns the original handshake data.
func (m *MaxMode) DeobfuscateHandshakeInit(in []byte) ([]byte, error) {
	payload, err := DeobfuscateClientHello(in)
	if err != nil {
		return nil, fmt.Errorf("tls unwrap: %w", err)
	}
	data, err := ExtractCookiePayload(m.cookieKey, payload, DefaultCookieWindow)
	if err != nil {
		return nil, fmt.Errorf("cookie validation: %w", err)
	}
	return data, nil
}

// ObfuscateData wraps the data packet with the Stage 3 padding format.
func (m *MaxMode) ObfuscateData(in []byte) ([]byte, error) {
	return AddPadding(in, m.minPad, m.maxPad)
}

// DeobfuscateData strips the Stage 3 padding and returns the original packet.
func (m *MaxMode) DeobfuscateData(in []byte) ([]byte, error) {
	return RemovePadding(in)
}

// ValidateCookie performs real HMAC validation of the cookie embedded
// in the TLS ClientHello GREASE extension.
//
// Returns true only if:
//   - The packet is a valid TLS ClientHello with a GREASE extension.
//   - The GREASE payload contains a valid timestamp + cookie + data.
//   - The HMAC-SHA256 matches.
//   - The timestamp is within ±90 seconds of the current time.
//
// Returns false for any malformed, tampered, or expired packet — which
// indicates a likely DPI probe.
func (m *MaxMode) ValidateCookie(packet []byte) bool {
	payload, err := DeobfuscateClientHello(packet)
	if err != nil {
		return false
	}
	_, err = ExtractCookiePayload(m.cookieKey, payload, DefaultCookieWindow)
	return err == nil
}

// Mode returns ModeMaximum.
func (m *MaxMode) Mode() ObfuscationMode {
	return ModeMaximum
}

// --- Stub mode structs for future stages ---

// AutoMode automatically selects the best obfuscation mode based on
// network conditions, detected DPI behavior, and success rates.
// Will be implemented in Stage 12.
type AutoMode struct{}
