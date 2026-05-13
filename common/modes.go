package common

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
//
// BalancedMode combines TLS ClientHello mimicry for handshake packets with
// variable-length padding for data packets. This offers a good balance of
// stealth and performance suitable for most DPI-circumvention scenarios.
//
// Handshake path:
//   ObfuscateHandshakeInit  → wraps in TLS ClientHello (Stage 4)
//   DeobfuscateHandshakeInit → unwraps TLS ClientHello
//
// Data path:
//   ObfuscateData  → AddPadding (Stage 3)
//   DeobfuscateData → RemovePadding (Stage 3)
//
// Overhead characteristics (DefaultConfig: minPad=8, maxPad=64, SNI="cloudflare.com"):
//   - Per handshake: ~250 bytes (TLS wrapper, ~170% on 148-byte init)
//   - Per data packet: 12–83 bytes (avg ~40, ~2.8% on MTU 1420)
//   - Average per-flow: ~5–7% (weighted by handshake frequency)
type BalancedMode struct {
	minPad int
	maxPad int
	sni    string
}

// Compile-time check: BalancedMode satisfies Obfuscator.
var _ Obfuscator = (*BalancedMode)(nil)

// ObfuscateHandshakeInit wraps the handshake packet inside a TLS 1.2 ClientHello.
func (m *BalancedMode) ObfuscateHandshakeInit(in []byte) ([]byte, error) {
	return ObfuscateClientHello(in, m.sni)
}

// DeobfuscateHandshakeInit extracts the handshake packet from a TLS ClientHello wrapper.
func (m *BalancedMode) DeobfuscateHandshakeInit(in []byte) ([]byte, error) {
	return DeobfuscateClientHello(in)
}

// ObfuscateData wraps the data packet with the Stage 3 padding format.
func (m *BalancedMode) ObfuscateData(in []byte) ([]byte, error) {
	return AddPadding(in, m.minPad, m.maxPad)
}

// DeobfuscateData strips the Stage 3 padding and returns the original packet.
func (m *BalancedMode) DeobfuscateData(in []byte) ([]byte, error) {
	return RemovePadding(in)
}

// ValidateCookie always returns true (no cookie mechanism in BalancedMode).
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
// MaxMode extends BalancedMode with an HMAC-SHA256 cookie embedded in the
// TLS SessionID field. The cookie authenticates the handshake and prevents
// replay and injection attacks by active probing systems.
//
// Handshake path:
//   ObfuscateHandshakeInit:
//     1. Generate 8-byte cookie = HMAC-SHA256(key, original[:64])[:8]
//     2. Prepend cookie to original handshake data
//     3. Wrap [cookie | original] in TLS ClientHello with default SessionID
//
//   DeobfuscateHandshakeInit:
//     1. Unwrap TLS ClientHello → [cookie | original]
//     2. Extract cookie (first 8 bytes), remaining = original
//     3. Verify cookie = HMAC-SHA256(key, original[:64])[:8]
//     4. Return original (without cookie)
//
// Data path:
//   ObfuscateData  → AddPadding (Stage 3)
//   DeobfuscateData → RemovePadding (Stage 3)
//
// Overhead characteristics (DefaultConfig: minPad=8, maxPad=64, SNI="cloudflare.com"):
//   - Per handshake: ~258 bytes (TLS wrapper + 8-byte cookie)
//   - Per data packet: 12–83 bytes (avg ~40, ~2.8% on MTU 1420)
//   - Average per-flow: ~7–10%
type MaxMode struct {
	minPad int
	maxPad int
	sni    string
	key    []byte // 32-byte HMAC-SHA256 key
}

// Compile-time check: MaxMode satisfies Obfuscator.
var _ Obfuscator = (*MaxMode)(nil)

// ObfuscateHandshakeInit embeds a cookie into the handshake and wraps in TLS ClientHello.
func (m *MaxMode) ObfuscateHandshakeInit(in []byte) ([]byte, error) {
	cookie, err := GenerateCookie(m.key, in)
	if err != nil {
		return nil, err
	}

	// Embed cookie before handshake data: [cookie | original]
	payload := make([]byte, CookieLen+len(in))
	copy(payload[:CookieLen], cookie)
	copy(payload[CookieLen:], in)

	return ObfuscateClientHello(payload, m.sni)
}

// DeobfuscateHandshakeInit extracts the handshake and verifies the HMAC cookie.
// Returns ErrNotClientHello for non-TLS wrappers, ErrInvalidCookie for bad cookies.
func (m *MaxMode) DeobfuscateHandshakeInit(in []byte) ([]byte, error) {
	payload, err := DeobfuscateClientHello(in)
	if err != nil {
		return nil, err
	}

	if len(payload) < CookieLen {
		return nil, ErrNotClientHello
	}

	cookie := payload[:CookieLen]
	original := payload[CookieLen:]

	if err := ValidateCookieBytes(m.key, original, cookie); err != nil {
		return nil, err
	}

	return original, nil
}

// ObfuscateData wraps the data packet with the Stage 3 padding format.
func (m *MaxMode) ObfuscateData(in []byte) ([]byte, error) {
	return AddPadding(in, m.minPad, m.maxPad)
}

// DeobfuscateData strips the Stage 3 padding and returns the original packet.
func (m *MaxMode) DeobfuscateData(in []byte) ([]byte, error) {
	return RemovePadding(in)
}

// ValidateCookie checks whether the handshake carries a valid HMAC cookie.
// This is a secondary validation path that can be used for active-probe rejection.
// The primary cookie validation happens in DeobfuscateHandshakeInit.
func (m *MaxMode) ValidateCookie(packet []byte) bool {
	if len(packet) < CookieLen {
		return false
	}
	// Try to extract the handshake payload and verify the cookie.
	payload, err := DeobfuscateClientHello(packet)
	if err != nil {
		return false
	}
	if len(payload) < CookieLen {
		return false
	}
	return ValidateCookieBytes(m.key, payload[CookieLen:], payload[:CookieLen]) == nil
}

// Mode returns ModeMaximum.
func (m *MaxMode) Mode() ObfuscationMode {
	return ModeMaximum
}

// --- Stub mode struct for future stage ---

// AutoMode automatically selects the best obfuscation mode based on
// network conditions, detected DPI behavior, and success rates.
// Will be implemented in Stage 12.
type AutoMode struct{}