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

// --- Stub mode structs for future stages ---
// Defined now to document the planned mode hierarchy and to allow
// NewObfuscator to reference them in error messages.

// LightMode provides minimal obfuscation with very low overhead (<3%).
// Will be implemented in Stage 3.
type LightMode struct{}

// BalancedMode provides moderate obfuscation (8–15% overhead).
// Combines padding + TLS mimicry for a good balance of stealth and performance.
// Will be implemented in Stage 5.
type BalancedMode struct{}

// MaxMode provides maximum obfuscation for the strictest DPI environments.
// Enables: TLS mimicry + QUIC short-header rotation + active probing protection +
// WebSocket fallback. Overhead 15–25%.
// Will be implemented across Stages 6 and 11.
type MaxMode struct{}

// AutoMode automatically selects the best obfuscation mode based on
// network conditions, detected DPI behavior, and success rates.
// Will be implemented in Stage 12.
type AutoMode struct{}