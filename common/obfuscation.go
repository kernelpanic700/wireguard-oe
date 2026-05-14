package common

import "fmt"

// ObfuscationMode defines the obfuscation mode selected by the user.
type ObfuscationMode int

const (
	// ModeVanilla — passthrough mode: zero overhead, bit-for-bit identical to original WireGuard.
	ModeVanilla ObfuscationMode = 0
	// ModeLight — light obfuscation with minimal overhead (<3%). Implemented in Stage 3.
	ModeLight ObfuscationMode = 1
	// ModeBalanced — balanced obfuscation (~5–7% overhead). Combines padding + TLS mimicry.
	// Implemented in Stage 5.
	ModeBalanced ObfuscationMode = 2
	// ModeMaximum — maximum obfuscation for strict DPI environments.
	// Implemented in Stage 6: TLS mimicry + padding + active probing protection (cookie).
	ModeMaximum ObfuscationMode = 3
	// ModeAuto — automatic mode selection based on network conditions. Planned for Stage 12.
	ModeAuto ObfuscationMode = 4
)

// String returns a human-readable name for the obfuscation mode.
func (m ObfuscationMode) String() string {
	switch m {
	case ModeVanilla:
		return "vanilla"
	case ModeLight:
		return "light"
	case ModeBalanced:
		return "balanced"
	case ModeMaximum:
		return "maximum"
	case ModeAuto:
		return "auto"
	default:
		return fmt.Sprintf("unknown(%d)", m)
	}
}

// Obfuscator is the interface all obfuscation modes must implement.
// VanillaMode passes all data through unmodified; other modes transform packets
// to evade DPI.
type Obfuscator interface {
	// ObfuscateHandshakeInit transforms the initial handshake packet on the sender side.
	ObfuscateHandshakeInit(in []byte) ([]byte, error)
	// DeobfuscateHandshakeInit restores the original handshake packet on the receiver side.
	DeobfuscateHandshakeInit(in []byte) ([]byte, error)
	// ObfuscateData transforms a transport data packet on the sender side.
	ObfuscateData(in []byte) ([]byte, error)
	// DeobfuscateData restores a transport data packet on the receiver side.
	DeobfuscateData(in []byte) ([]byte, error)
	// ValidateCookie checks whether a packet carries a valid obfuscation cookie.
	// VanillaMode, LightMode, and BalancedMode always return true (no cookie mechanism).
	// MaxMode performs real HMAC validation (Stage 6).
	ValidateCookie(packet []byte) bool
	// Mode returns the ObfuscationMode this instance was configured with.
	Mode() ObfuscationMode
}

// Config holds user-provided obfuscation configuration.
type Config struct {
	Mode         ObfuscationMode
	PaddingRange [2]int  // [min, max] extra bytes for data packets
	JunkRange    [2]int  // [min, max] random junk bytes in handshake
	TLSProfile   string  // deprecated: kept for backward compatibility, superseded by SNI
	SNI          string  // TLS SNI hostname (default: "cloudflare.com")
	CookieKey    []byte  // HMAC key for cookie generation (32 bytes, required for MaxMode)
	WebSocketURL string  // WebSocket fallback endpoint
}

// DefaultConfig returns a Config with reasonable defaults.
func DefaultConfig() Config {
	return Config{
		Mode:         ModeVanilla,
		PaddingRange: [2]int{8, 64},  // Light overhead range (Stage 3)
		JunkRange:    [2]int{0, 64},
		TLSProfile:   "chrome-112",
		SNI:          "cloudflare.com",
		CookieKey:    nil,
		WebSocketURL: "",
	}
}

// ValidateConfig checks the Config for invalid or contradictory values.
func ValidateConfig(cfg Config) error {
	if cfg.Mode < ModeVanilla || cfg.Mode > ModeAuto {
		return fmt.Errorf("invalid mode: %d (valid range: %d–%d)", cfg.Mode, ModeVanilla, ModeAuto)
	}
	if cfg.PaddingRange[0] < 0 || cfg.PaddingRange[1] < 0 {
		return fmt.Errorf("padding range must be non-negative: [%d, %d]", cfg.PaddingRange[0], cfg.PaddingRange[1])
	}
	if cfg.PaddingRange[0] > cfg.PaddingRange[1] {
		return fmt.Errorf("padding range min (%d) > max (%d)", cfg.PaddingRange[0], cfg.PaddingRange[1])
	}
	// For BalancedMode and beyond, maxPad must not exceed 255 (padding protocol limit).
	if cfg.Mode >= ModeBalanced && cfg.PaddingRange[1] > 255 {
		return fmt.Errorf("padding max (%d) exceeds 255 (protocol limit)", cfg.PaddingRange[1])
	}
	if cfg.JunkRange[0] < 0 || cfg.JunkRange[1] < 0 {
		return fmt.Errorf("junk range must be non-negative: [%d, %d]", cfg.JunkRange[0], cfg.JunkRange[1])
	}
	if cfg.JunkRange[0] > cfg.JunkRange[1] {
		return fmt.Errorf("junk range min (%d) > max (%d)", cfg.JunkRange[0], cfg.JunkRange[1])
	}
	// CookieKey, if provided, must be exactly 32 bytes (applies to any mode).
	if cfg.CookieKey != nil && len(cfg.CookieKey) != 32 {
		return fmt.Errorf("cookie key must be exactly 32 bytes, got %d", len(cfg.CookieKey))
	}
	// MaxMode requires a cookie key.
	if cfg.Mode == ModeMaximum {
		if cfg.CookieKey == nil {
			return fmt.Errorf("cookie key is required for %s mode", cfg.Mode)
		}
	}
	// For modes that use TLS mimicry, SNI must be non-empty.
	if cfg.Mode >= ModeBalanced && cfg.Mode <= ModeAuto {
		if cfg.SNI == "" {
			return fmt.Errorf("SNI is required for %s mode", cfg.Mode)
		}
		if len(cfg.SNI) > 255 {
			return fmt.Errorf("SNI too long: %d bytes (max 255)", len(cfg.SNI))
		}
	}
	return nil
}

// NewObfuscator is the factory function that creates an Obfuscator based on Config.
//
// Supported modes:
//   - ModeVanilla — fully implemented (passthrough, zero overhead)
//   - ModeLight — fully implemented (Stage 3: padding obfuscation)
//   - ModeBalanced — fully implemented (Stage 5: TLS mimicry + padding)
//   - ModeMaximum — fully implemented (Stage 6: TLS mimicry + padding + cookie)
//   - ModeAuto — returns descriptive "not implemented yet" error
func NewObfuscator(cfg Config) (Obfuscator, error) {
	// Apply defaults for zero-value config
	if cfg == (Config{}) {
		cfg = DefaultConfig()
	}

	if err := ValidateConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	switch cfg.Mode {
	case ModeVanilla:
		return &VanillaMode{}, nil
	case ModeLight:
		return &LightMode{
			minPad: cfg.PaddingRange[0],
			maxPad: cfg.PaddingRange[1],
		}, nil
	case ModeBalanced:
		sni := cfg.SNI
		if sni == "" {
			sni = DefaultConfig().SNI
		}
		return &BalancedMode{
			minPad: cfg.PaddingRange[0],
			maxPad: cfg.PaddingRange[1],
			sni:    sni,
		}, nil
	case ModeMaximum:
		sni := cfg.SNI
		if sni == "" {
			sni = DefaultConfig().SNI
		}
		// Clone CookieKey to avoid aliasing the config's backing array.
		key := make([]byte, len(cfg.CookieKey))
		copy(key, cfg.CookieKey)
		return &MaxMode{
			minPad:    cfg.PaddingRange[0],
			maxPad:    cfg.PaddingRange[1],
			sni:       sni,
			cookieKey: key,
		}, nil
	case ModeAuto:
		return nil, fmt.Errorf("mode %q is not implemented yet (planned for Stage 12)", cfg.Mode)
	default:
		return nil, fmt.Errorf("unsupported mode: %d", cfg.Mode)
	}
}
