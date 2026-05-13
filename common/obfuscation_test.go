package common

import (
	"strings"
	"testing"
)

func TestObfuscationMode_String(t *testing.T) {
	tests := []struct {
		mode     ObfuscationMode
		expected string
	}{
		{ModeVanilla, "vanilla"},
		{ModeLight, "light"},
		{ModeBalanced, "balanced"},
		{ModeMaximum, "maximum"},
		{ModeAuto, "auto"},
		{ObfuscationMode(99), "unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.mode.String()
			if got != tt.expected {
				t.Errorf("String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Mode != ModeVanilla {
		t.Errorf("default mode = %v, want vanilla", cfg.Mode)
	}
	if cfg.PaddingRange[0] != 16 || cfg.PaddingRange[1] != 128 {
		t.Errorf("default PaddingRange = %v, want [16, 128]", cfg.PaddingRange)
	}
	if cfg.JunkRange[0] != 0 || cfg.JunkRange[1] != 64 {
		t.Errorf("default JunkRange = %v, want [0, 64]", cfg.JunkRange)
	}
	if cfg.TLSProfile != "chrome-112" {
		t.Errorf("default TLSProfile = %q, want \"chrome-112\"", cfg.TLSProfile)
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid vanilla config",
			cfg:     DefaultConfig(),
			wantErr: false,
		},
		{
			name: "valid balanced config with custom ranges",
			cfg: Config{
				Mode:         ModeBalanced,
				PaddingRange: [2]int{32, 256},
				JunkRange:    [2]int{0, 32},
				TLSProfile:   "firefox-110",
				CookieKey:    make([]byte, 32),
			},
			wantErr: false,
		},
		{
			name: "valid config with nil cookie key",
			cfg: Config{
				Mode: ModeVanilla,
			},
			wantErr: false,
		},
		{
			name: "valid config with zero padding range",
			cfg: Config{
				Mode:         ModeLight,
				PaddingRange: [2]int{0, 0},
			},
			wantErr: false,
		},
		{
			name: "invalid mode (negative)",
			cfg: Config{
				Mode: ObfuscationMode(-1),
			},
			wantErr:   true,
			errSubstr: "invalid mode",
		},
		{
			name: "invalid mode (above range)",
			cfg: Config{
				Mode: ObfuscationMode(10),
			},
			wantErr:   true,
			errSubstr: "invalid mode",
		},
		{
			name: "negative padding min",
			cfg: Config{
				Mode:         ModeLight,
				PaddingRange: [2]int{-1, 10},
			},
			wantErr:   true,
			errSubstr: "padding range must be non-negative",
		},
		{
			name: "negative padding max",
			cfg: Config{
				Mode:         ModeLight,
				PaddingRange: [2]int{0, -5},
			},
			wantErr:   true,
			errSubstr: "padding range must be non-negative",
		},
		{
			name: "padding min > max",
			cfg: Config{
				Mode:         ModeLight,
				PaddingRange: [2]int{100, 50},
			},
			wantErr:   true,
			errSubstr: "padding range min",
		},
		{
			name: "negative junk min",
			cfg: Config{
				Mode:      ModeLight,
				JunkRange: [2]int{-1, 10},
			},
			wantErr:   true,
			errSubstr: "junk range must be non-negative",
		},
		{
			name: "junk min > max",
			cfg: Config{
				Mode:      ModeLight,
				JunkRange: [2]int{50, 10},
			},
			wantErr:   true,
			errSubstr: "junk range min",
		},
		{
			name: "invalid cookie key length (not 32)",
			cfg: Config{
				Mode:      ModeVanilla,
				CookieKey: make([]byte, 16),
			},
			wantErr:   true,
			errSubstr: "cookie key must be exactly 32 bytes",
		},
		{
			name: "valid cookie key length (exactly 32)",
			cfg: Config{
				Mode:      ModeVanilla,
				CookieKey: make([]byte, 32),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr = %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errSubstr != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
			}
		})
	}
}

func TestNewObfuscator(t *testing.T) {
	validCookieKey := make([]byte, 32)

	tests := []struct {
		name      string
		cfg       Config
		wantErr   bool
		errSubstr string
		wantMode  ObfuscationMode
	}{
		{
			name:     "vanilla mode - success",
			cfg:      Config{Mode: ModeVanilla},
			wantErr:  false,
			wantMode: ModeVanilla,
		},
		{
			name: "vanilla mode with all fields set",
			cfg: Config{
				Mode:         ModeVanilla,
				PaddingRange: [2]int{0, 0},
				JunkRange:    [2]int{0, 0},
				TLSProfile:   "chrome-112",
				CookieKey:    validCookieKey,
			},
			wantErr:  false,
			wantMode: ModeVanilla,
		},
		{
			name:     "zero config - applies defaults (vanilla)",
			cfg:      Config{},
			wantErr:  false,
			wantMode: ModeVanilla,
		},
		{
			name:      "light mode - not implemented",
			cfg:       Config{Mode: ModeLight},
			wantErr:   true,
			errSubstr: "not implemented yet",
		},
		{
			name:      "balanced mode - not implemented",
			cfg:       Config{Mode: ModeBalanced},
			wantErr:   true,
			errSubstr: "not implemented yet",
		},
		{
			name:      "maximum mode - not implemented",
			cfg:       Config{Mode: ModeMaximum},
			wantErr:   true,
			errSubstr: "not implemented yet",
		},
		{
			name:      "auto mode - not implemented",
			cfg:       Config{Mode: ModeAuto},
			wantErr:   true,
			errSubstr: "not implemented yet",
		},
		{
			name:      "unsupported mode code",
			cfg:       Config{Mode: ObfuscationMode(99)},
			wantErr:   true,
			errSubstr: "invalid mode",
		},
		{
			name: "invalid config - bad padding range",
			cfg: Config{
				Mode:         ModeVanilla,
				PaddingRange: [2]int{-1, 10},
			},
			wantErr:   true,
			errSubstr: "invalid config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obf, err := NewObfuscator(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewObfuscator() error = %v, wantErr = %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if tt.errSubstr != "" && err != nil {
					if !strings.Contains(err.Error(), tt.errSubstr) {
						t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
					}
				}
				return
			}
			if obf == nil {
				t.Fatal("expected non-nil Obfuscator")
			}
			if got := obf.Mode(); got != tt.wantMode {
				t.Errorf("Mode() = %v, want %v", got, tt.wantMode)
			}
		})
	}
}

// TestVanillaObfuscator_NewObfuscator ensures the factory returns *VanillaMode for ModeVanilla.
func TestVanillaObfuscator_NewObfuscator(t *testing.T) {
	obf, err := NewObfuscator(Config{Mode: ModeVanilla})
	if err != nil {
		t.Fatalf("NewObfuscator() error = %v", err)
	}
	if _, ok := obf.(*VanillaMode); !ok {
		t.Errorf("expected *VanillaMode, got %T", obf)
	}
	if obf.Mode() != ModeVanilla {
		t.Errorf("Mode() = %v, want %v", obf.Mode(), ModeVanilla)
	}
}