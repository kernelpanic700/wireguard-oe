package common

// ObfuscationMode defines the obfuscation mode selected by the user.
type ObfuscationMode int

const (
	ModeVanilla  ObfuscationMode = 0
	ModeLight    ObfuscationMode = 1
	ModeBalanced ObfuscationMode = 2
	ModeMaximum  ObfuscationMode = 3
	ModeAuto     ObfuscationMode = 4
)

// Obfuscator interface for packet obfuscation.
type Obfuscator interface {
	ObfuscateHandshakeInit(in []byte) ([]byte, error)
	DeobfuscateHandshakeInit(in []byte) ([]byte, error)
	ObfuscateData(in []byte) ([]byte, error)
	DeobfuscateData(in []byte) ([]byte, error)
	ValidateCookie(packet []byte) bool
	Mode() ObfuscationMode
}

// Config holds obfuscation configuration.
type Config struct {
	Mode         ObfuscationMode
	PaddingRange [2]int
	JunkRange    [2]int
	TLSProfile   string
	CookieKey    []byte
	WebSocketURL string
}

// NewObfuscator factory function (placeholder).
func NewObfuscator(cfg Config) (Obfuscator, error) {
	return nil, nil
}
