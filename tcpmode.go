package raw

import "fmt"

// TCPMode is a convenience view over the orthogonal Config.Transport and
// Config.Obfuscate fields. It is NOT stored on Config and does not replace
// those fields, which remain the single source of truth for transport
// selection.
//
// TCPMode only enumerates the four common framing+obfuscation combinations.
// Less common combinations — for example obfuscated padded intermediate —
// are still fully reachable by setting Config.Transport and Config.Obfuscate
// directly. Use Apply to populate a Config from a mode, or read Transport and
// Obfuscated to obtain the underlying pair:
//
//	var cfg raw.Config
//	raw.TCPModeObfuscatedAbridged.Apply(&cfg)
//	// equivalent to:
//	// cfg.Transport = raw.TransportAbridged
//	// cfg.Obfuscate = true
//
// Conversion is one-directional (TCPMode -> Config fields); no state is
// duplicated and the mode is selected only when a connection is created.
type TCPMode int

const (
	// TCPModeIntermediate selects intermediate framing
	// ([4-byte length][payload]) without obfuscation. It is the zero value
	// and matches the default Config, so existing behaviour is unchanged.
	TCPModeIntermediate TCPMode = iota
	// TCPModeAbridged selects abridged framing (minimal one- or four-byte
	// length encoding) without obfuscation.
	TCPModeAbridged
	// TCPModeObfuscatedAbridged wraps abridged framing in Telegram
	// obfuscation.
	TCPModeObfuscatedAbridged
	// TCPModeObfuscatedIntermediate wraps intermediate framing in Telegram
	// obfuscation.
	TCPModeObfuscatedIntermediate
)

// Transport returns the TCP framing kind selected by this mode. An unknown
// mode value resolves to TransportIntermediate.
func (mode TCPMode) Transport() TransportKind {
	switch mode {
	case TCPModeAbridged, TCPModeObfuscatedAbridged:
		return TransportAbridged
	default:
		return TransportIntermediate
	}
}

// Obfuscated reports whether this mode wraps the framing in Telegram
// obfuscation.
func (mode TCPMode) Obfuscated() bool {
	switch mode {
	case TCPModeObfuscatedAbridged, TCPModeObfuscatedIntermediate:
		return true
	default:
		return false
	}
}

// Apply sets Config.Transport and Config.Obfuscate to the values selected by
// this mode. It is a convenience over setting both fields by hand; only those
// two fields are touched and the mode itself is never retained.
func (mode TCPMode) Apply(config *Config) {
	if config == nil {
		return
	}
	config.Transport = mode.Transport()
	config.Obfuscate = mode.Obfuscated()
}

// String returns the constant name of the mode, or "TCPMode(0xN)" for an
// unrecognized value.
func (mode TCPMode) String() string {
	switch mode {
	case TCPModeIntermediate:
		return "TCPModeIntermediate"
	case TCPModeAbridged:
		return "TCPModeAbridged"
	case TCPModeObfuscatedAbridged:
		return "TCPModeObfuscatedAbridged"
	case TCPModeObfuscatedIntermediate:
		return "TCPModeObfuscatedIntermediate"
	default:
		return fmt.Sprintf("TCPMode(0x%x)", uint(mode))
	}
}
