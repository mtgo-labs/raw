package raw

import (
	"testing"
)

func TestTCPModeMapsToFramingAndObfuscation(t *testing.T) {
	cases := []struct {
		mode       TCPMode
		transport  TransportKind
		obfuscated bool
	}{
		{TCPModeIntermediate, TransportIntermediate, false},
		{TCPModeAbridged, TransportAbridged, false},
		{TCPModeObfuscatedAbridged, TransportAbridged, true},
		{TCPModeObfuscatedIntermediate, TransportIntermediate, true},
	}
	for _, test := range cases {
		if got := test.mode.Transport(); got != test.transport {
			t.Errorf("%s.Transport() = %d, want %d", test.mode, got, test.transport)
		}
		if got := test.mode.Obfuscated(); got != test.obfuscated {
			t.Errorf("%s.Obfuscated() = %v, want %v", test.mode, got, test.obfuscated)
		}
	}
}

func TestTCPModeZeroValueIsIntermediate(t *testing.T) {
	// The zero value must resolve to the default framing so existing users
	// who leave the mode untouched keep intermediate, non-obfuscated TCP.
	var mode TCPMode
	if mode != TCPModeIntermediate {
		t.Fatalf("zero TCPMode = %d, want TCPModeIntermediate", mode)
	}
	if got := mode.Transport(); got != TransportIntermediate {
		t.Errorf("zero-value Transport() = %d, want TransportIntermediate", got)
	}
	if mode.Obfuscated() {
		t.Errorf("zero-value Obfuscated() = true, want false")
	}
}

func TestTCPModeApplyWritesOnlyTransportAndObfuscate(t *testing.T) {
	cases := []TCPMode{
		TCPModeIntermediate,
		TCPModeAbridged,
		TCPModeObfuscatedAbridged,
		TCPModeObfuscatedIntermediate,
	}
	for _, mode := range cases {
		config := Config{
			APIID:     42,
			APIHash:   "hash",
			Transport: TransportPaddedIntermediate,
			Obfuscate: true,
			BotToken:  "token",
			Address:   "127.0.0.1:1",
			AuthKeyID: 7,
		}
		mode.Apply(&config)
		if config.Transport != mode.Transport() {
			t.Errorf("%s.Apply left Transport=%d, want %d", mode, config.Transport, mode.Transport())
		}
		if config.Obfuscate != mode.Obfuscated() {
			t.Errorf("%s.Apply left Obfuscate=%v, want %v", mode, config.Obfuscate, mode.Obfuscated())
		}
		// No other field should change.
		if config.APIID != 42 || config.APIHash != "hash" ||
			config.BotToken != "token" || config.Address != "127.0.0.1:1" ||
			config.AuthKeyID != 7 {
			t.Errorf("%s.Apply mutated unrelated fields: %+v", mode, config)
		}
	}
}

func TestTCPModeApplyNilConfigIsSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Apply(nil) panicked: %v", r)
		}
	}()
	TCPModeObfuscatedAbridged.Apply(nil)
}

func TestTCPModeProducesValidConfigs(t *testing.T) {
	// Every named mode must reduce to a Config that passes validation, so
	// the helper can never hand back an unusable transport combination.
	for _, mode := range []TCPMode{
		TCPModeIntermediate,
		TCPModeAbridged,
		TCPModeObfuscatedAbridged,
		TCPModeObfuscatedIntermediate,
	} {
		config := Config{APIID: 1, APIHash: "hash", Address: "127.0.0.1:1"}
		mode.Apply(&config)
		if err := config.validate(); err != nil {
			t.Errorf("%s produced invalid config: %v", mode, err)
		}
	}
}

func TestTCPModeDefaultConfigStaysIntermediate(t *testing.T) {
	// A Config that nobody touches must keep the historical default framing.
	var config Config
	if config.Transport != TransportIntermediate {
		t.Fatalf("default Config.Transport = %d, want TransportIntermediate", config.Transport)
	}
	if config.Obfuscate {
		t.Fatalf("default Config.Obfuscate = true, want false")
	}
}

func TestTCPModeString(t *testing.T) {
	cases := map[TCPMode]string{
		TCPModeIntermediate:           "TCPModeIntermediate",
		TCPModeAbridged:               "TCPModeAbridged",
		TCPModeObfuscatedAbridged:     "TCPModeObfuscatedAbridged",
		TCPModeObfuscatedIntermediate: "TCPModeObfuscatedIntermediate",
	}
	for mode, want := range cases {
		if got := mode.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", mode, got, want)
		}
	}
	if got := TCPMode(99).String(); got != "TCPMode(0x63)" {
		t.Errorf("unknown TCPMode String() = %q, want TCPMode(0x63)", got)
	}
	// Unknown modes degrade to intermediate, never panic.
	if got := TCPMode(99).Transport(); got != TransportIntermediate {
		t.Errorf("unknown TCPMode.Transport() = %d, want TransportIntermediate", got)
	}
	if TCPMode(99).Obfuscated() {
		t.Errorf("unknown TCPMode.Obfuscated() = true, want false")
	}
}
