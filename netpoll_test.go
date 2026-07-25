package raw

import "testing"

func TestConfigNetPollFalseByDefault(t *testing.T) {
	// The zero-value Config must have NetPoll=false so existing callers
	// keep the standard TCP transport without any changes.
	var config Config
	if config.NetPoll {
		t.Fatal("zero-value Config.NetPoll = true, want false")
	}
}

func TestConfigNetPollPassesValidation(t *testing.T) {
	config := Config{APIID: 1, APIHash: "hash", Address: "127.0.0.1:1", NetPoll: true}
	if err := config.validate(); err != nil {
		t.Fatalf("Config with NetPoll=true failed validation: %v", err)
	}
}
