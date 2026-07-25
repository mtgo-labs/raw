package raw

import (
	"context"
	"net"
	"testing"
)

func TestConfigDialFuncNilByDefault(t *testing.T) {
	// The zero-value Config must have DialFunc=nil so existing callers
	// keep the standard net.Dialer transport without any changes.
	var config Config
	if config.DialFunc != nil {
		t.Fatal("zero-value Config.DialFunc is non-nil, want nil")
	}
}

func TestConfigDialFuncPassesValidation(t *testing.T) {
	config := Config{
		APIID:    1,
		APIHash:  "hash",
		Address:  "127.0.0.1:1",
		DialFunc: func(context.Context, string) (net.Conn, error) { return nil, nil },
	}
	if err := config.validate(); err != nil {
		t.Fatalf("Config with DialFunc set failed validation: %v", err)
	}
}
