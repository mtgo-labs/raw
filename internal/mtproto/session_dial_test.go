package mtproto

import (
	"context"
	"errors"
	"testing"
)

func TestDialSessionCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := DialSession(ctx, "192.0.2.1:443", AuthKey{}, 0, [8]byte{}, 1)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}
