package transport

import (
	"context"
	"errors"
	"testing"
)

func TestDialIntermediateRejectsInvalidArguments(t *testing.T) {
	if _, err := DialIntermediate(context.TODO(), "127.0.0.1:1"); err == nil {
		t.Fatal("nil context unexpectedly succeeded")
	}
	if _, err := DialIntermediate(context.Background(), ""); err == nil {
		t.Fatal("empty address unexpectedly succeeded")
	}
}

func TestDialIntermediateHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DialIntermediate(ctx, "192.0.2.1:443")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}
