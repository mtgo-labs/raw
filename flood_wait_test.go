package raw

import (
	"context"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/tgerr"
)

func TestFloodWaitStoreCheckNoEntry(t *testing.T) {
	store := newFloodWaitStore()
	ctx := t.Context()
	maxWait := 10 * time.Second
	minWait := 2 * time.Second
	if err := store.check(ctx, 0xdeadbeef, maxWait, minWait); err != nil {
		t.Fatalf("check with no entry: %v", err)
	}
}

func TestFloodWaitStoreCheckBelowMinWait(t *testing.T) {
	store := newFloodWaitStore()
	method := uint32(0xdeadbeef)
	maxWait := 10 * time.Second
	minWait := 2 * time.Second

	// Record a wait smaller than minWait (1s < 2s)
	store.record(method, time.Second, false)

	// entry should have been dropped because wait <= defaultFloodWaitStoreMinWait
	ctx := t.Context()
	if err := store.check(ctx, method, maxWait, minWait); err != nil {
		t.Fatalf("check after below-min record: %v", err)
	}
}

func TestFloodWaitStoreCheckBetweenMinAndMax(t *testing.T) {
	store := newFloodWaitStore()
	method := uint32(0xdeadbeef)
	maxWait := 10 * time.Second
	minWait := 100 * time.Millisecond

	// Record a 3s wait
	store.record(method, 3*time.Second, false)

	// check should sleep and return nil
	start := time.Now()
	ctx := t.Context()
	if err := store.check(ctx, method, maxWait, minWait); err != nil {
		t.Fatalf("check between min and max: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 2*time.Second {
		t.Fatalf("check slept only %v, expected ~3s", elapsed)
	}
}

func TestFloodWaitStoreCheckExceedsMax(t *testing.T) {
	store := newFloodWaitStore()
	method := uint32(0xdeadbeef)
	maxWait := 1 * time.Second
	minWait := 100 * time.Millisecond

	// Record a 5s wait
	store.record(method, 5*time.Second, false)

	ctx := t.Context()
	err := store.check(ctx, method, maxWait, minWait)
	if err == nil {
		t.Fatal("expected error when wait exceeds max")
	}
	floodErr, ok := err.(*floodWaitStoredError)
	if !ok {
		t.Fatalf("expected *floodWaitStoredError, got %T: %v", err, err)
	}
	if floodErr.Method != method {
		t.Fatalf("method = %#x, want %#x", floodErr.Method, method)
	}
}

func TestFloodWaitStoreCheckContextCancelled(t *testing.T) {
	store := newFloodWaitStore()
	method := uint32(0xdeadbeef)
	maxWait := 10 * time.Second
	minWait := 100 * time.Millisecond

	store.record(method, 3*time.Second, false)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := store.check(ctx, method, maxWait, minWait)
	if err == nil {
		t.Fatal("expected context cancelled error")
	}
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestFloodWaitStoreRecordSlowModeNotStored(t *testing.T) {
	store := newFloodWaitStore()
	method := uint32(0xdeadbeef)
	maxWait := 10 * time.Second
	minWait := 100 * time.Millisecond

	// Record SLOWMODE_WAIT — should not be stored
	store.record(method, 5*time.Second, true)

	ctx := t.Context()
	if err := store.check(ctx, method, maxWait, minWait); err != nil {
		t.Fatalf("slowmode entry should not have been stored: %v", err)
	}
}

func TestFloodWaitStoreRecordBelowMinWaitNotStored(t *testing.T) {
	store := newFloodWaitStore()
	method := uint32(0xdeadbeef)
	maxWait := 10 * time.Second
	minWait := 100 * time.Millisecond

	// Record a wait below the minimum threshold
	store.record(method, 500*time.Millisecond, false)

	// Should have no effect — entry not stored
	ctx := t.Context()
	if err := store.check(ctx, method, maxWait, minWait); err != nil {
		t.Fatalf("below-min record should not persist: %v", err)
	}
}

func TestFloodWaitStoreNil(t *testing.T) {
	var store *floodWaitStore
	ctx := t.Context()

	if err := store.check(ctx, 0xdeadbeef, 10*time.Second, 2*time.Second); err != nil {
		t.Fatalf("nil store check: %v", err)
	}
	// record on nil store is a no-op (must not panic)
	store.record(0xdeadbeef, time.Second, false)
}

func TestFloodWaitStoreCheckMaxWaitZero(t *testing.T) {
	store := newFloodWaitStore()
	method := uint32(0xdeadbeef)
	store.record(method, 5*time.Second, false)

	// maxWait=0 disables the store
	ctx := t.Context()
	if err := store.check(ctx, method, 0, 2*time.Second); err != nil {
		t.Fatalf("zero max wait should skip check: %v", err)
	}
}

func TestFloodWaitStoredErrorString(t *testing.T) {
	err := &floodWaitStoredError{Method: 0xdeadbeef, RetryAfter: 5 * time.Second}
	s := err.Error()
	if s == "" {
		t.Fatal("Error() returned empty string")
	}
}

func TestFloodWaitDurationNormalizesZero(t *testing.T) {
	// FLOOD_WAIT_0 should normalize to 1 second
	err := tgerr.New(420, "FLOOD_WAIT_0")
	wait, ok := err.FloodWaitDuration()
	if !ok {
		t.Fatal("FloodWaitDuration returned false for FLOOD_WAIT_0")
	}
	if wait != time.Second {
		t.Fatalf("FloodWaitDuration = %v, want 1s", wait)
	}
}

func TestFloodWaitDurationHandlesAllVariants(t *testing.T) {
	tests := []struct {
		message string
		want    time.Duration
	}{
		{"FLOOD_WAIT_5", 5 * time.Second},
		{"FLOOD_PREMIUM_WAIT_3", 3 * time.Second},
		{"FLOOD_TEST_PHONE_WAIT_10", 10 * time.Second},
		{"SLOWMODE_WAIT_15", 15 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.message, func(t *testing.T) {
			err := tgerr.New(420, test.message)
			wait, ok := err.FloodWaitDuration()
			if !ok {
				t.Fatal("FloodWaitDuration returned false")
			}
			if wait != test.want {
				t.Fatalf("FloodWaitDuration = %v, want %v", wait, test.want)
			}
		})
	}
}
