package raw

import (
	"context"
	"sync"
	"time"
)

const defaultFloodWaitStoreMinWait = 2 * time.Second

// floodWaitStore tracks per-method flood wait expiry times to proactively
// delay or reject requests that would immediately hit FLOOD_WAIT again.
// All methods are safe for concurrent use.
type floodWaitStore struct {
	mu      sync.Mutex
	entries map[uint32]time.Time
}

func newFloodWaitStore() *floodWaitStore {
	return &floodWaitStore{entries: make(map[uint32]time.Time)}
}

// check returns an error if the method's stored wait exceeds maxWait.
// If the stored wait is between minWait and maxWait, it sleeps and
// returns nil. Waits below minWait are ignored (entry cleared).
// Returns nil if the store is disabled or no entry exists.
func (store *floodWaitStore) check(
	ctx context.Context,
	method uint32,
	maxWait time.Duration,
	minWait time.Duration,
) error {
	if store == nil || maxWait <= 0 {
		return nil
	}
	store.mu.Lock()
	until, ok := store.entries[method]
	if !ok {
		store.mu.Unlock()
		return nil
	}
	delta := time.Until(until)
	if delta <= minWait {
		delete(store.entries, method)
		store.mu.Unlock()
		return nil
	}
	if delta > maxWait {
		store.mu.Unlock()
		return &floodWaitStoredError{Method: method, RetryAfter: delta}
	}
	store.mu.Unlock()

	timer := time.NewTimer(delta)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	return nil
}

// record stores a flood wait for method, so subsequent requests are
// proactively delayed. Does nothing when store is nil or when wait is
// below the minimum threshold. SLOWMODE_WAIT is never stored because
// it is per-chat, not per-method.
func (store *floodWaitStore) record(method uint32, wait time.Duration, isSlowMode bool) {
	if store == nil || isSlowMode || wait <= defaultFloodWaitStoreMinWait {
		return
	}
	store.mu.Lock()
	store.entries[method] = time.Now().Add(wait)
	store.mu.Unlock()
}

// floodWaitStoredError signals that a stored flood wait exceeds the
// configured maximum, so the request was rejected without sending.
type floodWaitStoredError struct {
	Method     uint32
	RetryAfter time.Duration
}

func (e *floodWaitStoredError) Error() string {
	return "flood wait: method has an active flood wait, retry after " + e.RetryAfter.String()
}
