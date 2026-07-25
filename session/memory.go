package session

import (
	"context"
	"sync"
)

// MemoryStore keeps one session snapshot in memory. It is safe for concurrent
// Load and Save calls and copies bytes at the ownership boundary.
type MemoryStore struct {
	mu   sync.RWMutex
	data []byte
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{} }

func (store *MemoryStore) Load(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return append([]byte(nil), store.data...), nil
}

func (store *MemoryStore) Save(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	copyData := append([]byte(nil), data...)
	store.mu.Lock()
	store.data = copyData
	store.mu.Unlock()
	return nil
}
