package mtproto

import (
	"errors"
	"net"
	"sync"
	"time"
)

type ConnectionKind uint8

const (
	ConnectionMain ConnectionKind = iota
	ConnectionUpload
	ConnectionDownload
)

var (
	ErrPoolLimit   = errors.New("mtproto: connection pool limit reached")
	ErrPoolClosed  = errors.New("mtproto: connection pool is closed")
	ErrInvalidPool = errors.New("mtproto: invalid connection pool key")
)

type PoolKey struct {
	DCID int
	Kind ConnectionKind
	Slot int
}

type pooledConnection struct {
	connection net.Conn
	usedAt     time.Time
}

type ConnectionPool struct {
	mu      sync.Mutex
	max     int
	closed  bool
	entries map[PoolKey][]pooledConnection
	active  map[PoolKey]int
}

func NewConnectionPool(maxPerKey int) *ConnectionPool {
	if maxPerKey < 1 {
		maxPerKey = 1
	}
	return &ConnectionPool{max: maxPerKey, entries: make(map[PoolKey][]pooledConnection), active: make(map[PoolKey]int)}
}

func (pool *ConnectionPool) Acquire(key PoolKey, dial func() (net.Conn, error)) (net.Conn, error) {
	if pool == nil || key.DCID <= 0 || key.Kind > ConnectionDownload || key.Slot < 0 || dial == nil {
		return nil, ErrInvalidPool
	}
	pool.mu.Lock()
	if pool.closed {
		pool.mu.Unlock()
		return nil, ErrPoolClosed
	}
	entries := pool.entries[key]
	if count := len(entries); count != 0 {
		entry := entries[count-1]
		pool.entries[key] = entries[:count-1]
		pool.active[key]++
		pool.mu.Unlock()
		return entry.connection, nil
	}
	if pool.active[key] >= pool.max {
		pool.mu.Unlock()
		return nil, ErrPoolLimit
	}
	pool.active[key]++
	pool.mu.Unlock()
	connection, err := dial()
	if err != nil {
		pool.mu.Lock()
		pool.active[key]--
		pool.mu.Unlock()
		return nil, err
	}
	return connection, nil
}

func (pool *ConnectionPool) Release(key PoolKey, connection net.Conn) error {
	if pool == nil || key.DCID <= 0 || key.Kind > ConnectionDownload || key.Slot < 0 || connection == nil {
		return ErrInvalidPool
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.active[key] > 0 {
		pool.active[key]--
	}
	if pool.closed {
		return connection.Close()
	}
	if len(pool.entries[key]) >= pool.max {
		return connection.Close()
	}
	pool.entries[key] = append(pool.entries[key], pooledConnection{connection: connection, usedAt: time.Now()})
	return nil
}

func (pool *ConnectionPool) Discard(key PoolKey, connection net.Conn) error {
	if pool == nil || key.DCID <= 0 || key.Kind > ConnectionDownload || key.Slot < 0 || connection == nil {
		return ErrInvalidPool
	}
	pool.mu.Lock()
	if pool.active[key] > 0 {
		pool.active[key]--
	}
	pool.mu.Unlock()
	return connection.Close()
}

func (pool *ConnectionPool) CloseIdle(now time.Time, maxIdle time.Duration) int {
	if pool == nil || maxIdle < 0 {
		return 0
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	closed := 0
	for key, entries := range pool.entries {
		kept := entries[:0]
		for _, entry := range entries {
			if now.Sub(entry.usedAt) >= maxIdle {
				_ = entry.connection.Close()
				closed++
				continue
			}
			kept = append(kept, entry)
		}
		if len(kept) == 0 {
			delete(pool.entries, key)
		} else {
			pool.entries[key] = kept
		}
	}
	return closed
}

func (pool *ConnectionPool) Close() error {
	if pool == nil {
		return nil
	}
	pool.mu.Lock()
	if pool.closed {
		pool.mu.Unlock()
		return nil
	}
	pool.closed = true
	entries := pool.entries
	pool.entries = make(map[PoolKey][]pooledConnection)
	pool.mu.Unlock()
	var first error
	for _, values := range entries {
		for _, entry := range values {
			if err := entry.connection.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}
