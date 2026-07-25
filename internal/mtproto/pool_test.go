package mtproto

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestConnectionPoolReuseAndLimit(t *testing.T) {
	pool := NewConnectionPool(1)
	key := PoolKey{DCID: 2, Kind: ConnectionMain}
	left, right := net.Pipe()
	defer right.Close()
	connection, err := pool.Acquire(key, func() (net.Conn, error) { return left, nil })
	if err != nil || connection != left {
		t.Fatalf("connection=%v err=%v", connection, err)
	}
	if _, err := pool.Acquire(key, func() (net.Conn, error) { return nil, nil }); !errors.Is(err, ErrPoolLimit) {
		t.Fatalf("second acquire err=%v", err)
	}
	if err := pool.Release(key, connection); err != nil {
		t.Fatal(err)
	}
	reused, err := pool.Acquire(key, func() (net.Conn, error) { t.Fatal("dialed instead of reusing"); return nil, nil })
	if err != nil || reused != left {
		t.Fatalf("reused=%v err=%v", reused, err)
	}
	_ = pool.Release(key, reused)
	if closed := pool.CloseIdle(time.Now().Add(time.Second), 0); closed != 1 {
		t.Fatalf("closed idle=%d", closed)
	}
}

func TestConnectionPoolCloseRejectsAcquire(t *testing.T) {
	pool := NewConnectionPool(1)
	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Acquire(PoolKey{DCID: 2, Kind: ConnectionUpload}, func() (net.Conn, error) { return nil, nil }); !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("err=%v", err)
	}
}

func TestConnectionPoolSeparatesSessionSlots(t *testing.T) {
	pool := NewConnectionPool(1)
	left0, right0 := net.Pipe()
	defer right0.Close()
	left1, right1 := net.Pipe()
	defer right1.Close()
	key0 := PoolKey{DCID: 2, Kind: ConnectionMain, Slot: 0}
	key1 := PoolKey{DCID: 2, Kind: ConnectionMain, Slot: 1}
	if _, err := pool.Acquire(key0, func() (net.Conn, error) { return left0, nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Acquire(key1, func() (net.Conn, error) { return left1, nil }); err != nil {
		t.Fatal(err)
	}
	_ = pool.Discard(key0, left0)
	_ = pool.Discard(key1, left1)
}
