package raw

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/tl"
)

func TestClientRouteIdleCleanup(t *testing.T) {
	client, err := NewClient(Config{
		APIID: 1, Address: "127.0.0.1:1", PoolIdleTimeout: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	left, right := net.Pipe()
	defer right.Close()
	key := routeKey{dcid: 4, kind: ConnectionDownload}
	route := &clientRoute{
		connection: left,
		session:    mtproto.NewSession(testAuthKey(4), 0, [8]byte{4}, 1),
	}
	client.mu.Lock()
	client.routes[key] = route
	client.resetRouteIdleTimerLocked(key, route)
	client.mu.Unlock()

	closed := make(chan error, 1)
	go func() {
		var data [1]byte
		_, err := right.Read(data[:])
		closed <- err
	}()
	select {
	case err := <-closed:
		if err == nil {
			t.Fatal("idle route peer read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("idle route remained open")
	}
	client.mu.Lock()
	_, exists := client.routes[key]
	client.mu.Unlock()
	if exists {
		t.Fatal("idle route remained registered")
	}
}

func TestClientRouteIdleCleanupWaitsForPendingRequest(t *testing.T) {
	client, err := NewClient(Config{
		APIID: 1, Address: "127.0.0.1:1", PoolIdleTimeout: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	left, right := net.Pipe()
	defer right.Close()
	key := routeKey{dcid: 4, kind: ConnectionDownload}
	sessionState := mtproto.NewSession(testAuthKey(4), 0, [8]byte{4}, 1)
	route := &clientRoute{connection: left, session: sessionState}
	client.mu.Lock()
	client.routes[key] = route
	client.resetRouteIdleTimerLocked(key, route)
	idle := route.idle
	client.mu.Unlock()

	var wire bytes.Buffer
	if _, err := sessionState.Send(&wire, rand.Reader, time.Now(), &tl.MTPReqPQMulti{}); err != nil {
		t.Fatal(err)
	}
	client.closeIdleRoute(key, route, idle)

	client.mu.Lock()
	current := client.routes[key]
	client.mu.Unlock()
	if current != route {
		t.Fatal("route with a pending request was closed")
	}
}

func TestClientCloseClosesConnectionPool(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer right.Close()
	key := mtproto.PoolKey{DCID: 4, Kind: mtproto.ConnectionDownload}
	connection, err := client.pool.Acquire(key, func() (net.Conn, error) {
		return left, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.pool.Release(key, connection); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.pool.Acquire(key, func() (net.Conn, error) {
		return nil, nil
	}); !errors.Is(err, mtproto.ErrPoolClosed) {
		t.Fatalf("acquire after close err=%v", err)
	}
}

func BenchmarkRouteIdleTouch(b *testing.B) {
	client, err := NewClient(Config{
		APIID: 1, Address: "127.0.0.1:1", PoolIdleTimeout: time.Hour,
	})
	if err != nil {
		b.Fatal(err)
	}
	key := routeKey{dcid: 4, kind: ConnectionDownload}
	route := &clientRoute{}
	client.mu.Lock()
	client.routes[key] = route
	client.resetRouteIdleTimerLocked(key, route)
	client.mu.Unlock()
	defer client.Close()

	b.ReportAllocs()
	for b.Loop() {
		client.mu.Lock()
		client.resetRouteIdleTimerLocked(key, route)
		client.mu.Unlock()
	}
}

func testAuthKey(id byte) mtproto.AuthKey {
	var key mtproto.AuthKey
	key.ID = uint64(id)
	key.Key[0] = id
	return key
}

func TestNewClientRejectsNegativePoolIdleTimeout(t *testing.T) {
	_, err := NewClient(Config{
		APIID: 1, Address: "127.0.0.1:1", PoolIdleTimeout: -time.Second,
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err=%v", err)
	}
}

func TestNewClientDefaultsPoolIdleTimeout(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.config.PoolIdleTimeout != time.Minute {
		t.Fatalf("pool idle timeout=%v", client.config.PoolIdleTimeout)
	}
}

func TestPrimaryMainRouteHasNoIdleTimer(t *testing.T) {
	client, err := NewClient(Config{
		APIID: 1, Address: "127.0.0.1:1", PoolIdleTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	key := routeKey{dcid: client.config.DCID, kind: ConnectionMain, slot: 1}
	route := &clientRoute{}
	client.mu.Lock()
	client.routes[key] = route
	client.resetRouteIdleTimerLocked(key, route)
	client.mu.Unlock()
	if route.idle != nil {
		t.Fatal("primary main route received an idle timer")
	}
}

func TestRouteIdleTimerRefreshAfterPrimaryMigration(t *testing.T) {
	client, err := NewClient(Config{
		APIID: 1, Address: "127.0.0.1:1", PoolIdleTimeout: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	oldPrimary := routeKey{dcid: 2, kind: ConnectionMain, slot: 1}
	newPrimary := routeKey{dcid: 4, kind: ConnectionMain, slot: 1}
	oldRoute, newRoute := &clientRoute{}, &clientRoute{}
	client.mu.Lock()
	client.routes[oldPrimary] = oldRoute
	client.routes[newPrimary] = newRoute
	client.resetRouteIdleTimerLocked(oldPrimary, oldRoute)
	client.resetRouteIdleTimerLocked(newPrimary, newRoute)
	client.config.DCID = 4
	client.refreshRouteIdleTimersLocked()
	client.mu.Unlock()
	if oldRoute.idle == nil {
		t.Fatal("retired primary route did not receive an idle timer")
	}
	if newRoute.idle != nil {
		t.Fatal("promoted primary route retained an idle timer")
	}
}
