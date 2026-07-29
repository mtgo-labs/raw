package raw

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
)

// TestAuthorizeTemp runs the full DH exchange for a temporary key against the
// same mock server used for permanent-key authorization.
func TestAuthorizeTemp(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	fixedNow := time.Unix(1_700_000_000, 123_000_000)
	release := make(chan struct{})
	serverDone := make(chan authorizationServerResult, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- authorizationServerResult{err: err}
			return
		}
		key, err := runAuthorizationServer(conn, fixedNow, release)
		serverDone <- authorizationServerResult{key: key, err: err}
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send the intermediate transport header so runAuthorizationServer can read it.
	if _, err := conn.Write([]byte{0xee, 0xee, 0xee, 0xee}); err != nil {
		t.Fatal(err)
	}

	const expiresIn int32 = 3600
	key, err := mtproto.AuthorizeTemp(context.Background(), conn, &incrementReader{}, func() time.Time { return fixedNow }, 2, expiresIn)
	if err != nil {
		t.Fatalf("AuthorizeTemp: %v", err)
	}
	if key.ID == 0 {
		t.Fatal("temp key ID is zero")
	}

	close(release)
	result := <-serverDone
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.key.ID != key.ID || !bytes.Equal(result.key.Key[:], key.Key[:]) {
		t.Fatal("client and server derived different temp keys")
	}
}

func TestAuthorizeTempRejectsZeroExpiry(t *testing.T) {
	if _, err := mtproto.AuthorizeTemp(context.Background(), nil, nil, time.Now, 2, 0); !errors.Is(err, mtproto.ErrInvalidAuthorization) {
		t.Fatalf("error = %v, want ErrInvalidAuthorization", err)
	}
}

func TestPFSLifetimeSeconds(t *testing.T) {
	tests := []struct {
		name     string
		config   PFSPolicy
		expected int32
	}{
		{"zero defaults to 24h", PFSPolicy{Enabled: true}, 86400},
		{"explicit 1h", PFSPolicy{Enabled: true, Lifetime: time.Hour}, 3600},
		{"over 24h clamped", PFSPolicy{Enabled: true, Lifetime: 48 * time.Hour}, 86400},
		{"under 1s floored to 86400", PFSPolicy{Enabled: true, Lifetime: 100 * time.Millisecond}, 86400},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1", PFS: test.config})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if got := client.pfsLifetimeSeconds(); got != test.expected {
				t.Fatalf("pfsLifetimeSeconds = %d, want %d", got, test.expected)
			}
		})
	}
}

func TestRouteNeedsPFSWhenEnabledNoBinding(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1", PFS: PFSPolicy{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.mu.Lock()
	defer client.mu.Unlock()
	key := routeKey{dcid: client.config.DCID, kind: ConnectionMain, slot: 0}
	if !client.routeNeedsPFSLocked(key) {
		t.Fatal("expected routeNeedsPFSLocked=true when PFS enabled but no binding")
	}
}

func TestRouteNeedsPFSDisabledWhenPFSOff(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.mu.Lock()
	defer client.mu.Unlock()
	key := routeKey{dcid: client.config.DCID, kind: ConnectionMain, slot: 0}
	if client.routeNeedsPFSLocked(key) {
		t.Fatal("expected routeNeedsPFSLocked=false when PFS disabled")
	}
}

func TestRouteNeedsPFSExpired(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1", PFS: PFSPolicy{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.mu.Lock()
	client.pfs = &PFSBinding{}
	client.tempUntil = 1 // expired
	client.mu.Unlock()
	key := routeKey{dcid: client.config.DCID, kind: ConnectionMain, slot: 0}
	client.mu.Lock()
	if !client.routeNeedsPFSLocked(key) {
		t.Fatal("expected routeNeedsPFSLocked=true when temp key expired")
	}
	client.mu.Unlock()
}

func TestRouteNeedsPFSInvalidated(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1", PFS: PFSPolicy{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	key := routeKey{dcid: client.config.DCID, kind: ConnectionMain, slot: 0}
	client.mu.Lock()
	if client.pfsInvalid == nil {
		client.pfsInvalid = make(map[routeKey]struct{})
	}
	client.pfsInvalid[key] = struct{}{}
	client.mu.Unlock()

	client.mu.Lock()
	if !client.routeNeedsPFSLocked(key) {
		t.Fatal("expected routeNeedsPFSLocked=true when route invalidated")
	}
	client.mu.Unlock()
}

func TestPFSClearsBindingOnConnect(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1", PFS: PFSPolicy{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.pfs = &PFSBinding{}
	client.tempUntil = 100
	// Simulate a fresh connect resetting PFS state.
	client.mu.Lock()
	client.pfs = nil
	client.tempUntil = 0
	client.mu.Unlock()
	if client.pfs != nil || client.tempUntil != 0 {
		t.Fatal("PFS state not cleared")
	}
}
