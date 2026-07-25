package raw

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
)

func TestClientCloseWaitsForReceiveActor(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	connection := newDelayedCloseConn()
	sessionState := mtproto.NewSession(testAuthKey(2), 0, [8]byte{2}, 1)
	key := routeKey{dcid: client.config.DCID, kind: ConnectionMain}
	client.mu.Lock()
	client.conn = connection
	client.session = sessionState
	client.permanent = authState{key: testAuthKey(2)}
	client.startReceiveRouteLocked(key, &clientRoute{connection: connection, session: sessionState})
	client.mu.Unlock()

	select {
	case <-connection.readStarted:
	case <-time.After(time.Second):
		t.Fatal("receive actor did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case <-connection.closed:
	case <-time.After(time.Second):
		t.Fatal("client did not close the receive connection")
	}
	select {
	case err := <-closed:
		t.Fatalf("Close returned before receive actor stopped: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(connection.release)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join the receive actor")
	}
}

func TestClientReceiveActorStopsAfterNetworkFailure(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	sessionState := mtproto.NewSession(testAuthKey(2), 0, [8]byte{2}, 1)
	key := routeKey{dcid: client.config.DCID, kind: ConnectionMain}
	client.mu.Lock()
	client.conn = left
	client.session = sessionState
	client.permanent = authState{key: testAuthKey(2)}
	client.startReceiveRouteLocked(key, &clientRoute{connection: left, session: sessionState})
	client.mu.Unlock()

	if err := right.Close(); err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	go func() {
		client.receiveWG.Wait()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("receive actor leaked after network failure")
	}
	if client.Err() == nil {
		t.Fatal("network failure was not retained")
	}
	if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

type delayedCloseConn struct {
	readStarted chan struct{}
	closed      chan struct{}
	release     chan struct{}
	readOnce    sync.Once
	closeOnce   sync.Once
}

func newDelayedCloseConn() *delayedCloseConn {
	return &delayedCloseConn{
		readStarted: make(chan struct{}),
		closed:      make(chan struct{}),
		release:     make(chan struct{}),
	}
}

func (connection *delayedCloseConn) Read([]byte) (int, error) {
	connection.readOnce.Do(func() { close(connection.readStarted) })
	<-connection.closed
	<-connection.release
	return 0, net.ErrClosed
}

func (*delayedCloseConn) Write(payload []byte) (int, error) { return len(payload), nil }

func (connection *delayedCloseConn) Close() error {
	connection.closeOnce.Do(func() { close(connection.closed) })
	return nil
}

func (*delayedCloseConn) LocalAddr() net.Addr              { return nil }
func (*delayedCloseConn) RemoteAddr() net.Addr             { return nil }
func (*delayedCloseConn) SetDeadline(time.Time) error      { return nil }
func (*delayedCloseConn) SetReadDeadline(time.Time) error  { return nil }
func (*delayedCloseConn) SetWriteDeadline(time.Time) error { return nil }
