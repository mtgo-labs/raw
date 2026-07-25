package raw

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"

	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/tl"
)

func TestClientAutomaticallyReconnectsPrimaryRoute(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 2)
	go acceptConnections(listener, accepted, 2)

	client, err := NewClient(Config{
		APIID: 1, Address: listener.Addr().String(),
		AuthKey: bytes.Repeat([]byte{1}, 256), AuthKeyID: 1,
		Reconnect: ReconnectPolicy{MaxAttempts: 2, InitialDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	var second net.Conn
	defer func() {
		_ = client.Close()
		if second != nil {
			_ = second.Close()
		}
	}()
	client.reconnectDelay = func(int) time.Duration { return 0 }
	var unix atomic.Int64
	unix.Store(1_700_000_000)
	client.now = func() time.Time { return time.Unix(unix.Load(), 0) }

	if err := client.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := <-accepted
	unix.Add(1)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case second = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("primary route was not reconnected")
	}
	client.mu.Lock()
	connection, sessionState, reconnecting := client.conn, client.session, len(client.reconnects)
	client.mu.Unlock()
	if connection == nil || sessionState == nil || reconnecting != 0 {
		t.Fatalf("connection=%v session=%v reconnecting=%d", connection, sessionState, reconnecting)
	}
}

func TestClientAutomaticallyReconnectsSecondaryRoute(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 2)
	go acceptConnections(listener, accepted, 2)

	client, err := NewClient(Config{
		APIID: 1, Address: listener.Addr().String(),
		PoolSize:  1,
		Reconnect: ReconnectPolicy{MaxAttempts: 2, InitialDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	var second net.Conn
	defer func() {
		_ = client.Close()
		if second != nil {
			_ = second.Close()
		}
	}()
	client.permanent = authState{key: testAuthKey(2)}
	client.reconnectDelay = func(int) time.Duration { return 0 }
	var unix atomic.Int64
	unix.Store(1_700_000_000)
	client.now = func() time.Time { return time.Unix(unix.Load(), 0) }

	if err := client.ConnectDCWithKind(context.Background(), 2, ConnectionUpload); err != nil {
		t.Fatal(err)
	}
	key := routeKey{dcid: 2, kind: ConnectionUpload}
	client.mu.Lock()
	oldSession := client.routes[key].session
	client.mu.Unlock()
	first := <-accepted
	unix.Add(1)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case second = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("secondary route was not reconnected")
	}
	client.mu.Lock()
	route, reconnecting := client.routes[key], len(client.reconnects)
	client.mu.Unlock()
	if route == nil || reconnecting != 0 {
		t.Fatalf("route=%v reconnecting=%d", route, reconnecting)
	}
	if _, err := oldSession.Send(nil, nil, time.Time{}, nil); !errors.Is(err, mtproto.ErrSessionClosed) {
		t.Fatalf("old session send err=%v", err)
	}
}

func TestPendingRequestSurvivesPrimaryReconnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 2)
	go acceptConnections(listener, accepted, 2)

	client, err := NewClient(Config{
		APIID: 1, Address: listener.Addr().String(),
		AuthKey: bytes.Repeat([]byte{1}, 256), AuthKeyID: 1,
		Reconnect: ReconnectPolicy{MaxAttempts: 2, InitialDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.reconnectDelay = func(int) time.Duration { return 0 }
	var unix atomic.Int64
	unix.Store(1_700_000_000)
	client.now = func() time.Time { return time.Unix(unix.Load(), 0) }

	if err := client.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := <-accepted
	client.mu.Lock()
	sessionState := client.session
	client.mu.Unlock()
	_, request, err := sessionState.Prepare(client.now(), &tl.HelpGetConfigRequest{})
	if err != nil {
		t.Fatal(err)
	}
	unix.Add(1)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second := <-accepted
	defer second.Close()
	// Poll for client.conn instead of reconnectWG.Wait() to avoid racing
	// WaitGroup.Add(1) in scheduleReconnectSession with Wait() when the
	// counter may be zero.
	for deadline := time.Now(); ; {
		client.mu.Lock()
		conn := client.conn
		client.mu.Unlock()
		if conn != nil {
			break
		}
		if time.Since(deadline) > 5*time.Second {
			t.Fatal("reconnect did not set client.conn within timeout")
		}
		time.Sleep(time.Millisecond)
	}
	client.mu.Lock()
	reconnectedSession := client.session
	connection := client.conn
	client.mu.Unlock()
	if reconnectedSession != sessionState || connection == nil {
		t.Fatalf("session=%p want=%p connection=%v", reconnectedSession, sessionState, connection)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	completed, err := sessionState.WaitPrepared(ctx, request)
	if !errors.Is(err, context.Canceled) || completed != request {
		t.Fatalf("completed=%+v err=%v", completed, err)
	}
}

func TestClientReconnectStopsAfterConfiguredAttempts(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(Config{
		APIID: 1, Address: address,
		AuthKey: bytes.Repeat([]byte{1}, 256), AuthKeyID: 1,
		Reconnect: ReconnectPolicy{MaxAttempts: 2, InitialDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.reconnectDelay = func(int) time.Duration { return 0 }
	var unix atomic.Int64
	unix.Store(1_700_000_000)
	client.now = func() time.Time {
		return time.Unix(unix.Add(1), 0)
	}

	key := routeKey{dcid: 2, kind: ConnectionMain}
	client.scheduleReconnect(key)
	client.reconnectWG.Wait()
	client.mu.Lock()
	attempts := client.connectionFloodLocked(key).attempts.length
	reconnecting := len(client.reconnects)
	client.mu.Unlock()
	if attempts != 2 || reconnecting != 0 {
		t.Fatalf("attempts=%d reconnecting=%d", attempts, reconnecting)
	}
}

func TestClientCloseCancelsAndJoinsReconnect(t *testing.T) {
	client, err := NewClient(Config{
		APIID: 1, Address: "127.0.0.1:1",
		AuthKey: bytes.Repeat([]byte{1}, 256), AuthKeyID: 1,
		Reconnect: ReconnectPolicy{MaxAttempts: 2, InitialDelay: time.Hour, MaxDelay: time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	var once sync.Once
	client.reconnectDelay = func(int) time.Duration {
		once.Do(func() { close(started) })
		return time.Hour
	}
	key := routeKey{dcid: 2, kind: ConnectionMain}
	client.scheduleReconnect(key)
	<-started
	client.scheduleReconnect(key)
	client.mu.Lock()
	reconnect := client.reconnects[key]
	count := len(client.reconnects)
	client.mu.Unlock()
	if reconnect == nil || !reconnect.again || count != 1 {
		t.Fatalf("reconnect=%+v count=%d", reconnect, count)
	}

	start := time.Now()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("close waited %v", elapsed)
	}
}

func TestClientCloseCancelsReconnectDial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go acceptConnections(listener, accepted, 1)

	client, err := NewClient(Config{
		APIID: 1, Address: "127.0.0.1:1",
		AuthKey: bytes.Repeat([]byte{1}, 256), AuthKeyID: 1,
		Proxy: ProxyConfig{Kind: ProxyHTTPConnect, Address: listener.Addr().String()},
		Reconnect: ReconnectPolicy{
			MaxAttempts:  2,
			InitialDelay: time.Millisecond,
			MaxDelay:     time.Millisecond,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client.reconnectDelay = func(int) time.Duration { return 0 }
	client.scheduleReconnect(routeKey{dcid: 2, kind: ConnectionMain})
	proxyConnection := <-accepted
	defer proxyConnection.Close()

	closed := make(chan error, 1)
	go func() {
		closed <- client.Close()
	}()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not cancel reconnect dial")
	}
}

func TestClientReconnectsAfterPrimaryWriteFailure(t *testing.T) {
	client, err := NewClient(Config{
		APIID: 1, Address: "127.0.0.1:1",
		AuthKey: bytes.Repeat([]byte{1}, 256), AuthKeyID: 1,
		Reconnect: ReconnectPolicy{
			MaxAttempts:  2,
			InitialDelay: time.Hour,
			MaxDelay:     time.Hour,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	connection := &writeFailureConn{}
	sessionState := mtproto.NewSession(testAuthKey(2), 0, [8]byte{2}, 1)
	key := routeKey{dcid: client.config.DCID, kind: ConnectionMain}
	client.mu.Lock()
	client.conn = connection
	client.session = sessionState
	client.permanent = authState{key: testAuthKey(2)}
	client.mu.Unlock()

	if _, err := invokeRoute(context.Background(), client, &tl.HelpGetConfigRequest{}, InvokeOptions{}); !errors.Is(err, errReconnectWrite) {
		t.Fatalf("invoke err=%v", err)
	}
	client.mu.Lock()
	currentConnection := client.conn
	reconnect := client.reconnects[key]
	client.mu.Unlock()
	if currentConnection != nil || reconnect == nil {
		t.Fatalf("connection=%v reconnect=%+v", currentConnection, reconnect)
	}
	if _, err := sessionState.Send(nil, nil, time.Time{}, nil); !errors.Is(err, mtproto.ErrSessionClosed) {
		t.Fatalf("old session send err=%v", err)
	}
}

func TestClientReconnectsAfterSecondaryWriteFailure(t *testing.T) {
	client, err := NewClient(Config{
		APIID: 1, Address: "127.0.0.1:1",
		Reconnect: ReconnectPolicy{
			MaxAttempts:  2,
			InitialDelay: time.Hour,
			MaxDelay:     time.Hour,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	connection := &writeFailureConn{}
	sessionState := mtproto.NewSession(testAuthKey(2), 0, [8]byte{2}, 1)
	key := routeKey{dcid: client.config.DCID, kind: ConnectionUpload}
	client.mu.Lock()
	client.permanent = authState{key: testAuthKey(2)}
	client.routes[key] = &clientRoute{connection: connection, session: sessionState}
	client.mu.Unlock()

	if _, err := invokeRoute(
		context.Background(),
		client,
		&tl.HelpGetConfigRequest{},
		InvokeOptions{Kind: ConnectionUpload},
	); !errors.Is(err, errReconnectWrite) {
		t.Fatalf("invoke err=%v", err)
	}
	client.mu.Lock()
	route := client.routes[key]
	reconnect := client.reconnects[key]
	client.mu.Unlock()
	if route != nil || reconnect == nil {
		t.Fatalf("route=%v reconnect=%+v", route, reconnect)
	}
	if _, err := sessionState.Send(nil, nil, time.Time{}, nil); !errors.Is(err, mtproto.ErrSessionClosed) {
		t.Fatalf("old session send err=%v", err)
	}
}

func TestClientDoesNotAutomaticallyReconnectPFSRoute(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	binding, err := NewPFSBinding(AuthKeyConfig{Key: bytes.Repeat([]byte{1}, 256), ID: 1})
	if err != nil {
		t.Fatal(err)
	}
	client.pfs = binding
	client.scheduleReconnect(routeKey{dcid: 2, kind: ConnectionMain})
	client.mu.Lock()
	count := len(client.reconnects)
	client.mu.Unlock()
	if count != 0 {
		t.Fatalf("PFS reconnect count=%d", count)
	}
}

func TestClientDoesNotAutomaticallyReconnectWhenDisabled(t *testing.T) {
	client, err := NewClient(Config{
		APIID:     1,
		Address:   "127.0.0.1:1",
		Reconnect: ReconnectPolicy{Disabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.scheduleReconnect(routeKey{dcid: 2, kind: ConnectionMain})
	client.mu.Lock()
	count := len(client.reconnects)
	client.mu.Unlock()
	if count != 0 {
		t.Fatalf("disabled reconnect count=%d", count)
	}
}

func TestReconnectDefaultsAndValidation(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.config.Reconnect.MaxAttempts != defaultReconnectAttempts ||
		client.config.Reconnect.InitialDelay != defaultReconnectDelay ||
		client.config.Reconnect.MaxDelay != defaultReconnectMaxDelay {
		t.Fatalf("reconnect defaults=%+v", client.config.Reconnect)
	}
	if _, err := NewClient(Config{
		APIID: 1, Address: "127.0.0.1:1",
		Reconnect: ReconnectPolicy{InitialDelay: time.Second, MaxDelay: time.Millisecond},
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid reconnect err=%v", err)
	}
}

func TestTerminalReconnectErrors(t *testing.T) {
	for _, err := range []error{
		ErrNoAuthKey,
		ErrAuthKeyExpired,
		ErrPFSRebindRequired,
		ErrUnsupportedRoute,
		ErrInvalidConfig,
		mtproto.ErrSessionClosed,
		context.Canceled,
	} {
		if !terminalReconnectError(err) {
			t.Fatalf("non-terminal error=%v", err)
		}
	}
}

func TestClientReconnectsPendingRequestTranscript(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 2)
	go acceptConnections(listener, accepted, 2)

	authKey := testAuthKey(2)
	client, err := NewClient(Config{
		APIID:     1,
		Address:   listener.Addr().String(),
		AuthKey:   append([]byte(nil), authKey.Key[:]...),
		AuthKeyID: authKey.ID,
		Reconnect: ReconnectPolicy{
			MaxAttempts:  2,
			InitialDelay: time.Millisecond,
			MaxDelay:     time.Millisecond,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client.reconnectDelay = func(int) time.Duration { return 0 }
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	var firstServer net.Conn
	select {
	case firstServer = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var transportHeader [4]byte
	if _, err := io.ReadFull(firstServer, transportHeader[:]); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(transportHeader[:]) != 0xeeeeeeee {
		t.Fatalf("first transport header=%x", transportHeader)
	}
	defer firstServer.Close()

	client.mu.Lock()
	sessionState := client.session
	sessionID := sessionState.SessionID()
	client.initConnectionDone = true
	client.mu.Unlock()

	type nearestResult struct {
		value *tl.NearestDC
		err   error
	}
	completed := make(chan nearestResult, 1)
	go func() {
		value, invokeErr := Invoke(ctx, client, &tl.HelpGetNearestDCRequest{})
		completed <- nearestResult{value: value, err: invokeErr}
	}()

	firstMessageID, firstBody, err := readClientRequest(firstServer, authKey, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstBody) < 4 || binary.LittleEndian.Uint32(firstBody) != tl.HelpGetNearestDCRequestConstructorID {
		t.Fatalf("first request=%x", firstBody)
	}
	if err := firstServer.Close(); err != nil {
		t.Fatal(err)
	}

	var secondServer net.Conn
	select {
	case secondServer = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := io.ReadFull(secondServer, transportHeader[:]); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(transportHeader[:]) != 0xeeeeeeee {
		t.Fatalf("second transport header=%x", transportHeader)
	}
	defer secondServer.Close()
	containerID, retryBody, err := readClientRequest(secondServer, authKey, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(retryBody) < 28 ||
		binary.LittleEndian.Uint32(retryBody) != tl.MTPMessageContainerConstructorID ||
		binary.LittleEndian.Uint32(retryBody[4:]) != 1 {
		t.Fatalf("retry container=%x", retryBody)
	}
	retryMessageID := binary.LittleEndian.Uint64(retryBody[8:])
	retrySize := int(binary.LittleEndian.Uint32(retryBody[20:]))
	if containerID <= retryMessageID ||
		retryMessageID != firstMessageID ||
		retrySize != len(retryBody)-24 ||
		retrySize < 4 ||
		binary.LittleEndian.Uint32(retryBody[24:]) != tl.HelpGetNearestDCRequestConstructorID {
		t.Fatalf(
			"container=%x retry=%x first=%x size=%d body=%x",
			containerID,
			retryMessageID,
			firstMessageID,
			retrySize,
			retryBody,
		)
	}
	if err := writeServerResult(
		secondServer,
		authKey,
		sessionID,
		retryMessageID,
		&tl.NearestDC{Country: "IQ", ThisDC: 2, NearestDC: 4},
	); err != nil {
		t.Fatal(err)
	}

	select {
	case result := <-completed:
		if result.err != nil ||
			result.value == nil ||
			result.value.Country != "IQ" ||
			result.value.ThisDC != 2 ||
			result.value.NearestDC != 4 {
			t.Fatalf("result=%+v err=%v", result.value, result.err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

var errReconnectWrite = errors.New("reconnect test write failure")

type writeFailureConn struct{}

func (*writeFailureConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (*writeFailureConn) Write([]byte) (int, error)        { return 0, errReconnectWrite }
func (*writeFailureConn) Close() error                     { return nil }
func (*writeFailureConn) LocalAddr() net.Addr              { return nil }
func (*writeFailureConn) RemoteAddr() net.Addr             { return nil }
func (*writeFailureConn) SetDeadline(time.Time) error      { return nil }
func (*writeFailureConn) SetReadDeadline(time.Time) error  { return nil }
func (*writeFailureConn) SetWriteDeadline(time.Time) error { return nil }
