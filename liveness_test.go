package raw

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/tl"
)

func TestClientPingPongTracksRTT(t *testing.T) {
	client, server, key, sessionID, clock := newLivenessTranscriptClient(t, LivenessPolicy{
		PingInterval: 5 * time.Millisecond,
		PongTimeout:  100 * time.Millisecond,
	})
	serverDone := make(chan error, 1)
	go func() {
		messageID, body, err := readClientRequest(server, key, sessionID)
		if err != nil {
			serverDone <- err
			return
		}
		object, err := tl.Decode(body, tl.DefaultDecodeLimits())
		ping, ok := object.(*tl.MTPPingDelayDisconnect)
		if err == nil && (!ok || ping.PingID != 9 || ping.DisconnectDelay != 4) {
			err = errors.New("invalid ping_delay_disconnect")
		}
		if err == nil {
			clock.Add(int64(25 * time.Millisecond))
			err = writeServerObject(
				server,
				key,
				0,
				sessionID,
				messageID+1,
				&tl.MTPPong{MessageID: int64(messageID), PingID: ping.PingID},
			)
		}
		serverDone <- err
	}()

	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	keyRoute := routeKey{dcid: client.config.DCID, kind: ConnectionMain}
	deadline := time.Now().Add(time.Second)
	for {
		client.mu.Lock()
		liveness := client.liveness[keyRoute]
		client.mu.Unlock()
		if liveness != nil {
			if rtt, ok := liveness.rtt(); ok {
				if rtt != 25*time.Millisecond {
					t.Fatalf("RTT=%v", rtt)
				}
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("pong was not correlated")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestClientRepliesToServerPing(t *testing.T) {
	client, server, key, sessionID, _ := newLivenessTranscriptClient(t, LivenessPolicy{
		PingInterval: time.Hour,
		PongTimeout:  time.Second,
	})
	messageID := uint64(time.Now().Unix())<<32 | 1
	serverDone := make(chan error, 1)
	go func() {
		err := writeServerObject(server, key, 0, sessionID, messageID, &tl.MTPPing{PingID: 17})
		if err != nil {
			serverDone <- err
			return
		}
		_, body, err := readClientRequest(server, key, sessionID)
		if err == nil {
			object, decodeErr := tl.Decode(body, tl.DefaultDecodeLimits())
			if decodeErr != nil {
				err = decodeErr
			} else if pong, ok := object.(*tl.MTPPong); !ok || pong.MessageID != int64(messageID) || pong.PingID != 17 {
				err = errors.New("invalid pong")
			}
		}
		serverDone <- err
	}()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if client.Err() != nil {
		t.Fatalf("client err=%v", client.Err())
	}
}

func TestClientPingTimeoutDisconnectsRoute(t *testing.T) {
	client, server, key, sessionID, _ := newLivenessTranscriptClient(t, LivenessPolicy{
		PingInterval: 2 * time.Millisecond,
		PongTimeout:  5 * time.Millisecond,
	})
	messageID, body, err := readClientRequest(server, key, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	object, err := tl.Decode(body, tl.DefaultDecodeLimits())
	if err != nil {
		t.Fatal(err)
	}
	ping, ok := object.(*tl.MTPPingDelayDisconnect)
	if !ok {
		t.Fatalf("ping=%+v", object)
	}
	if err := writeServerObject(
		server,
		key,
		0,
		sessionID,
		messageID+1,
		&tl.MTPPong{MessageID: int64(messageID), PingID: ping.PingID + 1},
	); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		client.mu.Lock()
		connection := client.conn
		client.mu.Unlock()
		if connection == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ping timeout did not disconnect route")
		}
		time.Sleep(time.Millisecond)
	}
	if !errors.Is(client.Err(), ErrPingTimeout) {
		t.Fatalf("client err=%v", client.Err())
	}
}

func TestClientCloseJoinsRouteLiveness(t *testing.T) {
	client, _, _, _, _ := newLivenessTranscriptClient(t, LivenessPolicy{
		PingInterval: time.Hour,
		PongTimeout:  time.Hour,
	})
	start := time.Now()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("close waited %v", elapsed)
	}
}

func TestLivenessDefaultsAndValidation(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.config.Liveness.PingInterval != defaultPingInterval ||
		client.config.Liveness.PongTimeout != defaultPongTimeout ||
		pingDisconnectDelay(client.config.Liveness.PingInterval, client.config.Liveness.PongTimeout) != 77 {
		t.Fatalf(
			"liveness defaults=%+v disconnect=%d",
			client.config.Liveness,
			pingDisconnectDelay(client.config.Liveness.PingInterval, client.config.Liveness.PongTimeout),
		)
	}
	if _, err := NewClient(Config{
		APIID: 1, Address: "127.0.0.1:1",
		Liveness: LivenessPolicy{PingInterval: -1},
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid liveness err=%v", err)
	}
}

func TestClientDoesNotStartDisabledLiveness(t *testing.T) {
	client, err := NewClient(Config{
		APIID: 1, Address: "127.0.0.1:1",
		Liveness: LivenessPolicy{Disabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	connection, peer := net.Pipe()
	defer peer.Close()
	sessionState := mtproto.NewSession(testAuthKey(2), 0, [8]byte{2}, 1)
	client.mu.Lock()
	client.startRouteLivenessLocked(
		routeKey{dcid: client.config.DCID, kind: ConnectionMain},
		sessionState,
		connection,
		&client.writeMu,
	)
	count := len(client.liveness)
	client.mu.Unlock()
	if count != 0 {
		t.Fatalf("disabled liveness count=%d", count)
	}
	_ = connection.Close()
}

func TestConnectedRoutesStartLiveness(t *testing.T) {
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
		PoolSize:  1,
		Reconnect: ReconnectPolicy{Disabled: true},
		Liveness:  LivenessPolicy{PingInterval: time.Hour, PongTimeout: time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := client.ConnectDCWithKind(context.Background(), 2, ConnectionUpload); err != nil {
		t.Fatal(err)
	}
	first, second := <-accepted, <-accepted
	defer first.Close()
	defer second.Close()

	client.mu.Lock()
	primary := client.liveness[routeKey{dcid: 2, kind: ConnectionMain}]
	upload := client.liveness[routeKey{dcid: 2, kind: ConnectionUpload}]
	client.mu.Unlock()
	if primary == nil || upload == nil {
		t.Fatalf("primary=%v upload=%v", primary, upload)
	}
}

func TestRouteLivenessCorrelatesBothPongIDs(t *testing.T) {
	liveness := &routeLiveness{pong: make(chan struct{}, 1)}
	sentAt := time.Unix(1, 0)
	liveness.beginPing(7, sentAt)
	if liveness.finishPingSend(8) {
		t.Fatal("ping completed before pong")
	}
	if liveness.acceptPong(mtproto.InboundPong{MessageID: 9, PingID: 7}, sentAt.Add(time.Millisecond)) {
		t.Fatal("pong with wrong message ID was accepted")
	}
	if liveness.acceptPong(mtproto.InboundPong{MessageID: 8, PingID: 9}, sentAt.Add(time.Millisecond)) {
		t.Fatal("pong with wrong ping ID was accepted")
	}
	if !liveness.acceptPong(mtproto.InboundPong{MessageID: 8, PingID: 7}, sentAt.Add(2*time.Millisecond)) {
		t.Fatal("matching pong was rejected")
	}
	if rtt, ok := liveness.rtt(); !ok || rtt != 2*time.Millisecond {
		t.Fatalf("RTT=%v ok=%t", rtt, ok)
	}
}

func TestRouteLivenessCorrelatesEarlyPong(t *testing.T) {
	liveness := &routeLiveness{pong: make(chan struct{}, 1)}
	sentAt := time.Unix(1, 0)
	liveness.beginPing(7, sentAt)
	if liveness.acceptPong(mtproto.InboundPong{MessageID: 8, PingID: 7}, sentAt.Add(time.Millisecond)) {
		t.Fatal("pong completed before the outgoing message ID was known")
	}
	if !liveness.finishPingSend(8) {
		t.Fatal("early pong was not correlated after send")
	}
	if rtt, ok := liveness.rtt(); !ok || rtt != time.Millisecond {
		t.Fatalf("RTT=%v ok=%t", rtt, ok)
	}
}

func newLivenessTranscriptClient(
	t *testing.T,
	policy LivenessPolicy,
) (*Client, net.Conn, mtproto.AuthKey, [8]byte, *atomic.Int64) {
	t.Helper()
	client, err := NewClient(Config{
		APIID:     1,
		Address:   "127.0.0.1:1",
		Reconnect: ReconnectPolicy{Disabled: true},
		Liveness:  policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	connection, server := net.Pipe()
	key := testAuthKey(2)
	sessionID := [8]byte{2}
	sessionState := mtproto.NewSession(key, 0, sessionID, 4)
	clock := new(atomic.Int64)
	clock.Store(time.Now().UnixNano())
	client.now = func() time.Time { return time.Unix(0, clock.Load()) }
	client.pingJitter = func() time.Duration { return 0 }
	client.nextPingID = func() (int64, error) { return 9, nil }
	keyRoute := routeKey{dcid: client.config.DCID, kind: ConnectionMain}
	route := &clientRoute{connection: connection, session: sessionState}

	client.mu.Lock()
	client.conn = connection
	client.session = sessionState
	client.permanent = authState{key: key, sessionID: sessionID}
	client.startRouteLivenessLocked(keyRoute, sessionState, connection, &client.writeMu)
	client.startReceiveRouteLocked(keyRoute, route)
	client.mu.Unlock()

	t.Cleanup(func() {
		_ = server.SetDeadline(time.Now())
		_ = client.Close()
		_ = server.Close()
	})
	return client, server, key, sessionID, clock
}
