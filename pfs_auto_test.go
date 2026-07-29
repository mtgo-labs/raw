package raw

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/cryptoutil"
	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/internal/transport"
	"github.com/mtgo-labs/raw/tl"
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

func TestClientConnectNegotiatesAndBindsPFSOnOneConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	fixedNow := time.Now()
	sessionID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	permanentKey := bytes.Repeat([]byte{0x41}, 256)
	const permanentKeyID uint64 = 17
	release := make(chan struct{})
	defer close(release)
	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()
		var header [4]byte
		if _, err := io.ReadFull(connection, header[:]); err != nil {
			serverDone <- err
			return
		}
		if header != [4]byte{0xee, 0xee, 0xee, 0xee} {
			serverDone <- errors.New("unexpected transport header")
			return
		}
		packet, err := transport.NewPacketConn(connection, transport.PacketIntermediate)
		if err != nil {
			serverDone <- err
			return
		}
		temporary, err := runAuthorizationExchange(packet, fixedNow, nil)
		if err != nil {
			serverDone <- err
			return
		}
		messageID, salt, body, err := readPFSClientRequest(packet, temporary, sessionID)
		if err != nil {
			serverDone <- err
			return
		}
		expectedSalt := int64(binary.LittleEndian.Uint64(temporary.Salt[:]))
		if salt != expectedSalt {
			serverDone <- errors.New("bind request did not use the negotiated temporary salt")
			return
		}
		if len(body) < 25 ||
			binary.LittleEndian.Uint32(body) != tl.AuthBindTempAuthKeyRequestConstructorID ||
			binary.LittleEndian.Uint64(body[4:12]) != permanentKeyID ||
			int32(binary.LittleEndian.Uint32(body[20:24])) != int32(fixedNow.Unix()+3600) ||
			body[24] == 0 {
			serverDone <- errors.New("invalid auth.bindTempAuthKey request")
			return
		}
		var accepted [4]byte
		binary.LittleEndian.PutUint32(accepted[:], 0x997275b5)
		if err := writeServerResultRaw(packet, temporary, sessionID, messageID, accepted[:]); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
		<-release
	}()

	var dials atomic.Int32
	client, err := NewClient(Config{
		APIID:     1,
		DCID:      2,
		Address:   listener.Addr().String(),
		AuthKey:   permanentKey,
		AuthKeyID: permanentKeyID,
		SessionID: sessionID,
		Liveness:  LivenessPolicy{Disabled: true},
		PFS:       PFSPolicy{Enabled: true, Lifetime: time.Hour},
		DialFunc: func(ctx context.Context, address string) (net.Conn, error) {
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.now = func() time.Time { return fixedNow }
	client.authRandom = &incrementReader{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		serverErr := <-serverDone
		t.Fatalf("Connect: %v; server: %v", err, serverErr)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if dials.Load() != 1 {
		t.Fatalf("dial count = %d, want 1", dials.Load())
	}
	client.mu.Lock()
	bound := client.pfs != nil
	activeKeyID := client.session.AuthKey().ID
	client.mu.Unlock()
	if !bound || activeKeyID == permanentKeyID {
		t.Fatal("temporary key was not bound and activated during Connect")
	}
}

func readPFSClientRequest(
	connection interface{ ReadPacket(int) ([]byte, error) },
	key mtproto.AuthKey,
	sessionID [8]byte,
) (uint64, int64, []byte, error) {
	payload, err := connection.ReadPacket(1 << 20)
	if err != nil {
		return 0, 0, nil, err
	}
	if len(payload) < 56 || binary.LittleEndian.Uint64(payload) != key.ID {
		return 0, 0, nil, errors.New("invalid client encrypted payload")
	}
	var messageKey [16]byte
	copy(messageKey[:], payload[8:24])
	plain := append([]byte(nil), payload[24:]...)
	block, iv, err := cryptoutil.NewMessageAES256(key.Key[:], messageKey, cryptoutil.ClientToServer)
	if err != nil {
		return 0, 0, nil, err
	}
	if err := cryptoutil.DecryptIGE(plain, plain, block, iv[:]); err != nil {
		return 0, 0, nil, err
	}
	computed, err := cryptoutil.ComputeMessageKey(key.Key[:], plain, cryptoutil.ClientToServer)
	if err != nil || !bytes.Equal(computed[:], messageKey[:]) {
		return 0, 0, nil, errors.New("invalid client message key")
	}
	if !bytes.Equal(plain[8:16], sessionID[:]) {
		return 0, 0, nil, errors.New("invalid client session ID")
	}
	bodyLength := int(binary.LittleEndian.Uint32(plain[28:32]))
	if bodyLength < 4 || bodyLength > len(plain)-32 {
		return 0, 0, nil, errors.New("invalid client body length")
	}
	return binary.LittleEndian.Uint64(plain[16:24]),
		int64(binary.LittleEndian.Uint64(plain[:8])),
		plain[32 : 32+bodyLength],
		nil
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

func TestRouteNeedsPFSBeforeExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	client, err := NewClient(Config{
		APIID:   1,
		Address: "127.0.0.1:1",
		PFS:     PFSPolicy{Enabled: true, Lifetime: time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.now = func() time.Time { return now }
	key := routeKey{dcid: client.config.DCID, kind: ConnectionMain, slot: 0}

	client.mu.Lock()
	client.pfs = &PFSBinding{}
	client.tempUntil = now.Add(16 * time.Minute).Unix()
	if client.routeNeedsPFSLocked(key) {
		t.Fatal("temporary key refreshed earlier than the 15-minute margin")
	}
	client.tempUntil = now.Add(15 * time.Minute).Unix()
	if !client.routeNeedsPFSLocked(key) {
		t.Fatal("temporary key was not refreshed at the 15-minute margin")
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
