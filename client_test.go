package raw

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/session"
	"github.com/mtgo-labs/raw/tl"
)

func TestClientPersistsLiveSessionState(t *testing.T) {
	store := session.NewMemoryStore()
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1", Store: store})
	if err != nil {
		t.Fatal(err)
	}
	var key mtproto.AuthKey
	key.ID = 9
	key.Key[0] = 7
	client.session = mtproto.NewSession(key, 13, [8]byte{1, 2, 3}, 2)
	client.mu.Lock()
	err = client.saveStateLocked()
	client.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Decode(data)
	if err != nil || snapshot.PrimaryDC != 2 || snapshot.AuthKeys[0].ID != 9 || snapshot.AuthKeys[0].Salt != 13 || !bytes.Equal(snapshot.AuthKeys[0].Key, append([]byte{7}, make([]byte, 255)...)) {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
}

func TestClientPersistsPermanentDCAuthKeys(t *testing.T) {
	store := session.NewMemoryStore()
	client, err := NewClient(Config{
		APIID: 1, Address: "127.0.0.1:1", Store: store,
		DCAuthKeys: map[int]AuthKeyConfig{
			4: {
				Key: bytes.Repeat([]byte{4}, 256), ID: 44, Salt: 45,
				TimeOffset: 46,
			},
			5: {
				Key: bytes.Repeat([]byte{5}, 256), ID: 55, ExpiresAt: 100,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var primary mtproto.AuthKey
	primary.ID = 22
	primary.Key[0] = 2
	primary.TimeOffset = 23
	client.session = mtproto.NewSession(primary, 24, [8]byte{2}, 2)
	client.mu.Lock()
	err = client.saveStateLocked()
	client.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.AuthKeys) != 2 || snapshot.AuthKeys[0].DCID != 2 || snapshot.AuthKeys[1].DCID != 4 {
		t.Fatalf("auth keys=%+v", snapshot.AuthKeys)
	}
	secondary, ok := snapshot.AuthKeyFor(4, "main")
	if !ok || secondary.ID != 44 || secondary.Salt != 45 || secondary.TimeOffset != 46 {
		t.Fatalf("secondary=%+v ok=%v", secondary, ok)
	}
	if _, ok := snapshot.AuthKeyFor(5, "main"); ok {
		t.Fatal("expiring authorization key was persisted")
	}
}

func TestClientLoadsPersistedDCAuthKeys(t *testing.T) {
	store := session.NewMemoryStore()
	data, err := session.Encode(session.Snapshot{
		APIID: 1, PrimaryDC: 2, SessionID: [8]byte{2},
		AuthKeys: []session.AuthKey{
			{DCID: 4, Kind: "main", Key: bytes.Repeat([]byte{4}, 256), ID: 44, Salt: 45, TimeOffset: 46},
			{DCID: 2, Kind: "main", Key: bytes.Repeat([]byte{2}, 256), ID: 22, Salt: 23, TimeOffset: 24},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), data); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(Config{
		APIID: 1, Address: "127.0.0.1:1", Store: store,
		DCAuthKeys: map[int]AuthKeyConfig{
			5: {Key: bytes.Repeat([]byte{5}, 256), ID: 55},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	state, err := client.authState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.key.ID != 22 || state.key.TimeOffset != 24 || state.salt != 23 || state.sessionID != [8]byte{2} {
		t.Fatalf("primary=%+v", state)
	}
	secondary := client.config.DCAuthKeys[4]
	if secondary.ID != 44 || secondary.Salt != 45 || secondary.TimeOffset != 46 {
		t.Fatalf("secondary=%+v", secondary)
	}
	if client.config.DCAuthKeys[5].ID != 55 {
		t.Fatal("explicit DC authorization key was replaced")
	}
}

func TestClientLoadsPersistedPrimaryDCWithoutEndpointConfig(t *testing.T) {
	store := session.NewMemoryStore()
	data, err := session.Encode(session.Snapshot{
		APIID:     1,
		PrimaryDC: 4,
		AuthKeys: []session.AuthKey{{
			DCID: 4,
			Kind: "main",
			Key:  bytes.Repeat([]byte{4}, 256),
			ID:   44,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), data); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(Config{APIID: 1, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.authState(context.Background()); err != nil {
		t.Fatal(err)
	}
	const wantAddress = "149.154.167.91:443"
	endpoint, ok := client.endpoints.Get(4)
	if client.config.DCID != 4 || client.config.Address != wantAddress ||
		!ok || endpoint.Address != wantAddress {
		t.Fatalf("config=%+v endpoint=%+v ok=%t", client.config, endpoint, ok)
	}
}

func TestNewClientAppliesDefaults(t *testing.T) {
	client, err := NewClient(Config{APIID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if client.config.PendingCapacity == 0 || client.config.MaxPayload == 0 || client.config.Logger == nil {
		t.Fatalf("defaults not applied: %+v", client.config)
	}
	if client.config.DCID != defaultDCID || client.config.Address != defaultProductionAddress {
		t.Fatalf("connection defaults not applied: %+v", client.config)
	}
	init := client.config.InitConnection
	if init.DeviceModel == "" || init.SystemVersion == "" || init.AppVersion == "" ||
		init.SystemLanguageCode != "en" || init.LanguageCode != "en" {
		t.Fatalf("initConnection defaults not applied: %+v", init)
	}
}

func TestNewClientAppliesTestAndConfiguredAddressDefaults(t *testing.T) {
	testClient, err := NewClient(Config{APIID: 1, TestMode: true})
	if err != nil {
		t.Fatal(err)
	}
	defer testClient.Close()
	if testClient.config.DCID != defaultDCID || testClient.config.Address != defaultTestAddress {
		t.Fatalf("test defaults not applied: %+v", testClient.config)
	}

	configuredClient, err := NewClient(Config{
		APIID:       1,
		DCID:        4,
		DCAddresses: map[int]string{4: "127.0.0.1:443"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer configuredClient.Close()
	if configuredClient.config.Address != "127.0.0.1:443" {
		t.Fatalf("configured address not applied: %+v", configuredClient.config)
	}

	defaultClient, err := NewClient(Config{APIID: 1, DCID: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer defaultClient.Close()
	if defaultClient.config.Address != "149.154.167.91:443" {
		t.Fatalf("DC 4 default not applied: %+v", defaultClient.config)
	}
}

func TestNewClientRejectsUnknownTransport(t *testing.T) {
	if _, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1", Transport: 3}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err=%v", err)
	}
}

func TestNewClientRejectsInvalidProxy(t *testing.T) {
	if _, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1", Proxy: ProxyConfig{Kind: ProxyHTTPConnect, Address: "bad"}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err=%v", err)
	}
}

func TestNewClientCopiesDCAddresses(t *testing.T) {
	addresses := map[int]string{2: "127.0.0.1:443"}
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1", DCAddresses: addresses})
	if err != nil {
		t.Fatal(err)
	}
	addresses[2] = "127.0.0.1:1"
	if client.config.DCAddresses[2] != "127.0.0.1:443" {
		t.Fatal("DC address map aliases caller")
	}
}

func TestInvokeWithOptionsRejectsUnconnectedRoute(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InvokeWithOptions(context.Background(), client, &tl.HelpGetConfigRequest{}, InvokeOptions{DCID: 3}); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("err=%v", err)
	}
}

func TestOrderedRequestWrapsPreviousMessage(t *testing.T) {
	request := &tl.HelpGetConfigRequest{}
	if got := orderedRequest(request, 0); got != request {
		t.Fatal("first ordered request was wrapped")
	}
	got, ok := orderedRequest(request, 17).(*tl.InvokeAfterMessageRequest[*tl.Config])
	if !ok || got.MessageID != 17 || got.Query != request {
		t.Fatalf("ordered request=%+v", got)
	}
}

func TestConnectDCRequiresAuthState(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1", DCAddresses: map[int]string{4: "127.0.0.1:4"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ConnectDC(context.Background(), 4); !errors.Is(err, ErrNoAuthKey) {
		t.Fatalf("err=%v", err)
	}
}

func TestConnectDCWithKindOpensPrimaryTransferRoutes(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 3)
	go acceptConnections(listener, accepted, cap(accepted))
	client, err := NewClient(Config{
		APIID: 1, Address: listener.Addr().String(),
		AuthKey: bytes.Repeat([]byte{1}, 256), AuthKeyID: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := client.ConnectDCWithKind(context.Background(), 0, ConnectionUpload); err != nil {
		t.Fatal(err)
	}
	if err := client.ConnectDCWithKind(context.Background(), 0, ConnectionDownload); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	upload := client.routes[routeKey{dcid: client.config.DCID, kind: ConnectionUpload}]
	download := client.routes[routeKey{dcid: client.config.DCID, kind: ConnectionDownload}]
	client.mu.Unlock()
	if upload == nil || download == nil {
		t.Fatalf("upload=%v download=%v", upload, download)
	}
	if upload.session.AuthKey().ID != 7 || download.session.AuthKey().ID != 7 {
		t.Fatal("transfer route did not reuse the primary authorization key")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	for range cap(accepted) {
		_ = (<-accepted).Close()
	}
}

func TestConnectDCWithKindRejectsUnknownKind(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ConnectDCWithKind(context.Background(), 4, ConnectionKind(3)); !errors.Is(err, ErrUnsupportedRoute) {
		t.Fatalf("err=%v", err)
	}
}

func TestConnectDCSlotEnforcesRouteLimits(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1", PoolSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		dcid int
		kind ConnectionKind
		slot int
	}{
		{name: "primary main advertised limit", dcid: 2, kind: ConnectionMain, slot: 1},
		{name: "primary upload pool limit", dcid: 2, kind: ConnectionUpload, slot: 2},
		{name: "secondary main pool limit", dcid: 4, kind: ConnectionMain, slot: 2},
		{name: "secondary download pool limit", dcid: 4, kind: ConnectionDownload, slot: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := client.ConnectDCSlot(context.Background(), test.dcid, test.kind, test.slot); !errors.Is(err, ErrUnsupportedRoute) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	if err := client.ConnectDCSlot(context.Background(), 2, ConnectionUpload, 1); !errors.Is(err, ErrNoAuthKey) {
		t.Fatalf("in-range route err=%v", err)
	}
}

func TestConnectDCRejectsExpiredAuthKey(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1", DCAddresses: map[int]string{4: "127.0.0.4:443"}, DCAuthKeys: map[int]AuthKeyConfig{4: {Key: bytes.Repeat([]byte{1}, 256), ID: 1, ExpiresAt: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ConnectDC(context.Background(), 4); !errors.Is(err, ErrAuthKeyExpired) {
		t.Fatalf("err=%v", err)
	}
}

func TestAuthKeyConfigExpiredUsesControlledClock(t *testing.T) {
	auth := AuthKeyConfig{ExpiresAt: 100}
	if auth.Expired(time.Unix(99, 0)) {
		t.Fatal("key expired before configured deadline")
	}
	if !auth.Expired(time.Unix(100, 0)) {
		t.Fatal("key remained valid at configured deadline")
	}
	if (AuthKeyConfig{}).Expired(time.Unix(1<<62, 0)) {
		t.Fatal("permanent key reported expired")
	}
}

func TestActivateTemporaryAuthKeyKeepsPermanentKeyForPersistence(t *testing.T) {
	store := session.NewMemoryStore()
	permanentBytes := bytes.Repeat([]byte{1}, 256)
	client, err := NewClient(Config{
		APIID: 1, Address: "127.0.0.1:1", Store: store,
		AuthKey: permanentBytes, AuthKeyID: 7, Salt: 9,
	})
	if err != nil {
		t.Fatal(err)
	}
	permanent, err := mtproto.RestoreAuthKey(permanentBytes, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	client.session = mtproto.NewSession(permanent, 9, [8]byte{1}, 2)
	client.permanent = authState{key: permanent, salt: 9, sessionID: [8]byte{1}}
	client.now = func() time.Time { return time.Unix(100, 0) }
	temporary := AuthKeyConfig{
		Key: bytes.Repeat([]byte{2}, 256), ID: 11, Salt: 13, ExpiresAt: 200,
	}
	if err := client.ActivateTemporaryAuthKey(0, ConnectionMain, temporary); err != nil {
		t.Fatal(err)
	}
	if client.session.AuthKey().ID != 11 || client.session.Salt() != 13 {
		t.Fatal("temporary key was not activated")
	}
	client.mu.Lock()
	err = client.saveStateLocked()
	client.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.AuthKeys[0].ID != 7 || snapshot.AuthKeys[0].Salt != 9 {
		t.Fatalf("persisted temporary key: %+v", snapshot.AuthKeys[0])
	}
}

func TestActivateTemporaryAuthKeyRejectsExpiredKey(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return time.Unix(100, 0) }
	auth := AuthKeyConfig{Key: bytes.Repeat([]byte{2}, 256), ID: 11, ExpiresAt: 100}
	if err := client.ActivateTemporaryAuthKey(0, ConnectionMain, auth); !errors.Is(err, ErrAuthKeyExpired) {
		t.Fatalf("err=%v", err)
	}
}

func TestPFSBindingReplacesTemporaryKey(t *testing.T) {
	permanent := AuthKeyConfig{Key: bytes.Repeat([]byte{1}, 256), ID: 7}
	binding, err := NewPFSBinding(permanent)
	if err != nil {
		t.Fatal(err)
	}
	first := AuthKeyConfig{Key: bytes.Repeat([]byte{2}, 256), ID: 9, SessionID: [8]byte{1}, ExpiresAt: 200}
	second := AuthKeyConfig{Key: bytes.Repeat([]byte{3}, 256), ID: 11, SessionID: [8]byte{2}, ExpiresAt: 300}
	if err := binding.InstallTemporary(first); err != nil {
		t.Fatal(err)
	}
	if err := binding.InstallTemporary(second); err != nil {
		t.Fatal(err)
	}
	got, err := binding.temporaryAt(time.Unix(250, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != second.ID || got.SessionID != second.SessionID {
		t.Fatalf("temporary=%+v", got)
	}
}

func TestConnectConfiguredSessionsUsesAdvertisedSlots(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 2)
	go func() {
		for range 2 {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- connection
		}
	}()
	client, err := NewClient(Config{
		APIID: 1, Address: listener.Addr().String(),
		AuthKey: bytes.Repeat([]byte{1}, 256), AuthKeyID: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	limit := int32(2)
	if err := client.RefreshEndpoints(&tl.Config{TmpSessions: &limit}); err != nil {
		t.Fatal(err)
	}
	if err := client.ConnectConfiguredSessions(context.Background()); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	route := client.routes[routeKey{dcid: client.config.DCID, kind: ConnectionMain, slot: 1}]
	client.mu.Unlock()
	if route == nil {
		t.Fatal("second main session was not connected")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		connection := <-accepted
		_ = connection.Close()
	}
}

func TestPFS404InvalidatesOnlyAffectedSession(t *testing.T) {
	permanentConfig := AuthKeyConfig{Key: bytes.Repeat([]byte{1}, 256), ID: 7}
	binding, err := NewPFSBinding(permanentConfig)
	if err != nil {
		t.Fatal(err)
	}
	temporaryConfig := AuthKeyConfig{
		Key: bytes.Repeat([]byte{2}, 256), ID: 9, SessionID: [8]byte{3}, ExpiresAt: 200,
	}
	if err := binding.InstallTemporary(temporaryConfig); err != nil {
		t.Fatal(err)
	}
	if err := binding.state.MarkBound(); err != nil {
		t.Fatal(err)
	}
	temporary, _ := mtproto.RestoreAuthKey(temporaryConfig.Key, temporaryConfig.ID, 0)
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer right.Close()
	sessionState := mtproto.NewSession(temporary, 0, temporaryConfig.SessionID, 1)
	client.conn = left
	client.session = sessionState
	client.pfs = binding
	client.tempUntil = temporaryConfig.ExpiresAt
	route := &clientRoute{connection: left, session: sessionState}
	key := routeKey{dcid: client.config.DCID, kind: ConnectionMain, slot: 0}
	if !client.invalidatePFSRoute(key, route) {
		t.Fatal("PFS route was not invalidated")
	}
	if client.session != nil || client.conn != nil || !errors.Is(client.Err(), ErrPFSRebindRequired) {
		t.Fatalf("session=%v conn=%v err=%v", client.session, client.conn, client.Err())
	}
	if _, err := binding.temporaryAt(time.Unix(100, 0)); !errors.Is(err, ErrNoAuthKey) {
		t.Fatalf("temporary key remains installed: %v", err)
	}
	if _, err := InvokeWithOptions(context.Background(), client, &tl.HelpGetConfigRequest{}, InvokeOptions{}); !errors.Is(err, ErrPFSRebindRequired) {
		t.Fatalf("invoke after 404 err=%v", err)
	}
}

func TestClientRejectsInvalidConfig(t *testing.T) {
	if _, err := NewClient(Config{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err=%v", err)
	}
	if _, err := NewClient(Config{APIID: 1, Address: "x", AuthKey: []byte("short")}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("auth key err=%v", err)
	}
}

func TestClientUpdateOverflowTerminatesClient(t *testing.T) {
	client, err := NewClient(Config{
		APIID:        1,
		DCID:         2,
		Address:      "127.0.0.1:1",
		UpdateBuffer: 1,
		AuthKey:      bytes.Repeat([]byte{1}, 256),
		AuthKeyID:    1,
	})
	if err != nil {
		t.Fatal(err)
	}
	authKey := testAuthKey(2)
	sessionID := [8]byte{2}
	sessionState := mtproto.NewSession(authKey, 0, sessionID, 2)
	clientConnection, serverConnection := net.Pipe()
	route := &clientRoute{connection: clientConnection, session: sessionState}
	route.sender = newRouteSender(new(sync.Mutex), sessionState, clientConnection, time.Now, 2, nil)
	client.conn = clientConnection
	client.session = sessionState
	client.sender = route.sender

	serverDone := make(chan error, 1)
	go func() {
		defer serverConnection.Close()
		messageID := uint64(time.Now().Unix())<<32 | 1
		if err := writeServerObject(serverConnection, authKey, 0, sessionID, messageID, &tl.UpdatesTooLong{}); err != nil {
			serverDone <- err
			return
		}
		serverDone <- writeServerObject(serverConnection, authKey, 0, sessionID, messageID+4, &tl.UpdatesTooLong{})
	}()

	client.receiveRoute(routeKey{dcid: 2, kind: ConnectionMain}, route)
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if !errors.Is(client.Err(), ErrUpdateOverflow) {
		t.Fatalf("err=%v", client.Err())
	}
	select {
	case <-client.Done():
	default:
		t.Fatal("Done channel remains open")
	}
	if update, ok := <-client.Updates(); !ok || update == nil {
		t.Fatalf("buffered update=%T ok=%v", update, ok)
	}
	if update, ok := <-client.Updates(); ok || update != nil {
		t.Fatalf("closed update=%T ok=%v", update, ok)
	}
}

func TestClientCloseIsIdempotent(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.Done():
	default:
		t.Fatal("Done channel remains open")
	}
	if err := client.Connect(context.Background()); !errors.Is(err, mtproto.ErrSessionClosed) {
		t.Fatalf("connect after close err=%v", err)
	}
}

func TestClientConnectionFailureIsReconnectable(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1", AuthKey: bytes.Repeat([]byte{1}, 256), AuthKeyID: 1})
	if err != nil {
		t.Fatal(err)
	}
	client.fail(errors.New("connection lost"))
	select {
	case <-client.Done():
		t.Fatal("connection failure closed the client permanently")
	default:
	}
	if !errors.Is(client.Err(), errors.New("connection lost")) {
		// Compare the observable message without requiring a shared sentinel.
		if client.Err() == nil || client.Err().Error() != "connection lost" {
			t.Fatalf("err=%v", client.Err())
		}
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestClientConnectWithoutStoreRequiresPersistedKey(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Connect(context.Background()); !errors.Is(err, ErrNoAuthKey) {
		t.Fatalf("err=%v", err)
	}
}
