package raw

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/session"
	"github.com/mtgo-labs/raw/tgerr"
	"github.com/mtgo-labs/raw/tl"
	"time"
)

func TestTransferAuthorizationBuildsExactRequests(t *testing.T) {
	exportedBytes := []byte{1, 2, 3}
	var exportRequest *tl.AuthExportAuthorizationRequest
	var importRequest *tl.AuthImportAuthorizationRequest
	err := transferAuthorization(
		4,
		func(request *tl.AuthExportAuthorizationRequest) (*tl.AuthExportedAuthorization, error) {
			exportRequest = request
			return &tl.AuthExportedAuthorization{ID: 7, Bytes: exportedBytes}, nil
		},
		func(request *tl.AuthImportAuthorizationRequest) (tl.AuthAuthorizationClass, error) {
			importRequest = request
			return &tl.AuthAuthorization{}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if exportRequest == nil || exportRequest.DCID != 4 {
		t.Fatalf("export request=%+v", exportRequest)
	}
	if importRequest == nil || importRequest.ID != 7 || !bytes.Equal(importRequest.Bytes, exportedBytes) {
		t.Fatalf("import request=%+v", importRequest)
	}
	if &importRequest.Bytes[0] != &exportedBytes[0] {
		t.Fatal("authorization bytes were copied between export and import")
	}
}

func TestTransferAuthorizationRejectsUnexpectedResult(t *testing.T) {
	err := transferAuthorization(
		4,
		func(*tl.AuthExportAuthorizationRequest) (*tl.AuthExportedAuthorization, error) {
			return &tl.AuthExportedAuthorization{ID: 7, Bytes: []byte{1}}, nil
		},
		func(*tl.AuthImportAuthorizationRequest) (tl.AuthAuthorizationClass, error) {
			return &tl.AuthAuthorizationSignUpRequired{}, nil
		},
	)
	if !errors.Is(err, ErrAuthTransfer) {
		t.Fatalf("err=%v", err)
	}
}

func TestAuthorizationTransferDeduplicatesPerDC(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	first, owner := client.beginAuthorizationTransfer(4)
	if !owner {
		t.Fatal("first transfer did not acquire ownership")
	}
	second, owner := client.beginAuthorizationTransfer(4)
	if owner || second != first {
		t.Fatal("concurrent transfer was not deduplicated")
	}
	want := errors.New("transfer failed")
	client.finishAuthorizationTransfer(4, first, want)
	<-second.done
	if !errors.Is(second.err, want) {
		t.Fatalf("err=%v", second.err)
	}
	third, owner := client.beginAuthorizationTransfer(4)
	if !owner || third == first {
		t.Fatal("completed transfer remained registered")
	}
	client.finishAuthorizationTransfer(4, third, nil)
}

func TestConnectMigrationRouteCreatesMainAndSelectedRoute(t *testing.T) {
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
		DCAddresses: map[int]string{4: listener.Addr().String()},
		DCAuthKeys: map[int]AuthKeyConfig{
			4: {Key: bytes.Repeat([]byte{4}, 256), ID: 44},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.connectMigrationRoute(context.Background(), 4, InvokeOptions{Kind: ConnectionUpload}); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	mainRoute := client.routes[routeKey{dcid: 4, kind: ConnectionMain}]
	uploadRoute := client.routes[routeKey{dcid: 4, kind: ConnectionUpload}]
	client.mu.Unlock()
	if mainRoute == nil || uploadRoute == nil {
		t.Fatalf("main=%v upload=%v", mainRoute, uploadRoute)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		_ = (<-accepted).Close()
	}
}

func TestPrimaryMigrationClassification(t *testing.T) {
	for _, message := range []string{"NETWORK_MIGRATE_4", "PHONE_MIGRATE_4", "USER_MIGRATE_4"} {
		if !isPrimaryMigration(tgerr.New(303, message)) {
			t.Fatalf("%q was not classified as a primary migration", message)
		}
	}
	if isPrimaryMigration(tgerr.New(303, "FILE_MIGRATE_4")) {
		t.Fatal("file migration was classified as a primary migration")
	}
}

func TestChangePrimaryDCDiscoversAndAuthorizesTarget(t *testing.T) {
	primaryListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer primaryListener.Close()
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetListener.Close()

	fixedNow := time.Now()
	primaryKey := testAuthKey(2)
	primarySessionID := [8]byte{2}
	primaryRelease := make(chan struct{})
	primaryDone := make(chan error, 1)
	go func() {
		connection, err := primaryListener.Accept()
		if err != nil {
			primaryDone <- err
			return
		}
		defer connection.Close()
		var header [4]byte
		if _, err = io.ReadFull(connection, header[:]); err == nil && header != [4]byte{0xee, 0xee, 0xee, 0xee} {
			err = errors.New("invalid primary transport header")
		}
		var messageID uint64
		if err == nil {
			messageID, _, err = readClientRequest(connection, primaryKey, primarySessionID)
		}
		targetAddress := targetListener.Addr().(*net.TCPAddr)
		if err == nil {
			err = writeServerResult(connection, primaryKey, primarySessionID, messageID, &tl.Config{
				DCOptions: []tl.DCOptionClass{&tl.DCOption{
					ID:        4,
					IPAddress: targetAddress.IP.String(),
					Port:      int32(targetAddress.Port),
				}},
			})
		}
		if err == nil {
			<-primaryRelease
		}
		primaryDone <- err
	}()

	targetRelease := make(chan struct{})
	targetDone := make(chan authorizationServerResult, 1)
	go func() {
		connection, err := targetListener.Accept()
		if err != nil {
			targetDone <- authorizationServerResult{err: err}
			return
		}
		key, err := runAuthorizationServer(connection, fixedNow, targetRelease)
		targetDone <- authorizationServerResult{key: key, err: err}
	}()

	store := session.NewMemoryStore()
	client, err := NewClient(Config{
		APIID: 1, DCID: 2, Address: primaryListener.Addr().String(), Store: store,
		AuthKey: append([]byte(nil), primaryKey.Key[:]...), AuthKeyID: primaryKey.ID,
		SessionID: primarySessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return fixedNow }
	client.authRandom = &incrementReader{}
	if err := client.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.changePrimaryDC(ctx, 4); err != nil {
		t.Fatalf("change primary DC: %v (client error: %v)", err, client.Err())
	}
	targetAuth := client.config.DCAuthKeys[4]
	if client.config.DCID != 4 || targetAuth.ID == 0 ||
		client.session.AuthKey().ID != targetAuth.ID {
		t.Fatalf("primary=%d target auth=%+v", client.config.DCID, targetAuth)
	}
	data, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	sourcePersisted, sourceOK := snapshot.AuthKeyFor(2, "main")
	targetPersisted, targetOK := snapshot.AuthKeyFor(4, "main")
	if snapshot.PrimaryDC != 4 || !sourceOK || !targetOK ||
		sourcePersisted.ID != primaryKey.ID || targetPersisted.ID != targetAuth.ID {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	close(primaryRelease)
	close(targetRelease)
	if err := <-primaryDone; err != nil {
		t.Fatal(err)
	}
	result := <-targetDone
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.key.ID != targetAuth.ID {
		t.Fatalf("server auth key ID=%d client=%d", result.key.ID, targetAuth.ID)
	}
}

func TestChangePrimaryDCPersistsAndRetiresOldSession(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 2)
	go acceptConnections(listener, accepted, 2)
	store := session.NewMemoryStore()
	client, err := NewClient(Config{
		APIID: 1, DCID: 2, Address: listener.Addr().String(), Store: store,
		AuthKey: bytes.Repeat([]byte{2}, 256), AuthKeyID: 22,
		AuthKeyTimeOffset: 23, Salt: 24, SessionID: [8]byte{2},
		DCAddresses: map[int]string{4: listener.Addr().String()},
		DCAuthKeys: map[int]AuthKeyConfig{
			4: {
				Key: bytes.Repeat([]byte{4}, 256), ID: 44, Salt: 45,
				SessionID: [8]byte{4}, TimeOffset: 46,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	client.initConnectionDone = true
	oldConnection, oldSession := client.conn, client.session
	if err := client.changePrimaryDC(context.Background(), 4); err != nil {
		t.Fatal(err)
	}
	if client.config.DCID != 4 || client.config.AuthKeyID != 44 || client.config.AuthKeyTimeOffset != 46 {
		t.Fatalf("primary config=%+v", client.config)
	}
	if client.conn == oldConnection || client.session == oldSession ||
		client.session.AuthKey().ID != 44 || client.session.AuthKey().TimeOffset != 46 {
		t.Fatal("primary connection and session were not replaced")
	}
	if client.initConnectionDone {
		t.Fatal("new primary connection inherited initialization state")
	}
	source := client.config.DCAuthKeys[2]
	if source.ID != 22 || source.Salt != 24 || source.TimeOffset != 23 || source.SessionID != [8]byte{2} {
		t.Fatalf("source auth=%+v", source)
	}
	data, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	sourcePersisted, sourceOK := snapshot.AuthKeyFor(2, "main")
	targetPersisted, targetOK := snapshot.AuthKeyFor(4, "main")
	if snapshot.PrimaryDC != 4 || !sourceOK || !targetOK ||
		sourcePersisted.ID != 22 || targetPersisted.ID != 44 ||
		sourcePersisted.TimeOffset != 23 || targetPersisted.TimeOffset != 46 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		_ = (<-accepted).Close()
	}
}

func TestChangePrimaryDCRollsBackStorageFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 2)
	go acceptConnections(listener, accepted, 2)
	saveErr := errors.New("save failed")
	store := &failSaveStore{MemoryStore: session.NewMemoryStore(), failAt: 2, err: saveErr}
	client, err := NewClient(Config{
		APIID: 1, DCID: 2, Address: listener.Addr().String(), Store: store,
		AuthKey: bytes.Repeat([]byte{2}, 256), AuthKeyID: 22, Salt: 24,
		DCAddresses: map[int]string{4: listener.Addr().String()},
		DCAuthKeys: map[int]AuthKeyConfig{
			4: {Key: bytes.Repeat([]byte{4}, 256), ID: 44, Salt: 45},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	client.initConnectionDone = true
	oldConnection, oldSession := client.conn, client.session
	if err := client.changePrimaryDC(context.Background(), 4); !errors.Is(err, saveErr) {
		t.Fatalf("err=%v", err)
	}
	if client.config.DCID != 2 || client.config.AuthKeyID != 22 ||
		client.conn != oldConnection || client.session != oldSession {
		t.Fatal("failed migration changed the primary session")
	}
	if !client.initConnectionDone {
		t.Fatal("failed migration discarded initialization state")
	}
	data, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Decode(data)
	if err != nil || snapshot.PrimaryDC != 2 {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	_ = client.Close()
	for range 2 {
		_ = (<-accepted).Close()
	}
}

func TestStaleRouteFailureDoesNotFailPromotedPrimary(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, DCID: 4, Address: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	var currentKey, staleKey mtproto.AuthKey
	currentKey.ID = 44
	staleKey.ID = 43
	currentClient, currentServer := net.Pipe()
	defer currentServer.Close()
	staleClient, staleServer := net.Pipe()
	defer staleClient.Close()
	defer staleServer.Close()
	client.conn = currentClient
	client.session = mtproto.NewSession(currentKey, 0, [8]byte{4}, 1)
	stale := &clientRoute{
		connection: staleClient,
		session:    mtproto.NewSession(staleKey, 0, [8]byte{3}, 1),
	}
	if client.failRoute(routeKey{dcid: 4, kind: ConnectionMain}, stale, errors.New("stale failure")) {
		t.Fatal("stale route was treated as the current primary")
	}
	if client.conn != currentClient || client.session.AuthKey().ID != 44 || client.Err() != nil {
		t.Fatal("stale route failure changed the current primary")
	}
	_ = currentClient.Close()
}

type failSaveStore struct {
	*session.MemoryStore
	failAt int
	saves  int
	err    error
}

func (store *failSaveStore) Save(ctx context.Context, data []byte) error {
	store.saves++
	if store.saves == store.failAt {
		return store.err
	}
	return store.MemoryStore.Save(ctx, data)
}

func acceptConnections(listener net.Listener, accepted chan<- net.Conn, count int) {
	for range count {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- connection
	}
}
