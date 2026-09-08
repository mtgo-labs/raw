package raw

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/session"
	"github.com/mtgo-labs/raw/tl"
)

func TestNewClientImportsMtcuteSessionString(t *testing.T) {
	authKey := bytes.Repeat([]byte{0x42}, 256)
	encoded := testSessionString(t, session.SessionString{
		Version: session.MtcuteSessionStringVersion,
		Main:    session.SessionStringDC{ID: 4, Address: "149.154.167.91:443"},
		Media:   session.SessionStringDC{ID: 4, Address: "149.154.167.92:443", MediaOnly: true},
		User:    &session.SessionStringUser{ID: 12345, Bot: true},
		AuthKey: authKey,
	})
	client, err := NewClient(Config{APIID: 1, SessionString: encoded})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	digest := sha1.Sum(authKey)
	wantID := binary.LittleEndian.Uint64(digest[12:20])
	if client.config.DCID != 4 || client.config.Address != "149.154.167.91:443" ||
		client.config.AuthKeyID != wantID || !bytes.Equal(client.config.AuthKey, authKey) {
		t.Fatalf("config=%+v", client.config)
	}
	if client.config.SessionString != "" {
		t.Fatal("client retained encoded session string")
	}
	authKey[0] ^= 0xff
	if client.config.AuthKey[0] != 0x42 {
		t.Fatal("client auth key aliases caller input")
	}
}

func TestNewClientAutomaticallyImportsPyrogramTelethonAndRaw(t *testing.T) {
	authKey := bytes.Repeat([]byte{0x35}, 256)
	pyrogram := make([]byte, 271)
	pyrogram[0] = 4
	binary.BigEndian.PutUint32(pyrogram[1:5], 22333936)
	copy(pyrogram[6:262], authKey)
	binary.BigEndian.PutUint64(pyrogram[262:270], 12345)

	telethon := []byte{4, 149, 154, 167, 91}
	telethon = binary.BigEndian.AppendUint16(telethon, 443)
	telethon = append(telethon, authKey...)

	encryptionKey := bytes.Repeat([]byte{0x91}, 32)
	rawString, err := session.EncodeSessionString(session.SessionString{
		APIID: 22333936,
		Main: session.SessionStringDC{
			ID:      4,
			Address: "149.154.167.91:443",
		},
		AuthKey: authKey,
	}, encryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]Config{
		"pyrogram": {
			SessionString: base64.RawURLEncoding.EncodeToString(pyrogram),
		},
		"telethon": {
			APIID:         22333936,
			SessionString: "1" + base64.URLEncoding.EncodeToString(telethon),
		},
		"mtgo-raw": {
			SessionString:    rawString,
			SessionStringKey: encryptionKey,
		},
	}
	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			client, err := NewClient(config)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if client.config.APIID != 22333936 || client.config.DCID != 4 ||
				client.config.Address != "149.154.167.91:443" ||
				!bytes.Equal(client.config.AuthKey, authKey) ||
				client.config.SessionString != "" || len(client.config.SessionStringKey) != 0 {
				t.Fatalf("config=%+v", client.config)
			}
		})
	}
	client, err := NewClient(Config{
		APIID:         1,
		SessionString: base64.RawURLEncoding.EncodeToString(pyrogram),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.config.APIID != 1 {
		t.Fatalf("config APIID should be 1, got %d", client.config.APIID)
	}
	if !bytes.Equal(encryptionKey, bytes.Repeat([]byte{0x91}, 32)) {
		t.Fatal("NewClient modified the caller-owned encryption key")
	}
}

func TestNewClientImportsMTGOSessionString(t *testing.T) {
	authKey := bytes.Repeat([]byte{0x6e}, 256)
	encoded, err := session.EncodeMTGOSessionString(session.SessionString{
		APIID:       22333936,
		Main:        session.SessionStringDC{ID: 4},
		User:        &session.SessionStringUser{ID: 12345, Bot: true},
		AuthKey:     authKey,
		APIHash:     "89abcdef0123456789abcdef01234567",
		PhoneNumber: "+9996621234",
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(Config{SessionString: encoded})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	digest := sha1.Sum(authKey)
	wantID := binary.LittleEndian.Uint64(digest[12:20])
	if client.config.APIID != 22333936 || client.config.APIHash != "89abcdef0123456789abcdef01234567" ||
		client.config.DCID != 4 || client.config.Address != "149.154.167.91:443" ||
		client.config.AuthKeyID != wantID || !bytes.Equal(client.config.AuthKey, authKey) ||
		client.config.SessionString != "" {
		t.Fatalf("config=%+v", client.config)
	}
}

func TestNewClientRejectsUnsupportedMTGOVersion(t *testing.T) {
	authKey := bytes.Repeat([]byte{0x6e}, 256)
	encoded, err := session.EncodeMTGOSessionString(session.SessionString{
		APIID:   22333936,
		Main:    session.SessionStringDC{ID: 4},
		User:    &session.SessionStringUser{ID: 12345},
		AuthKey: authKey,
		APIHash: "89abcdef0123456789abcdef01234567",
	})
	if err != nil {
		t.Fatal(err)
	}
	future := "MTGO2." + strings.TrimPrefix(encoded, "MTGO1.")
	if _, err := NewClient(Config{SessionString: future}); err == nil {
		t.Fatal("accepted unsupported MTGO2 session string")
	}
}

func TestNewClientSessionStringValidatesConflictsAndBackend(t *testing.T) {
	production := testSessionString(t, session.SessionString{
		Version: session.MtcuteSessionStringVersion,
		Main:    session.SessionStringDC{ID: 2, Address: "149.154.167.50:443"},
		AuthKey: bytes.Repeat([]byte{1}, 256),
	})
	testBackend := testSessionString(t, session.SessionString{
		Version: session.MtcuteSessionStringVersion,
		Main:    session.SessionStringDC{ID: 2, Address: "149.154.167.40:443", TestMode: true},
		AuthKey: bytes.Repeat([]byte{2}, 256),
	})
	cases := map[string]Config{
		"malformed":    {APIID: 1, SessionString: "not-base64"},
		"explicit key": {APIID: 1, SessionString: production, AuthKey: bytes.Repeat([]byte{3}, 256), AuthKeyID: 3},
		"dc":           {APIID: 1, DCID: 4, SessionString: production},
		"address":      {APIID: 1, Address: "127.0.0.1:443", SessionString: production},
		"endpoint":     {APIID: 1, SessionString: production, DCAddresses: map[int]string{2: "127.0.0.1:443"}},
		"prod as test": {APIID: 1, SessionString: production, TestMode: true},
		"key without string": {
			APIID:            1,
			Address:          "149.154.167.50:443",
			SessionStringKey: bytes.Repeat([]byte{4}, 32),
		},
		"short string key": {
			APIID:            1,
			SessionString:    production,
			SessionStringKey: bytes.Repeat([]byte{4}, 31),
		},
		"key on mtcute": {
			APIID:            1,
			SessionString:    production,
			SessionStringKey: bytes.Repeat([]byte{4}, 32),
		},
	}
	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewClient(config); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	client, err := NewClient(Config{APIID: 1, SessionString: testBackend})
	if err != nil {
		t.Fatal(err)
	}
	if !client.config.TestMode {
		t.Fatal("test backend flag was lost")
	}
	_ = client.Close()
}

// newMTGOExportTestClient wires a client to a net.Pipe connection with the
// given auth key so ExportSessionString can invoke users.getUsers against the
// returned server side. When permanent is true the key is also registered as
// the client's permanent authorization.
func newMTGOExportTestClient(t *testing.T, cfg Config, key mtproto.AuthKey, permanent bool) (*Client, net.Conn) {
	t.Helper()
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	sessionID := [8]byte{9}
	sessionState := mtproto.NewSession(key, 0, sessionID, 4)
	client.mu.Lock()
	client.conn = clientConn
	client.session = sessionState
	if permanent {
		client.permanent = authState{key: key, sessionID: sessionID}
	}
	client.initConnectionDone = true
	client.startReceiveRouteLocked(
		routeKey{dcid: client.config.DCID, kind: ConnectionMain},
		&clientRoute{connection: clientConn, session: sessionState},
	)
	client.mu.Unlock()
	t.Cleanup(func() { _ = serverConn.Close() })
	t.Cleanup(func() { _ = client.Close() })
	return client, serverConn
}

// serveGetMeRequest answers the next client request with a users.getUsers
// result containing the given self user.
func serveGetMeRequest(serverConn net.Conn, key mtproto.AuthKey, sessionID [8]byte, user *tl.User) chan error {
	done := make(chan error, 1)
	go func() {
		messageID, body, err := readClientRequest(serverConn, key, sessionID)
		if err == nil && binary.LittleEndian.Uint32(body) != tl.UsersGetUsersRequestConstructorID {
			err = fmt.Errorf("constructor=%#x", binary.LittleEndian.Uint32(body))
		}
		if err == nil {
			var userBody []byte
			userBody, err = tl.Encode(user)
			if err == nil {
				vector := make([]byte, 0, 8+len(userBody))
				vector = binary.LittleEndian.AppendUint32(vector, 0x1cb5c415)
				vector = binary.LittleEndian.AppendUint32(vector, 1)
				vector = append(vector, userBody...)
				err = writeServerResultRaw(serverConn, key, sessionID, messageID, vector)
			}
		}
		done <- err
	}()
	return done
}

// stringPtr returns a pointer to a string for tl.User optional string fields.
func stringPtr(s string) *string { return &s }

// int32Ptr returns a pointer to an int32 for tl.User optional int fields.
func int32Ptr(v int32) *int32 { return &v }

func TestClientExportsMTGOSessionString(t *testing.T) {
	const apiHash = "89abcdef0123456789abcdef01234567"
	key := testAuthKey(4)
	client, serverConn := newMTGOExportTestClient(t, Config{
		APIID:   611335,
		APIHash: apiHash,
		Phone:   "+9996621234",
		DCID:    4,
		Address: "149.154.167.91:443",
	}, key, true)
	serverDone := serveGetMeRequest(serverConn, key, [8]byte{9},
		&tl.User{Self: true, Bot: true, BotInfoVersion: int32Ptr(1), ID: 777, FirstName: stringPtr("T"), LastName: stringPtr("B")})

	exportDone := make(chan struct{})
	var exported string
	var exportErr error
	go func() {
		exported, exportErr = client.ExportSessionString(context.Background())
		close(exportDone)
	}()
	select {
	case <-exportDone:
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("export did not complete")
	}
	<-exportDone
	if exportErr != nil {
		t.Fatal(exportErr)
	}
	value, err := session.DecodeSessionString(exported, nil)
	if err != nil {
		t.Fatal(err)
	}
	if value.Format != session.SessionStringFormatMTGO || value.APIID != 611335 ||
		value.APIHash != apiHash || value.PhoneNumber != "+9996621234" ||
		value.Main.ID != 4 || value.Main.TestMode ||
		value.User == nil || value.User.ID != 777 || !value.User.Bot ||
		!bytes.Equal(value.AuthKey, key.Key[:]) {
		t.Fatalf("value=%+v", value)
	}
}

func TestClientExportsStoredPrimarySessionString(t *testing.T) {
	const apiHash = "0123456789abcdef0123456789abcdef"
	authKey := bytes.Repeat([]byte{0x6b}, 256)
	digest := sha1.Sum(authKey)
	var key mtproto.AuthKey
	copy(key.Key[:], authKey)
	key.ID = binary.LittleEndian.Uint64(digest[12:20])
	store := session.NewMemoryStore()
	data, err := session.Encode(session.Snapshot{
		APIID:     1,
		PrimaryDC: 4,
		AuthKeys: []session.AuthKey{{
			DCID: 4,
			Kind: "main",
			Key:  authKey,
			ID:   binary.LittleEndian.Uint64(digest[12:20]),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), data); err != nil {
		t.Fatal(err)
	}
	client, serverConn := newMTGOExportTestClient(t, Config{
		APIID:       1,
		APIHash:     apiHash,
		Address:     "149.154.167.50:443",
		DCAddresses: map[int]string{4: "149.154.167.91:443"},
		Store:       store,
	}, key, false)
	serverDone := serveGetMeRequest(serverConn, key, [8]byte{9},
		&tl.User{Self: true, ID: 42, FirstName: stringPtr("T"), LastName: stringPtr("B")})

	exportDone := make(chan struct{})
	var exported string
	var exportErr error
	go func() {
		exported, exportErr = client.ExportSessionString(context.Background())
		close(exportDone)
	}()
	select {
	case <-exportDone:
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("export did not complete")
	}
	<-exportDone
	if exportErr != nil {
		t.Fatal(exportErr)
	}
	value, err := session.DecodeSessionString(exported, nil)
	if err != nil {
		t.Fatal(err)
	}
	if value.Main.ID != 4 || value.User == nil || value.User.ID != 42 || value.User.Bot ||
		value.APIHash != apiHash || !bytes.Equal(value.AuthKey, authKey) {
		t.Fatalf("value=%+v", value)
	}
}

func TestClientExportSessionStringRejectsMissingOrCorruptState(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "149.154.167.50:443"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ExportSessionString(context.Background()); !errors.Is(err, ErrNoAuthKey) {
		t.Fatalf("missing key err=%v", err)
	}
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.ExportSessionString(canceledCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context err=%v", err)
	}
	_ = client.Close()

	store := session.NewMemoryStore()
	if err := store.Save(context.Background(), []byte("corrupt")); err != nil {
		t.Fatal(err)
	}
	client, err = NewClient(Config{APIID: 1, Address: "149.154.167.50:443", Store: store})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.ExportSessionString(context.Background()); !errors.Is(err, session.ErrInvalidSnapshot) {
		t.Fatalf("corrupt state err=%v", err)
	}

	key := testAuthKey(4)
	client, _ = newMTGOExportTestClient(t, Config{
		APIID:   1,
		DCID:    4,
		Address: "149.154.167.91:443",
	}, key, true)
	if _, err := client.ExportSessionString(context.Background()); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing api hash err=%v", err)
	}
}

func testSessionString(t *testing.T, value session.SessionString) string {
	t.Helper()
	encoded, err := session.EncodeMtcuteSessionString(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
