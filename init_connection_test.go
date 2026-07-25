package raw

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/tgerr"
	"github.com/mtgo-labs/raw/tl"
)

func TestInvokeConnectsOnFirstCall(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	key := testAuthKey(2)
	sessionID := [8]byte{2}
	client, err := NewClient(Config{
		APIID:     1,
		Address:   listener.Addr().String(),
		AuthKey:   key.Key[:],
		AuthKeyID: key.ID,
		SessionID: sessionID,
		Liveness:  LivenessPolicy{Disabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	stopServer := make(chan struct{})
	defer close(stopServer)
	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()

		var header [4]byte
		if _, err = io.ReadFull(connection, header[:]); err == nil &&
			binary.LittleEndian.Uint32(header[:]) != 0xeeeeeeee {
			err = fmt.Errorf("transport header=%x", header)
		}
		var messageID uint64
		var body []byte
		if err == nil {
			messageID, body, err = readClientRequest(connection, key, sessionID)
		}
		if err == nil && binary.LittleEndian.Uint32(body) != tl.InvokeWithLayerRequestConstructorID {
			err = fmt.Errorf("first constructor=%#x", binary.LittleEndian.Uint32(body))
		}
		if err == nil {
			err = writeServerResult(connection, key, sessionID, messageID, &tl.Config{})
		}
		serverDone <- err
		<-stopServer
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := Invoke(ctx, client, &tl.HelpGetConfigRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("Invoke returned a nil config")
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("explicit Connect after implicit connection: %v", err)
	}
}

func TestInvokeInitializesConnectionOnce(t *testing.T) {
	config := Config{
		APIID:   12345,
		Address: "127.0.0.1:1",
		InitConnection: InitConnectionConfig{
			DeviceModel:        "test-device",
			SystemVersion:      "test-system",
			AppVersion:         "1.2.3",
			SystemLanguageCode: "ar",
			LanguagePack:       "test-pack",
			LanguageCode:       "ku",
			Proxy:              &tl.InputClientProxy{Address: "proxy.test", Port: 443},
			Parameters:         &tl.JSONObject{},
		},
	}
	client, server, key, sessionID := newInitConnectionTranscriptClient(t, config)
	request := &tl.HelpGetConfigRequest{}
	expected, err := tl.Encode(&tl.InvokeWithLayerRequest[*tl.Config]{
		Layer: int32(tl.Layer),
		Query: &tl.InitConnectionRequest[*tl.Config]{
			APIID:          config.APIID,
			DeviceModel:    config.InitConnection.DeviceModel,
			SystemVersion:  config.InitConnection.SystemVersion,
			AppVersion:     config.InitConnection.AppVersion,
			SystemLangCode: config.InitConnection.SystemLanguageCode,
			LangPack:       config.InitConnection.LanguagePack,
			LangCode:       config.InitConnection.LanguageCode,
			Proxy:          config.InitConnection.Proxy,
			Params:         config.InitConnection.Parameters,
			Query:          request,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	serverDone := make(chan error, 1)
	go func() {
		messageID, body, err := readClientRequest(server, key, sessionID)
		if err == nil && !bytes.Equal(body, expected) {
			err = fmt.Errorf("initial request does not contain configured initConnection envelope")
		}
		if err == nil {
			err = writeServerResult(server, key, sessionID, messageID, &tl.Config{})
		}
		if err == nil {
			messageID, body, err = readClientRequest(server, key, sessionID)
		}
		if err == nil && binary.LittleEndian.Uint32(body) != tl.HelpGetConfigRequestConstructorID {
			err = fmt.Errorf("second constructor=%#x", binary.LittleEndian.Uint32(body))
		}
		if err == nil {
			err = writeServerResult(server, key, sessionID, messageID, &tl.Config{})
		}
		serverDone <- err
	}()

	for range 2 {
		result, err := invokeRoute(context.Background(), client, request, InvokeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if result == nil {
			t.Fatal("invoke returned a nil config")
		}
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestInvokeReinitializesAfterConnectionNotInited(t *testing.T) {
	client, server, key, sessionID := newInitConnectionTranscriptClient(t, Config{
		APIID: 1, Address: "127.0.0.1:1",
	})
	request := &tl.HelpGetConfigRequest{}

	serverDone := make(chan error, 1)
	go func() {
		messageID, _, err := readClientRequest(server, key, sessionID)
		if err == nil {
			err = writeServerResult(server, key, sessionID, messageID, &tl.Config{})
		}
		if err == nil {
			messageID, _, err = readClientRequest(server, key, sessionID)
		}
		if err == nil {
			err = writeServerResult(server, key, sessionID, messageID, &tl.MTPRPCError{
				ErrorCode: 400, ErrorMessage: tgerr.ErrConnectionNotInited,
			})
		}
		var body []byte
		if err == nil {
			messageID, body, err = readClientRequest(server, key, sessionID)
		}
		if err == nil && binary.LittleEndian.Uint32(body) != tl.InvokeWithLayerRequestConstructorID {
			err = fmt.Errorf("retry constructor=%#x", binary.LittleEndian.Uint32(body))
		}
		if err == nil {
			err = writeServerResult(server, key, sessionID, messageID, &tl.Config{})
		}
		serverDone <- err
	}()

	if _, err := invokeRoute(context.Background(), client, request, InvokeOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := invokeRoute(context.Background(), client, request, InvokeOptions{}); !tgerr.IsConnectionNotInited(err) {
		t.Fatalf("err=%v", err)
	}
	if _, err := invokeRoute(context.Background(), client, request, InvokeOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestInvokeInitializesRoutesIndependently(t *testing.T) {
	client, _, targetServer, _, targetKey, targetSessionID := newMigrationTranscriptClient(t)
	targetKeyRoute := routeKey{dcid: 4, kind: ConnectionMain}
	client.mu.Lock()
	client.routes[targetKeyRoute].initConnectionDone = false
	client.mu.Unlock()

	serverDone := make(chan error, 1)
	go func() {
		messageID, body, err := readClientRequest(targetServer, targetKey, targetSessionID)
		if err == nil && binary.LittleEndian.Uint32(body) != tl.InvokeWithLayerRequestConstructorID {
			err = fmt.Errorf("target constructor=%#x", binary.LittleEndian.Uint32(body))
		}
		if err == nil {
			err = writeServerResult(targetServer, targetKey, targetSessionID, messageID, &tl.Config{})
		}
		serverDone <- err
	}()

	if _, err := invokeRoute(
		context.Background(),
		client,
		&tl.HelpGetConfigRequest{},
		InvokeOptions{DCID: 4},
	); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}

	client.mu.Lock()
	primaryInitialized := client.initConnectionDone
	targetInitialized := client.routes[targetKeyRoute].initConnectionDone
	client.mu.Unlock()
	if !primaryInitialized || !targetInitialized {
		t.Fatalf("primary initialized=%t target initialized=%t", primaryInitialized, targetInitialized)
	}
}

func BenchmarkInvokeInitializedConnection(b *testing.B) {
	client, server, key, sessionID := newInitConnectionTranscriptClient(b, Config{
		APIID: 1, Address: "127.0.0.1:1",
	})
	client.initConnectionDone = true
	request := &tl.HelpGetConfigRequest{}

	serverDone := make(chan error, 1)
	go func() {
		var err error
		for range b.N {
			var messageID uint64
			var body []byte
			messageID, body, err = readClientRequest(server, key, sessionID)
			if err == nil && binary.LittleEndian.Uint32(body) != tl.HelpGetConfigRequestConstructorID {
				err = fmt.Errorf("steady-state constructor=%#x", binary.LittleEndian.Uint32(body))
			}
			if err != nil {
				_ = server.SetDeadline(time.Now())
				break
			}
			if err = writeServerResult(server, key, sessionID, messageID, &tl.Config{}); err != nil {
				_ = server.SetDeadline(time.Now())
				break
			}
		}
		serverDone <- err
	}()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := invokeRoute(context.Background(), client, request, InvokeOptions{}); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if err := <-serverDone; err != nil {
		b.Fatal(err)
	}
}

func newInitConnectionTranscriptClient(t testing.TB, config Config) (*Client, net.Conn, mtproto.AuthKey, [8]byte) {
	t.Helper()
	client, err := NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	connection, server := net.Pipe()
	key := testAuthKey(2)
	sessionID := [8]byte{2}
	sessionState := mtproto.NewSession(key, 0, sessionID, 4)

	client.mu.Lock()
	client.conn = connection
	client.session = sessionState
	client.permanent = authState{key: key, sessionID: sessionID}
	client.startReceiveRouteLocked(
		routeKey{dcid: client.config.DCID, kind: ConnectionMain},
		&clientRoute{connection: connection, session: sessionState},
	)
	client.mu.Unlock()

	t.Cleanup(func() {
		_ = server.SetDeadline(time.Now())
		_ = client.Close()
		_ = server.Close()
	})
	return client, server, key, sessionID
}
