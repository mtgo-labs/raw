package raw

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/tgerr"
	"github.com/mtgo-labs/raw/tl"
)

func readNextRequest(server net.Conn, key mtproto.AuthKey, sessionID [8]byte) (uint64, []byte, error) {
	for {
		messageID, body, err := readClientRequest(server, key, sessionID)
		if err != nil {
			return 0, nil, err
		}
		if len(body) >= 4 && binary.LittleEndian.Uint32(body) == tl.MTPMessagesAckConstructorID {
			continue
		}
		return messageID, body, nil
	}
}

// requestStream reads decrypted client messages and yields application-level
// requests one at a time, transparently unwrapping msg_container and skipping
// acks. The client may batch a retry together with its acks into a container
// (SendPreparedSessionObjects containers when more than one message is ready),
// which the race detector's scheduling makes more likely — so a strict "one
// decrypted frame == one request" assumption is brittle.
type requestStream struct {
	server    net.Conn
	key       mtproto.AuthKey
	sessionID [8]byte
	pending   []clientRequest
}

type clientRequest struct {
	id   uint64
	body []byte
}

const msgContainerConstructorID = 0x73f1f8dc

func (stream *requestStream) next() (uint64, []byte, error) {
	for len(stream.pending) == 0 {
		outerID, body, err := readClientRequest(stream.server, stream.key, stream.sessionID)
		if err != nil {
			return 0, nil, err
		}
		stream.pending = appendClientRequests(stream.pending, body, outerID)
	}
	request := stream.pending[0]
	stream.pending = stream.pending[1:]
	return request.id, request.body, nil
}

// appendClientRequests collects application-level request bodies from body. A
// msg_container is decoded into its bare messages (msg_id:long seqno:int
// bytes:int body:bytes); acks are skipped. A non-container body is returned as
// a single request unless it is itself an ack.
func appendClientRequests(out []clientRequest, body []byte, outerID uint64) []clientRequest {
	if len(body) >= 4 && binary.LittleEndian.Uint32(body) == msgContainerConstructorID {
		data := body[4:]
		if len(data) < 4 {
			return out
		}
		count := binary.LittleEndian.Uint32(data)
		data = data[4:]
		for index := uint32(0); index < count; index++ {
			if len(data) < 16 { // msg_id:long + seqno:int + bytes:int
				break
			}
			messageID := binary.LittleEndian.Uint64(data)
			length := int(binary.LittleEndian.Uint32(data[12:]))
			data = data[16:]
			if length < 4 || length > len(data) {
				break
			}
			inner := data[:length]
			data = data[length:]
			if len(inner) >= 4 && binary.LittleEndian.Uint32(inner) == tl.MTPMessagesAckConstructorID {
				continue
			}
			out = append(out, clientRequest{id: messageID, body: inner})
		}
		return out
	}
	if len(body) >= 4 && binary.LittleEndian.Uint32(body) == tl.MTPMessagesAckConstructorID {
		return out
	}
	return append(out, clientRequest{id: outerID, body: body})
}

func testBotUser(id int64) *tl.User {
	version := int32(0)
	return &tl.User{ID: id, Self: true, Bot: true, BotInfoVersion: &version, FirstName: new("bot")}
}

func TestStartReturnsExistingUser(t *testing.T) {
	key := testAuthKey(2)
	sessionID := [8]byte{2}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go acceptConnections(listener, accepted, 1)

	client, err := NewClient(Config{
		APIID: 1, APIHash: "hash", BotToken: "ignored",
		Address: listener.Addr().String(),
		AuthKey: append([]byte(nil), key.Key[:]...), AuthKeyID: key.ID,
		SessionID: sessionID, Liveness: LivenessPolicy{Disabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type startResult struct {
		user *tl.User
		err  error
	}
	startDone := make(chan startResult, 1)
	go func() {
		user, err := client.Start(ctx)
		startDone <- startResult{user: user, err: err}
	}()

	server := <-accepted
	defer server.Close()
	var header [4]byte
	if _, err := io.ReadFull(server, header[:]); err != nil {
		t.Fatal(err)
	}
	messageID, body, err := readNextRequest(server, key, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(body) != tl.InvokeWithLayerRequestConstructorID {
		t.Fatalf("expected invokeWithLayer, got %#x", binary.LittleEndian.Uint32(body))
	}
	userEncoded, err := tl.Encode(testBotUser(42))
	if err != nil {
		t.Fatal(err)
	}
	vectorBody := make([]byte, 8+len(userEncoded))
	binary.LittleEndian.PutUint32(vectorBody, 0x1cb5c415)
	binary.LittleEndian.PutUint32(vectorBody[4:], 1)
	copy(vectorBody[8:], userEncoded)
	if err := writeServerResultRaw(server, key, sessionID, messageID, vectorBody); err != nil {
		t.Fatal(err)
	}
	result := <-startDone
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.user.ID != 42 || !result.user.Bot {
		t.Fatalf("user=%+v", result.user)
	}
}

func TestStartBotLoginAfterUnregisteredKey(t *testing.T) {
	key := testAuthKey(2)
	sessionID := [8]byte{2}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go acceptConnections(listener, accepted, 1)

	client, err := NewClient(Config{
		APIID: 1, APIHash: "hash", BotToken: "123:abc",
		Address: listener.Addr().String(),
		AuthKey: append([]byte(nil), key.Key[:]...), AuthKeyID: key.ID,
		SessionID: sessionID, Liveness: LivenessPolicy{Disabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type startResult struct {
		user *tl.User
		err  error
	}
	startDone := make(chan startResult, 1)
	go func() {
		user, err := client.Start(ctx)
		startDone <- startResult{user: user, err: err}
	}()

	server := <-accepted
	defer server.Close()
	var header [4]byte
	if _, err := io.ReadFull(server, header[:]); err != nil {
		t.Fatal(err)
	}
	stream := &requestStream{server: server, key: key, sessionID: sessionID}
	invokeMessageID, invokeBody, err := stream.next()
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(invokeBody) != tl.InvokeWithLayerRequestConstructorID {
		t.Fatalf("first expected invokeWithLayer, got %#x", binary.LittleEndian.Uint32(invokeBody))
	}
	if err := writeServerResult(server, key, sessionID, invokeMessageID, &tl.MTPRPCError{
		ErrorCode: 401, ErrorMessage: tgerr.ErrAuthKeyUnregistered,
	}); err != nil {
		t.Fatal(err)
	}
	// After AUTH_KEY_UNREGISTERED the client re-attempts the login. The retry
	// may be batched into a msg_container (with acks or a re-sent
	// invokeWithLayer), so unwrap containers and read until the
	// importBotAuthorization query arrives.
	var loginMessageID uint64
	for {
		id, requestBody, err := stream.next()
		if err != nil {
			t.Fatal(err)
		}
		if binary.LittleEndian.Uint32(requestBody) == tl.AuthImportBotAuthorizationRequestConstructorID {
			loginMessageID = id
			break
		}
	}
	if err := writeServerResult(server, key, sessionID, loginMessageID, &tl.AuthAuthorization{
		User: testBotUser(99),
	}); err != nil {
		t.Fatal(err)
	}
	result := <-startDone
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.user.ID != 99 || !result.user.Bot {
		t.Fatalf("user=%+v", result.user)
	}
}

func TestStartRejectsMissingAPIHash(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.Start(context.Background())
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err=%v", err)
	}
}

func TestStartRejectsMissingCredentials(t *testing.T) {
	key := testAuthKey(2)
	sessionID := [8]byte{2}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go acceptConnections(listener, accepted, 1)

	client, err := NewClient(Config{
		APIID: 1, APIHash: "hash",
		Address: listener.Addr().String(),
		AuthKey: append([]byte(nil), key.Key[:]...), AuthKeyID: key.ID,
		SessionID: sessionID, Liveness: LivenessPolicy{Disabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type startResult struct{ err error }
	startDone := make(chan startResult, 1)
	go func() {
		_, err := client.Start(ctx)
		startDone <- startResult{err: err}
	}()

	server := <-accepted
	defer server.Close()
	var header [4]byte
	if _, err := io.ReadFull(server, header[:]); err != nil {
		t.Fatal(err)
	}
	messageID, _, err := readNextRequest(server, key, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeServerResult(server, key, sessionID, messageID, &tl.MTPRPCError{
		ErrorCode: 401, ErrorMessage: tgerr.ErrAuthKeyUnregistered,
	}); err != nil {
		t.Fatal(err)
	}
	result := <-startDone
	if !errors.Is(result.err, ErrMissingCredentials) {
		t.Fatalf("err=%v", result.err)
	}
}

func TestDisconnectAllowsReconnect(t *testing.T) {
	key := testAuthKey(2)
	sessionID := [8]byte{2}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	client, err := NewClient(Config{
		APIID: 1, APIHash: "hash", BotToken: "ignored",
		Address: listener.Addr().String(),
		AuthKey: append([]byte(nil), key.Key[:]...), AuthKeyID: key.ID,
		SessionID: sessionID, Liveness: LivenessPolicy{Disabled: true},
		Reconnect: ReconnectPolicy{Disabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	accepted1 := make(chan net.Conn, 1)
	go acceptConnections(listener, accepted1, 1)
	if err := client.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	server1 := <-accepted1
	defer server1.Close()

	if err := client.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.Done():
		t.Fatal("Done channel closed after Disconnect")
	default:
	}

	accepted2 := make(chan net.Conn, 1)
	go acceptConnections(listener, accepted2, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	server2 := <-accepted2
	defer server2.Close()
}
