package raw

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/tl"
)

func TestRouteSenderBatchesRequestsAndAcknowledgements(t *testing.T) {
	sender := newRouteSender(nil, nil, nil, time.Now, 2, nil)
	first := tl.MTPMessage{MessageID: 1, Seqno: 1, Bytes: 4, Body: &tl.HelpGetConfigRequest{}}
	second := tl.MTPMessage{MessageID: 2, Seqno: 3, Bytes: 4, Body: &tl.HelpGetConfigRequest{}}
	if err := sender.enqueueRequest(first); err != nil {
		t.Fatal(err)
	}
	if err := sender.enqueueRequest(second); err != nil {
		t.Fatal(err)
	}
	if err := sender.enqueueRequest(tl.MTPMessage{}); !errors.Is(err, mtproto.ErrPendingLimit) {
		t.Fatalf("queue overflow error=%v", err)
	}
	if err := sender.enqueueAcknowledgements([]int64{7, 9}); err != nil {
		t.Fatal(err)
	}
	messages, acknowledgements, forceContainer := sender.takeBatch()
	if len(messages) != 2 || messages[0].MessageID != 1 || messages[1].MessageID != 2 {
		t.Fatalf("messages=%+v", messages)
	}
	if len(acknowledgements) != 2 || acknowledgements[0] != 7 || acknowledgements[1] != 9 {
		t.Fatalf("acknowledgements=%v", acknowledgements)
	}
	if forceContainer {
		t.Fatal("new requests unexpectedly forced a container")
	}
	messages, acknowledgements, forceContainer = sender.takeBatch()
	if len(messages) != 0 || len(acknowledgements) != 0 || forceContainer {
		t.Fatalf("second batch messages=%v acknowledgements=%v force=%t", messages, acknowledgements, forceContainer)
	}
}

func TestRouteSenderRejectsInvalidAcknowledgements(t *testing.T) {
	sender := newRouteSender(nil, nil, nil, time.Now, 1, nil)
	if err := sender.enqueueAcknowledgements([]int64{0}); !errors.Is(err, ErrAcknowledgementOverflow) {
		t.Fatalf("zero acknowledgement error=%v", err)
	}
	if err := sender.enqueueAcknowledgements(make([]int64, mtproto.MaxAcknowledgementIDs+1)); !errors.Is(err, ErrAcknowledgementOverflow) {
		t.Fatalf("overflow error=%v", err)
	}
}

func TestRouteSenderStopCancelsQueuedRequests(t *testing.T) {
	sessionState := mtproto.NewSession(testAuthKey(2), 0, [8]byte{2}, 1)
	message, pending, err := sessionState.Prepare(time.Unix(1_700_000_000, 0), &tl.HelpGetConfigRequest{})
	if err != nil {
		t.Fatal(err)
	}
	sender := newRouteSender(new(sync.Mutex), sessionState, nil, time.Now, 1, nil)
	if err := sender.enqueueRequest(message); err != nil {
		t.Fatal(err)
	}
	stopError := errors.New("sender stopped")
	sender.stopAndCancel(stopError)
	completed, err := sessionState.WaitPrepared(context.Background(), pending)
	if err != nil || !errors.Is(completed.Result.Err, stopError) {
		t.Fatalf("completed=%+v err=%v", completed, err)
	}
	if err := sender.enqueueRequest(message); !errors.Is(err, mtproto.ErrSessionClosed) {
		t.Fatalf("enqueue after stop error=%v", err)
	}
}

func TestRouteSenderRecycleDoesNotOverwriteQueuedRequests(t *testing.T) {
	sender := newRouteSender(nil, nil, nil, time.Now, 1, nil)
	first := tl.MTPMessage{MessageID: 1, Bytes: 20, Body: &tl.MTPReqPQMulti{}}
	second := tl.MTPMessage{MessageID: 2, Bytes: 20, Body: &tl.MTPReqPQMulti{}}
	if err := sender.enqueueRequest(first); err != nil {
		t.Fatal(err)
	}
	sent, acknowledgements, _ := sender.takeBatch()
	if err := sender.enqueueRequest(second); err != nil {
		t.Fatal(err)
	}
	sender.recycleBatch(sent, acknowledgements)
	queued, _, _ := sender.takeBatch()
	if len(queued) != 1 || queued[0].MessageID != second.MessageID || queued[0].Body == nil {
		t.Fatalf("queued=%+v", queued)
	}
}

func TestRouteSenderEncryptedBatchTranscript(t *testing.T) {
	now := time.Now()
	authKey := testAuthKey(2)
	sessionID := [8]byte{2}
	sessionState := mtproto.NewSession(authKey, 0, sessionID, 4)
	clientConnection, serverConnection := net.Pipe()
	defer clientConnection.Close()
	defer serverConnection.Close()

	sender := newRouteSender(
		new(sync.Mutex),
		sessionState,
		clientConnection,
		func() time.Time { return now },
		4,
		nil,
	)
	senderDone := make(chan struct{})
	defer func() {
		sender.halt()
		select {
		case <-senderDone:
		case <-time.After(time.Second):
			t.Error("route sender did not stop")
		}
	}()

	first, _, err := sessionState.Prepare(now, &tl.MTPReqPQMulti{Nonce: [16]byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := sessionState.Prepare(now, &tl.MTPReqPQMulti{Nonce: [16]byte{2}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.enqueueRequest(first); err != nil {
		t.Fatal(err)
	}
	if err := sender.enqueueRequest(second); err != nil {
		t.Fatal(err)
	}
	if err := sender.enqueueAcknowledgements([]int64{7, 9}); err != nil {
		t.Fatal(err)
	}
	go func() {
		sender.run()
		close(senderDone)
	}()

	containerID, body, err := readClientRequest(serverConnection, authKey, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	object, err := tl.Decode(body, tl.DefaultDecodeLimits())
	if err != nil {
		t.Fatal(err)
	}
	container, ok := object.(*tl.MTPMessageContainer)
	if !ok || len(container.Messages) != 3 {
		t.Fatalf("wire object=%T value=%+v", object, object)
	}
	if containerID <= uint64(second.MessageID) ||
		container.Messages[0].MessageID != first.MessageID ||
		container.Messages[1].MessageID != second.MessageID {
		t.Fatalf("container=%x messages=%+v", containerID, container.Messages)
	}
	acknowledgement, ok := container.Messages[2].Body.(*tl.MTPMessagesAck)
	if !ok || len(acknowledgement.MessageIDs) != 2 ||
		acknowledgement.MessageIDs[0] != 7 ||
		acknowledgement.MessageIDs[1] != 9 {
		t.Fatalf("acknowledgement=%T %+v", container.Messages[2].Body, container.Messages[2].Body)
	}
}

func TestRouteSenderBadSaltRecoveryTranscript(t *testing.T) {
	now := time.Now()
	authKey := testAuthKey(2)
	sessionID := [8]byte{3}
	sessionState := mtproto.NewSession(authKey, 0, sessionID, 2)
	clientConnection, serverConnection := net.Pipe()
	defer clientConnection.Close()
	defer serverConnection.Close()

	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.now = func() time.Time { return now }
	route := &clientRoute{
		connection: clientConnection,
		session:    sessionState,
	}
	route.sender = newRouteSender(
		&route.writeMu,
		sessionState,
		clientConnection,
		client.now,
		2,
		nil,
	)
	senderDone := make(chan struct{})
	go func() {
		route.sender.run()
		close(senderDone)
	}()
	defer func() {
		route.sender.halt()
		select {
		case <-senderDone:
		case <-time.After(time.Second):
			t.Error("route sender did not stop")
		}
	}()

	message, pending, err := sessionState.Prepare(now, &tl.MTPReqPQMulti{Nonce: [16]byte{3}})
	if err != nil {
		t.Fatal(err)
	}
	if err := route.sender.enqueueRequest(message); err != nil {
		t.Fatal(err)
	}
	messageID, body, err := readClientRequest(serverConnection, authKey, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if messageID != uint64(message.MessageID) {
		t.Fatalf("wire message ID=%x prepared=%x", messageID, message.MessageID)
	}
	if object, err := tl.Decode(body, tl.DefaultDecodeLimits()); err != nil {
		t.Fatal(err)
	} else if request, ok := object.(*tl.MTPReqPQMulti); !ok || request.Nonce[0] != 3 {
		t.Fatalf("request object=%T value=%+v", object, object)
	}

	serverWrite := make(chan error, 1)
	go func() {
		serverWrite <- writeServerObject(
			serverConnection,
			authKey,
			0,
			sessionID,
			messageID+1,
			&tl.MTPBadServerSalt{
				BadMessageID:    int64(messageID),
				BadMessageSeqno: message.Seqno,
				ErrorCode:       48,
				NewServerSalt:   9,
			},
		)
	}()
	inbound, _, _, err := sessionState.Receive(clientConnection, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serverWrite; err != nil {
		t.Fatal(err)
	}
	if err := client.applyInboundRecovery(
		routeKey{dcid: client.config.DCID, kind: ConnectionMain},
		route,
		inbound,
	); err != nil {
		t.Fatal(err)
	}

	retryMessageID, retryBody, err := readClientRequest(serverConnection, authKey, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if retryMessageID == messageID || sessionState.Salt() != 9 {
		t.Fatalf("retry=%x original=%x salt=%d", retryMessageID, messageID, sessionState.Salt())
	}
	if object, err := tl.Decode(retryBody, tl.DefaultDecodeLimits()); err != nil {
		t.Fatal(err)
	} else if request, ok := object.(*tl.MTPReqPQMulti); !ok || request.Nonce[0] != 3 {
		t.Fatalf("retry object=%T value=%+v", object, object)
	}

	responseMessageID := retryMessageID + 1
	go func() {
		serverWrite <- writeServerObject(
			serverConnection,
			authKey,
			9,
			sessionID,
			responseMessageID,
			&tl.MTPRPCResult{
				ReqMessageID: int64(retryMessageID),
				Result:       &tl.MTPReqPQMulti{Nonce: [16]byte{4}},
			},
		)
	}()
	inbound, _, _, err = sessionState.Receive(clientConnection, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serverWrite; err != nil {
		t.Fatal(err)
	}
	if err := route.sender.enqueueAcknowledgements(inbound.AcknowledgeIDs); err != nil {
		t.Fatal(err)
	}
	if err := client.applyInboundRecovery(
		routeKey{dcid: client.config.DCID, kind: ConnectionMain},
		route,
		inbound,
	); err != nil {
		t.Fatal(err)
	}

	_, acknowledgementBody, err := readClientRequest(serverConnection, authKey, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	acknowledgementObject, err := tl.Decode(acknowledgementBody, tl.DefaultDecodeLimits())
	if err != nil {
		t.Fatal(err)
	}
	acknowledgement, ok := acknowledgementObject.(*tl.MTPMessagesAck)
	if !ok || len(acknowledgement.MessageIDs) != 1 ||
		uint64(acknowledgement.MessageIDs[0]) != responseMessageID {
		t.Fatalf("acknowledgement=%T %+v", acknowledgementObject, acknowledgementObject)
	}

	completed, err := sessionState.WaitPrepared(context.Background(), pending)
	if err != nil || completed.Result.Err != nil {
		t.Fatalf("completed=%+v err=%v", completed, err)
	}
	resultObject, err := tl.Decode(completed.Result.Body, tl.DefaultDecodeLimits())
	if err != nil {
		t.Fatal(err)
	}
	result, ok := resultObject.(*tl.MTPReqPQMulti)
	if !ok || result.Nonce[0] != 4 {
		t.Fatalf("result=%T %+v", resultObject, resultObject)
	}
}
