package raw

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/tl"
)

func TestRouteSenderBatchesAcknowledgements(t *testing.T) {
	sender := newRouteSender(nil, nil, nil, time.Now, 2, nil)
	if err := sender.enqueueAcknowledgements([]int64{7, 9}); err != nil {
		t.Fatal(err)
	}
	acks := sender.takeAcks()
	if len(acks) != 2 || acks[0] != 7 || acks[1] != 9 {
		t.Fatalf("acknowledgements=%v", acks)
	}
	if second := sender.takeAcks(); len(second) != 0 {
		t.Fatalf("second batch acknowledgements=%v", second)
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

func TestRouteSenderRecycleDoesNotOverwriteQueuedAcks(t *testing.T) {
	sender := newRouteSender(nil, nil, nil, time.Now, 1, nil)
	if err := sender.enqueueAcknowledgements([]int64{1}); err != nil {
		t.Fatal(err)
	}
	sent := sender.takeAcks()
	if err := sender.enqueueAcknowledgements([]int64{2}); err != nil {
		t.Fatal(err)
	}
	sender.recycleAcks(sent)
	queued := sender.takeAcks()
	if len(queued) != 1 || queued[0] != 2 {
		t.Fatalf("queued=%v", queued)
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

	if err := sender.enqueueAcknowledgements([]int64{7, 9}); err != nil {
		t.Fatal(err)
	}
	go func() {
		sender.run()
		close(senderDone)
	}()

	ackMessageID, body, err := readClientRequest(serverConnection, authKey, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	object, err := tl.Decode(body, tl.DefaultDecodeLimits())
	if err != nil {
		t.Fatal(err)
	}
	acknowledgement, ok := object.(*tl.MTPMessagesAck)
	if !ok || len(acknowledgement.MessageIDs) != 2 ||
		acknowledgement.MessageIDs[0] != 7 ||
		acknowledgement.MessageIDs[1] != 9 {
		t.Fatalf("acknowledgement=%T %+v", object, object)
	}
	if ackMessageID == 0 || ackMessageID&3 != 0 {
		t.Fatalf("ack message ID=%x", ackMessageID)
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
	client.mu.Lock()
	client.session = sessionState
	client.conn = clientConnection
	client.mu.Unlock()

	message, pending, err := sessionState.Prepare(now, &tl.MTPReqPQMulti{Nonce: [16]byte{3}})
	if err != nil {
		t.Fatal(err)
	}
	// net.Pipe writes block until read, so the direct write and the server
	// side read must overlap.
	type wireRequest struct {
		messageID uint64
		body      []byte
		err       error
	}
	firstRead := make(chan wireRequest, 1)
	go func() {
		messageID, body, err := readClientRequest(serverConnection, authKey, sessionID)
		firstRead <- wireRequest{messageID: messageID, body: body, err: err}
	}()
	client.writeMu.Lock()
	_, err = sessionState.SendPrepared(clientConnection, rand.Reader, now, []tl.MTPMessage{message}, nil, false)
	client.writeMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	first := <-firstRead
	if first.err != nil {
		t.Fatal(first.err)
	}
	if first.messageID != uint64(message.MessageID) {
		t.Fatalf("wire message ID=%x prepared=%x", first.messageID, message.MessageID)
	}
	if object, err := tl.Decode(first.body, tl.DefaultDecodeLimits()); err != nil {
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
			first.messageID+1,
			&tl.MTPBadServerSalt{
				BadMessageID:    int64(first.messageID),
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
	retryRead := make(chan wireRequest, 1)
	go func() {
		messageID, body, err := readClientRequest(serverConnection, authKey, sessionID)
		retryRead <- wireRequest{messageID: messageID, body: body, err: err}
	}()
	recoveryDone := make(chan error, 1)
	go func() {
		recoveryDone <- client.applyInboundRecovery(
			routeKey{dcid: client.config.DCID, kind: ConnectionMain},
			route,
			inbound,
		)
	}()
	retry := <-retryRead
	if err := <-recoveryDone; err != nil {
		t.Fatal(err)
	}
	if retry.err != nil {
		t.Fatal(retry.err)
	}
	if retry.messageID <= first.messageID || sessionState.Salt() != 9 {
		t.Fatalf("retry=%x original=%x salt=%d", retry.messageID, first.messageID, sessionState.Salt())
	}
	if object, err := tl.Decode(retry.body, tl.DefaultDecodeLimits()); err != nil {
		t.Fatal(err)
	} else if request, ok := object.(*tl.MTPReqPQMulti); !ok || request.Nonce[0] != 3 {
		t.Fatalf("retry object=%T value=%+v", object, object)
	}

	responseMessageID := retry.messageID + 1
	go func() {
		serverWrite <- writeServerObject(
			serverConnection,
			authKey,
			9,
			sessionID,
			responseMessageID,
			&tl.MTPRPCResult{
				ReqMessageID: int64(retry.messageID),
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

// TestConcurrentWritersKeepWireIDsMonotonic pins the route write discipline:
// every writer must allocate its message id while holding writeMu. Concurrent
// invoke-style senders racing the liveness ping writer then still emit ids in
// strictly increasing wire order; a decrease would be rejected by the server
// as MSGID_DECREASE_RETRY.
func TestConcurrentWritersKeepWireIDsMonotonic(t *testing.T) {
	authKey := testAuthKey(2)
	sessionID := [8]byte{5}
	sessionState := mtproto.NewSession(authKey, 0, sessionID, 256)
	clientConnection, serverConnection := net.Pipe()

	type wireFrame struct {
		messageID uint64
	}
	frames := make(chan wireFrame, 1024)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			messageID, _, err := readClientRequest(serverConnection, authKey, sessionID)
			if err != nil {
				return
			}
			frames <- wireFrame{messageID: messageID}
		}
	}()

	var writeMu sync.Mutex
	var invokeWG sync.WaitGroup
	stop := make(chan struct{})
	var pingWG sync.WaitGroup
	pingWG.Add(1)
	go func() {
		defer pingWG.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			writeMu.Lock()
			_, err := sessionState.SendPing(clientConnection, rand.Reader, time.Now(), 1, 60)
			writeMu.Unlock()
			if err != nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	for range 8 {
		invokeWG.Add(1)
		go func() {
			defer invokeWG.Done()
			for range 20 {
				writeMu.Lock()
				message, _, err := sessionState.Prepare(time.Now(), &tl.MTPReqPQMulti{})
				if err == nil {
					_, err = sessionState.SendPrepared(
						clientConnection, rand.Reader, time.Now(), []tl.MTPMessage{message}, nil, false,
					)
				}
				writeMu.Unlock()
				if err != nil {
					return
				}
			}
		}()
	}
	invokeWG.Wait()
	close(stop)
	pingWG.Wait()
	_ = clientConnection.Close()
	<-readerDone
	close(frames)

	previous := uint64(0)
	count := 0
	for frame := range frames {
		if frame.messageID <= previous {
			t.Fatalf("wire msg IDs not monotonic: previous=%x current=%x", previous, frame.messageID)
		}
		previous = frame.messageID
		count++
	}
	if count < 160 {
		t.Fatalf("captured frames=%d, expected at least the 160 invoke messages", count)
	}
}
