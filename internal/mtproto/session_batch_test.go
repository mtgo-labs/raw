package mtproto

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/cryptoutil"
	"github.com/mtgo-labs/raw/internal/transport"
	"github.com/mtgo-labs/raw/tl"
)

func TestSendPreparedSessionObjectsContainer(t *testing.T) {
	authKey, err := NewAuthKey(bytes.Repeat([]byte{0x42}, 256), [16]byte{}, [32]byte{}, 0, testNow())
	if err != nil {
		t.Fatal(err)
	}
	state := NewSessionState(1, [8]byte{3}, 0)
	pending := NewPendingTable(2)
	now := time.Unix(1_700_000_000, 0)
	first, firstRequest, err := PrepareSessionObject(state, pending, now, &tl.MTPReqPQMulti{Nonce: [16]byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	second, secondRequest, err := PrepareSessionObject(state, pending, now, &tl.MTPReqPQMulti{Nonce: [16]byte{2}})
	if err != nil {
		t.Fatal(err)
	}
	if firstRequest == nil || secondRequest == nil {
		t.Fatal("prepared requests did not retain pending ownership")
	}

	var wire bytes.Buffer
	containerID, err := SendPreparedSessionObjects(
		&wire,
		&constantReader{value: 7},
		state,
		pending,
		authKey,
		now,
		[]tl.MTPMessage{first, second},
		[]int64{7, 9},
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := transport.ReadIntermediate(&wire, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	messageID, sequenceNo, body, err := decryptMessageWithSalt(
		authKey,
		state.Salt(),
		state.SessionID(),
		payload,
		cryptoutil.ClientToServer,
	)
	if err != nil {
		t.Fatal(err)
	}
	if messageID != containerID || containerID <= uint64(second.MessageID) || sequenceNo&1 != 0 {
		t.Fatalf("container id=%x second=%x sequence=%d", containerID, second.MessageID, sequenceNo)
	}
	object, err := tl.Decode(body, tl.DefaultDecodeLimits())
	if err != nil {
		t.Fatal(err)
	}
	container, ok := object.(*tl.MTPMessageContainer)
	if !ok || len(container.Messages) != 3 {
		t.Fatalf("object=%T messages=%d", object, len(container.Messages))
	}
	if container.Messages[0].MessageID != first.MessageID || container.Messages[0].Seqno&1 == 0 ||
		container.Messages[1].MessageID != second.MessageID || container.Messages[1].Seqno&1 == 0 {
		t.Fatalf("request messages=%+v", container.Messages[:2])
	}
	ack, ok := container.Messages[2].Body.(*tl.MTPMessagesAck)
	if !ok || container.Messages[2].Seqno&1 != 0 || len(ack.MessageIDs) != 2 || ack.MessageIDs[0] != 7 || ack.MessageIDs[1] != 9 {
		t.Fatalf("ack message=%+v body=%T", container.Messages[2], container.Messages[2].Body)
	}
}

func TestSendPreparedSessionObjectsSkipsCanceledRequest(t *testing.T) {
	authKey, err := NewAuthKey(bytes.Repeat([]byte{0x42}, 256), [16]byte{}, [32]byte{}, 0, testNow())
	if err != nil {
		t.Fatal(err)
	}
	state := NewSessionState(1, [8]byte{4}, 0)
	pending := NewPendingTable(2)
	now := time.Unix(1_700_000_000, 0)
	first, firstRequest, err := PrepareSessionObject(state, pending, now, &tl.MTPReqPQMulti{Nonce: [16]byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := PrepareSessionObject(state, pending, now, &tl.MTPReqPQMulti{Nonce: [16]byte{2}})
	if err != nil {
		t.Fatal(err)
	}
	if !pending.Cancel(uint64(first.MessageID), context.Canceled) {
		t.Fatal("cancel failed")
	}

	var wire bytes.Buffer
	messageID, err := SendPreparedSessionObjects(
		&wire,
		&constantReader{value: 7},
		state,
		pending,
		authKey,
		now,
		[]tl.MTPMessage{first, second},
		nil,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := transport.ReadIntermediate(&wire, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	gotID, _, body, err := decryptMessageWithSalt(
		authKey,
		state.Salt(),
		state.SessionID(),
		payload,
		cryptoutil.ClientToServer,
	)
	if err != nil {
		t.Fatal(err)
	}
	object, err := tl.Decode(body, tl.DefaultDecodeLimits())
	if err != nil {
		t.Fatal(err)
	}
	if gotID != messageID || messageID != uint64(second.MessageID) {
		t.Fatalf("wire id=%x send id=%x second=%x", gotID, messageID, second.MessageID)
	}
	request, ok := object.(*tl.MTPReqPQMulti)
	if !ok || request.Nonce[0] != 2 {
		t.Fatalf("object=%T value=%+v", object, object)
	}
	completed, err := pending.WaitRequest(context.Background(), firstRequest)
	if err != nil || !errors.Is(completed.Result.Err, context.Canceled) {
		t.Fatalf("completed=%+v err=%v", completed, err)
	}
}

func TestSendPreparedSessionObjectsWrapsRetryInContainer(t *testing.T) {
	authKey, err := NewAuthKey(bytes.Repeat([]byte{0x42}, 256), [16]byte{}, [32]byte{}, 0, testNow())
	if err != nil {
		t.Fatal(err)
	}
	state := NewSessionState(1, [8]byte{5}, 0)
	pending := NewPendingTable(1)
	now := time.Unix(1_700_000_000, 0)
	message, _, err := PrepareSessionObject(state, pending, now, &tl.MTPReqPQMulti{})
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	containerID, err := SendPreparedSessionObjects(
		&wire,
		&constantReader{value: 7},
		state,
		pending,
		authKey,
		now,
		[]tl.MTPMessage{message},
		nil,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := transport.ReadIntermediate(&wire, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	gotID, sequenceNo, body, err := decryptMessageWithSalt(
		authKey,
		state.Salt(),
		state.SessionID(),
		payload,
		cryptoutil.ClientToServer,
	)
	if err != nil {
		t.Fatal(err)
	}
	object, err := tl.Decode(body, tl.DefaultDecodeLimits())
	if err != nil {
		t.Fatal(err)
	}
	container, ok := object.(*tl.MTPMessageContainer)
	if !ok || len(container.Messages) != 1 || container.Messages[0].MessageID != message.MessageID {
		t.Fatalf("object=%T value=%+v", object, object)
	}
	if gotID != containerID || containerID <= uint64(message.MessageID) || sequenceNo&1 != 0 {
		t.Fatalf("wire=%x container=%x child=%x sequence=%d", gotID, containerID, message.MessageID, sequenceNo)
	}
}
