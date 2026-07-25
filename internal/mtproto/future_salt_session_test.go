package mtproto

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/cryptoutil"
	"github.com/mtgo-labs/raw/internal/transport"
	"github.com/mtgo-labs/raw/tl"
)

func TestSessionFetchesRoutesAndActivatesFutureSalts(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	authKey, err := NewAuthKey(
		bytes.Repeat([]byte{0x42}, 256),
		[16]byte{},
		[32]byte{},
		now.Unix(),
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	session := NewSession(authKey, 3, [8]byte{7}, 1)
	if !session.NeedsFutureSalts() {
		t.Fatal("session with no future salts did not request a refresh")
	}

	var wire bytes.Buffer
	requestID, sent, err := session.SendFutureSaltsRequest(
		&wire,
		&constantReader{value: 7},
		now,
	)
	if err != nil || !sent {
		t.Fatalf("request=%d sent=%t err=%v", requestID, sent, err)
	}
	payload, err := transport.ReadIntermediate(&wire, 4096)
	if err != nil {
		t.Fatal(err)
	}
	_, sequenceNo, body, err := decryptMessageWithSalt(
		authKey,
		3,
		[8]byte{7},
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
	request, ok := object.(*tl.MTPGetFutureSalts)
	if !ok || request.Num != maxFutureSalts || sequenceNo&1 == 0 {
		t.Fatalf("request=%+v sequence=%d", object, sequenceNo)
	}
	if session.NeedsFutureSalts() {
		t.Fatal("duplicate refresh remained eligible while request was in flight")
	}

	response := &tl.MTPFutureSalts{
		ReqMessageID: int64(requestID),
		Now:          int32(now.Unix()),
		Salts: []tl.MTPFutureSalt{
			{ValidSince: int32(now.Unix() - 1), ValidUntil: int32(now.Unix() + 100), Salt: 4},
			{ValidSince: int32(now.Unix() + 100), ValidUntil: int32(now.Unix() + 200), Salt: 5},
			{ValidSince: int32(now.Unix() + 200), ValidUntil: int32(now.Unix() + 300), Salt: 6},
		},
	}
	result, err := RouteInboundObject(session.state, session.pending, response)
	if err != nil || result.Resolved != 1 || session.Salt() != 4 {
		t.Fatalf("result=%+v salt=%d err=%v", result, session.Salt(), err)
	}
	if session.NeedsFutureSalts() {
		t.Fatal("full future-salt window requested an early refresh")
	}

	salt, _ := session.state.inboundEnvelope(now.Add(101 * time.Second))
	if salt != 5 {
		t.Fatalf("activated salt=%d", salt)
	}
	if !session.NeedsFutureSalts() {
		t.Fatal("depleted future-salt window did not request a refresh")
	}
}

func TestSessionRejectsUnmatchedFutureSalts(t *testing.T) {
	state := NewSessionState(3, [8]byte{}, 0)
	result, err := RouteInboundObject(state, NewPendingTable(1), &tl.MTPFutureSalts{
		ReqMessageID: 9,
		Now:          1_700_000_000,
	})
	if !errors.Is(err, ErrInvalidFutureSalt) || result.Resolved != 0 || state.Salt() != 3 {
		t.Fatalf("result=%+v salt=%d err=%v", result, state.Salt(), err)
	}
}

func TestSessionRetriesFutureSaltRequestAfterWriteFailure(t *testing.T) {
	session := NewSession(AuthKey{ID: 1}, 3, [8]byte{}, 1)
	_, sent, err := session.SendFutureSaltsRequest(
		failingWriter{},
		&constantReader{value: 7},
		time.Unix(1_700_000_000, 0),
	)
	if err == nil || !sent {
		t.Fatalf("sent=%t err=%v", sent, err)
	}
	if !session.NeedsFutureSalts() {
		t.Fatal("failed request did not become retryable")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}
