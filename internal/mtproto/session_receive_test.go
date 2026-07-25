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

func TestRouteInboundObject(t *testing.T) {
	state := NewSessionState(1, [8]byte{}, 0)
	pending := NewPendingTable(2)
	if _, err := pending.Add(11); err != nil {
		t.Fatal(err)
	}
	result, err := RouteInboundObject(state, pending, &tl.MTPMessageContainer{Messages: []tl.MTPMessage{
		{Body: &tl.MTPRPCResult{ReqMessageID: 11, Result: &tl.MTPReqPQMulti{}}},
		{Body: &tl.MTPBadServerSalt{BadMessageID: 12, ErrorCode: 48, NewServerSalt: 9}},
	}})
	if err != nil || result.Resolved != 1 || len(result.Controls) != 1 || state.Salt() != 9 {
		t.Fatalf("result=%+v salt=%d err=%v", result, state.Salt(), err)
	}
	if _, ok := pending.Take(11); !ok {
		t.Fatal("rpc result was not completed")
	}
}

func TestRouteInboundContainerCollectsUpdates(t *testing.T) {
	state := NewSessionState(1, [8]byte{}, 0)
	pending := NewPendingTable(1)
	update := &tl.UpdateShort{Date: 1}
	result, err := RouteInboundObject(state, pending, &tl.MTPMessageContainer{Messages: []tl.MTPMessage{
		{Body: update},
	}})
	if err != nil || len(result.Updates) != 1 || result.Updates[0] != update {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestRouteInboundContainerCollectsPingAndPong(t *testing.T) {
	state := NewSessionState(1, [8]byte{}, 0)
	pending := NewPendingTable(1)
	result, err := routeInboundObject(state, pending, &tl.MTPMessageContainer{Messages: []tl.MTPMessage{
		{MessageID: 11, Body: &tl.MTPPing{PingID: 12}},
		{MessageID: 13, Body: &tl.MTPPong{MessageID: 14, PingID: 15}},
	}}, 9)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Pings) != 1 || result.Pings[0] != (InboundPing{MessageID: 11, PingID: 12}) {
		t.Fatalf("pings=%+v", result.Pings)
	}
	if len(result.Pongs) != 1 || result.Pongs[0] != (InboundPong{MessageID: 14, PingID: 15}) {
		t.Fatalf("pongs=%+v", result.Pongs)
	}
}

func TestReceiveSessionObject(t *testing.T) {
	now := time.Now()
	authKey, err := NewAuthKey(bytes.Repeat([]byte{0x42}, 256), [16]byte{}, [32]byte{}, now.Unix(), now)
	if err != nil {
		t.Fatal(err)
	}
	state := NewSessionState(1, [8]byte{4}, 0)
	pending := NewPendingTable(1)
	if _, err := pending.Add(13); err != nil {
		t.Fatal(err)
	}
	responseID := serverMessageID(now.Unix(), 1)
	serverMessage, err := encryptMessageWithSalt(&constantReader{value: 7}, authKey, state.Salt(), state.SessionID(), responseID, 2, mustEncodeObject(t, &tl.MTPRPCResult{ReqMessageID: 13, Result: &tl.MTPReqPQMulti{}}), cryptoutil.ServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := transport.WriteIntermediate(&wire, serverMessage.Payload); err != nil {
		t.Fatal(err)
	}
	result, messageID, sequenceNo, err := ReceiveSessionObject(&wire, state, pending, authKey, 4096)
	if err != nil || result.Resolved != 1 || len(result.AcknowledgeIDs) != 1 || result.AcknowledgeIDs[0] != int64(responseID) || messageID != responseID || sequenceNo != 2 {
		t.Fatalf("result=%+v id=%x seq=%d err=%v", result, messageID, sequenceNo, err)
	}
}

func TestReceiveSessionObjectBootstrapsUnknownSalt(t *testing.T) {
	now := time.Now()
	authKey, err := NewAuthKey(bytes.Repeat([]byte{0x42}, 256), [16]byte{}, [32]byte{}, now.Unix(), now)
	if err != nil {
		t.Fatal(err)
	}
	state := NewSessionState(0, [8]byte{4}, 0)
	pending := NewPendingTable(1)
	if _, err := pending.Add(13); err != nil {
		t.Fatal(err)
	}
	responseID := serverMessageID(now.Unix(), 1)
	serverMessage, err := encryptMessageWithSalt(
		&constantReader{value: 7},
		authKey,
		9,
		state.SessionID(),
		responseID,
		2,
		mustEncodeObject(t, &tl.MTPBadServerSalt{
			BadMessageID:    13,
			BadMessageSeqno: 1,
			ErrorCode:       48,
			NewServerSalt:   9,
		}),
		cryptoutil.ServerToClient,
	)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := transport.WriteIntermediate(&wire, serverMessage.Payload); err != nil {
		t.Fatal(err)
	}
	result, messageID, sequenceNo, err := ReceiveSessionObject(&wire, state, pending, authKey, 4096)
	if err != nil || state.Salt() != 9 || len(result.Controls) != 1 || messageID != responseID || sequenceNo != 2 {
		t.Fatalf("result=%+v salt=%d id=%x seq=%d err=%v", result, state.Salt(), messageID, sequenceNo, err)
	}
}

func TestReceiveSessionObjectRejectsUnconfirmedBootstrapSalt(t *testing.T) {
	now := time.Now()
	authKey, err := NewAuthKey(bytes.Repeat([]byte{0x42}, 256), [16]byte{}, [32]byte{}, now.Unix(), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		body tl.Object
	}{
		{
			name: "ordinary response",
			body: &tl.MTPRPCResult{ReqMessageID: 13, Result: &tl.MTPReqPQMulti{}},
		},
		{
			name: "mismatched bad salt",
			body: &tl.MTPBadServerSalt{
				BadMessageID:    13,
				BadMessageSeqno: 1,
				ErrorCode:       48,
				NewServerSalt:   10,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := NewSessionState(0, [8]byte{4}, 0)
			serverMessage, err := encryptMessageWithSalt(
				&constantReader{value: 7},
				authKey,
				9,
				state.SessionID(),
				serverMessageID(now.Unix(), 1),
				2,
				mustEncodeObject(t, test.body),
				cryptoutil.ServerToClient,
			)
			if err != nil {
				t.Fatal(err)
			}
			var wire bytes.Buffer
			if err := transport.WriteIntermediate(&wire, serverMessage.Payload); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := ReceiveSessionObject(&wire, state, NewPendingTable(1), authKey, 4096); !errors.Is(err, ErrEncryptedMessage) {
				t.Fatalf("err=%v", err)
			}
			if state.Salt() != 0 {
				t.Fatalf("salt=%d", state.Salt())
			}
		})
	}
}
