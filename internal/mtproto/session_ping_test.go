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

func TestSendSessionPingUsesContentSequenceWithoutPending(t *testing.T) {
	authKey, err := NewAuthKey(
		bytes.Repeat([]byte{0x42}, 256),
		[16]byte{},
		[32]byte{},
		0,
		testNow(),
	)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := [8]byte{4}
	session := NewSession(authKey, 3, sessionID, 1)
	var wire bytes.Buffer
	messageID, err := session.SendPing(
		&wire,
		&constantReader{value: 7},
		time.Unix(1_700_000_000, 0),
		9,
		75,
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := transport.ReadIntermediate(&wire, 4096)
	if err != nil {
		t.Fatal(err)
	}
	gotID, sequenceNo, body, err := decryptMessageWithSalt(
		authKey,
		3,
		sessionID,
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
	ping, ok := object.(*tl.MTPPingDelayDisconnect)
	if !ok || ping.PingID != 9 || ping.DisconnectDelay != 75 {
		t.Fatalf("ping=%+v", object)
	}
	if gotID != messageID || sequenceNo != 1 || session.Pending() != 0 {
		t.Fatalf("message=%d/%d sequence=%d pending=%d", gotID, messageID, sequenceNo, session.Pending())
	}
}

func TestSendSessionPingRejectsInvalidDelay(t *testing.T) {
	if _, err := SendSessionPing(nil, nil, NewSessionState(0, [8]byte{}, 0), AuthKey{}, time.Time{}, 1, 0); !errors.Is(err, ErrSessionPing) {
		t.Fatalf("err=%v", err)
	}
}
