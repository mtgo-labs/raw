package mtproto

import (
	"bytes"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/cryptoutil"
	"github.com/mtgo-labs/raw/internal/transport"
	"github.com/mtgo-labs/raw/tl"
)

func TestSendSessionControlUsesNonContentSequence(t *testing.T) {
	authKey, err := NewAuthKey(bytes.Repeat([]byte{0x42}, 256), [16]byte{}, [32]byte{}, 0, testNow())
	if err != nil {
		t.Fatal(err)
	}
	state := NewSessionState(1, [8]byte{5}, 0)
	var wire bytes.Buffer
	messageID, err := SendSessionControl(&wire, &constantReader{value: 7}, state, authKey, time.Unix(1_700_000_000, 0), &tl.MTPMessagesAck{MessageIDs: []int64{1}})
	if err != nil || messageID == 0 || wire.Len() == 0 {
		t.Fatalf("id=%x err=%v wire=%d", messageID, err, wire.Len())
	}
	payload, err := transport.ReadIntermediate(&wire, 4096)
	if err != nil {
		t.Fatal(err)
	}
	_, sequenceNo, _, err := decryptMessageWithSalt(authKey, state.Salt(), state.SessionID(), payload, cryptoutil.ClientToServer)
	if err != nil || sequenceNo != 0 {
		t.Fatalf("sequence=%d err=%v", sequenceNo, err)
	}
}
