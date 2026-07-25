package mtproto

import (
	"bytes"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/tl"
)

func TestSendSessionObjectRegistersPending(t *testing.T) {
	authKey, err := NewAuthKey(bytes.Repeat([]byte{0x42}, 256), [16]byte{}, [32]byte{}, 0, testNow())
	if err != nil {
		t.Fatal(err)
	}
	state := NewSessionState(1, [8]byte{3}, 0)
	pending := NewPendingTable(1)
	var wire bytes.Buffer
	messageID, err := SendSessionObject(&wire, &constantReader{value: 7}, state, pending, authKey, time.Unix(1_700_000_000, 0), &tl.MTPReqPQMulti{})
	if err != nil || messageID == 0 || pending.Len() != 1 || wire.Len() == 0 {
		t.Fatalf("send id=%x err=%v pending=%d wire=%d", messageID, err, pending.Len(), wire.Len())
	}
}
