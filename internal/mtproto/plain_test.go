package mtproto

import (
	"bytes"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/tl"
)

func TestClientMessageID(t *testing.T) {
	id := ClientMessageID(time.Unix(1_700_000_000, 500_000_000))
	if id>>32 != 1_700_000_000 || id&3 != 0 {
		t.Fatalf("message ID = %x", id)
	}
	wholeSecond := ClientMessageID(time.Unix(1_700_000_000, 0))
	if wholeSecond&3 != 0 || uint32(wholeSecond) == 0 {
		t.Fatalf("whole-second message ID = %x", wholeSecond)
	}
}

func TestPlainObjectRoundTrip(t *testing.T) {
	var wire bytes.Buffer
	want := &tl.MTPReqPQMulti{}
	when := time.Unix(1_700_000_000, 0)
	messageID, err := SendPlainObject(&wire, when, want)
	if err != nil {
		t.Fatal(err)
	}
	got, receivedID, err := ReceivePlainObject(&wire, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if messageID != receivedID {
		t.Fatalf("message IDs = %x/%x", messageID, receivedID)
	}
	if _, ok := got.(*tl.MTPReqPQMulti); !ok {
		t.Fatalf("object type = %T", got)
	}
}
