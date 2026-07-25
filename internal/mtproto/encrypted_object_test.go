package mtproto

import (
	"bytes"
	"testing"

	"github.com/mtgo-labs/raw/internal/cryptoutil"
	"github.com/mtgo-labs/raw/internal/transport"
	"github.com/mtgo-labs/raw/tl"
)

func TestEncryptedObjectRoundTrip(t *testing.T) {
	authKey, err := NewAuthKey(bytes.Repeat([]byte{0x42}, 256), [16]byte{}, [32]byte{}, 0, testNow())
	if err != nil {
		t.Fatal(err)
	}
	var session [8]byte
	var wire bytes.Buffer
	serverMessage, err := encryptMessage(&constantReader{value: 7}, authKey, session, 0x200, 2, mustEncodeObject(t, &tl.MTPResPQ{PQ: []byte{15}}), cryptoutil.ServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	if err := transport.WriteIntermediate(&wire, serverMessage.Payload); err != nil {
		t.Fatal(err)
	}
	object, messageID, sequenceNo, err := ReceiveEncryptedObject(&wire, authKey, session, 4096)
	if err != nil || messageID != 0x200 || sequenceNo != 2 {
		t.Fatalf("object=%T id=%x seq=%d err=%v", object, messageID, sequenceNo, err)
	}
	if _, ok := object.(*tl.MTPResPQ); !ok {
		t.Fatalf("object type = %T", object)
	}
}

func mustEncodeObject(t *testing.T, object tl.Object) []byte {
	t.Helper()
	value, err := tl.Encode(object)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
