package mtproto

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestParseTransportError(t *testing.T) {
	var payload [4]byte
	wireCode := int32(-404)
	binary.LittleEndian.PutUint32(payload[:], uint32(wireCode))
	err, ok := ParseTransportError(payload[:])
	if !ok || err.Code != 404 {
		t.Fatalf("error=%v ok=%v", err, ok)
	}
	gotCode, ok := TransportErrorCode(err)
	if !ok || gotCode != 404 {
		t.Fatalf("code=%d ok=%v", gotCode, ok)
	}
	if _, ok := TransportErrorCode(errors.New("other")); ok {
		t.Fatal("ordinary error classified as transport error")
	}
}
