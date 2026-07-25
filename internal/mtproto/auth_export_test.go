package mtproto

import (
	"bytes"
	"errors"
	"testing"
)

func TestAuthExportRoundTrip(t *testing.T) {
	export := AuthExport{DCID: 4, Salt: 9, SessionID: [8]byte{1, 2, 3}}
	export.AuthKey.ID = 7
	export.AuthKey.Key[0] = 8
	data, err := EncodeAuthExport(export)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAuthExport(data)
	if err != nil || got.DCID != 4 || got.AuthKey.ID != 7 || got.Salt != 9 || got.SessionID != export.SessionID || !bytes.Equal(got.AuthKey.Key[:], export.AuthKey.Key[:]) {
		t.Fatalf("export=%+v err=%v", got, err)
	}
}

func TestAuthExportRejectsCorruption(t *testing.T) {
	if _, err := DecodeAuthExport([]byte("bad")); !errors.Is(err, ErrInvalidAuthExport) {
		t.Fatalf("err=%v", err)
	}
}
