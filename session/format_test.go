package session

import (
	"bytes"
	"errors"
	"testing"
)

func TestSnapshotRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 256)
	want := Snapshot{APIID: 123, PrimaryDC: 2, AuthKeys: []AuthKey{{DCID: 2, Kind: "main", Key: key, ID: 9, Salt: 11, TimeOffset: -3}}}
	data, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	key[0] = 9
	got, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.APIID != want.APIID || got.PrimaryDC != want.PrimaryDC || got.AuthKeys[0].ID != 9 || got.AuthKeys[0].Salt != 11 || got.AuthKeys[0].TimeOffset != -3 || !bytes.Equal(got.AuthKeys[0].Key, bytes.Repeat([]byte{7}, 256)) {
		t.Fatalf("snapshot=%+v", got)
	}
}

func TestSnapshotRejectsUnknownVersion(t *testing.T) {
	data, err := Encode(Snapshot{APIID: 1, PrimaryDC: 1})
	if err != nil {
		t.Fatal(err)
	}
	data[8] = 2
	if _, err := Decode(data); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("err=%v", err)
	}
}

func TestSnapshotRejectsInvalidAuthKey(t *testing.T) {
	if _, err := Encode(Snapshot{APIID: 1, PrimaryDC: 1, AuthKeys: []AuthKey{{DCID: 1, Kind: "main", Key: []byte("short")}}}); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("err=%v", err)
	}
}
