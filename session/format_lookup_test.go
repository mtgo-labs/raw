package session

import (
	"bytes"
	"testing"
)

func TestSnapshotAuthKeyForCopiesKey(t *testing.T) {
	snapshot := Snapshot{AuthKeys: []AuthKey{{DCID: 4, Kind: "upload", Key: bytes.Repeat([]byte{1}, 256), ID: 8}}}
	got, ok := snapshot.AuthKeyFor(4, "upload")
	if !ok || got.ID != 8 {
		t.Fatalf("key=%+v ok=%v", got, ok)
	}
	got.Key[0] = 9
	if snapshot.AuthKeys[0].Key[0] != 1 {
		t.Fatal("lookup aliases snapshot key")
	}
}
