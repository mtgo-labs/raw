package session

import "testing"

func FuzzDecodeSnapshot(f *testing.F) {
	valid, err := Encode(Snapshot{APIID: 1, PrimaryDC: 2})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte("MTGORAW\x00\x02\x00\x02\x00\x00\x00{}"))
	f.Add([]byte("MTGORAW\x00\x01\x00\x03\x00\x00\x00{}"))
	f.Add([]byte("MTGORAW\x00\x01\x00\x01\x00\x00\x00{"))

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 4096 {
			t.Skip()
		}
		snapshot, err := Decode(input)
		if err != nil {
			return
		}
		encoded, err := Encode(snapshot)
		if err != nil {
			t.Fatalf("Encode accepted snapshot: %v", err)
		}
		if _, err := Decode(encoded); err != nil {
			t.Fatalf("Decode re-encoded snapshot: %v", err)
		}
	})
}
