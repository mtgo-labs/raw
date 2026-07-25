package transport

import (
	"bytes"
	"testing"
)

func FuzzReadPaddedIntermediate(f *testing.F) {
	var valid bytes.Buffer
	if err := writePaddedIntermediate(&valid, bytes.NewReader(make([]byte, 16)), make([]byte, 16)); err != nil {
		f.Fatal(err)
	}
	f.Add(valid.Bytes())
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{16, 0, 0, 0, 1})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 4096 {
			t.Skip()
		}
		payload, err := ReadPaddedIntermediate(bytes.NewReader(wire), 1024)
		if err == nil && (len(payload) == 0 || len(payload) > 1024 || len(payload) != 4 && len(payload)%16 != 0) {
			t.Fatalf("accepted payload length %d", len(payload))
		}
	})
}
