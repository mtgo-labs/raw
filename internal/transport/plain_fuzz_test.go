package transport

import (
	"bytes"
	"testing"
)

func FuzzReadPlain(f *testing.F) {
	var valid bytes.Buffer
	if err := WritePlain(&valid, 1, []byte{1, 2, 3, 4}); err != nil {
		f.Fatal(err)
	}
	f.Add(valid.Bytes())
	f.Add([]byte{})
	f.Add([]byte{24, 0, 0, 0})
	f.Add([]byte{24, 0, 0, 0, 1, 0, 0, 0})

	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 4096 {
			t.Skip()
		}
		message, err := ReadPlain(bytes.NewReader(wire), 1024)
		if err == nil && (message.MessageID == 0 || len(message.Body) == 0 || len(message.Body) > 1024 || len(message.Body)%4 != 0) {
			t.Fatalf("accepted message ID %d with body length %d", message.MessageID, len(message.Body))
		}
	})
}
