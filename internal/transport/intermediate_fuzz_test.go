package transport

import (
	"bytes"
	"testing"
)

func FuzzReadIntermediate(f *testing.F) {
	f.Add([]byte{4, 0, 0, 0, 1, 2, 3, 4})
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, wire []byte) {
		_, _ = ReadIntermediate(bytes.NewReader(wire), 1<<20)
	})
}
