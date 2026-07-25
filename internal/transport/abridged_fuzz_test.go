package transport

import (
	"bytes"
	"testing"
)

func FuzzReadAbridged(f *testing.F) {
	f.Add([]byte{1, 1, 2, 3, 4})
	f.Add([]byte{0x7f, 1, 0, 0, 1, 2, 3, 4})
	f.Fuzz(func(t *testing.T, wire []byte) {
		_, _ = ReadAbridged(bytes.NewReader(wire), 1<<20)
	})
}
