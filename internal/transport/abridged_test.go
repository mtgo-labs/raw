package transport

import (
	"bytes"
	"errors"
	"testing"
)

func TestAbridgedRoundTrip(t *testing.T) {
	for _, payload := range [][]byte{bytes.Repeat([]byte{1}, 4), bytes.Repeat([]byte{2}, 512)} {
		var wire bytes.Buffer
		if err := WriteAbridged(&wire, payload); err != nil {
			t.Fatal(err)
		}
		got, err := ReadAbridged(&wire, len(payload))
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("got=%x err=%v", got, err)
		}
	}
}

func TestAbridgedRejectsBounds(t *testing.T) {
	if err := WriteAbridged(&bytes.Buffer{}, []byte{1, 2}); !errors.Is(err, ErrAbridgedLength) {
		t.Fatalf("write err=%v", err)
	}
	if _, err := ReadAbridged(bytes.NewReader([]byte{0}), 32); !errors.Is(err, ErrAbridgedLength) {
		t.Fatalf("zero err=%v", err)
	}
	if _, err := ReadAbridged(bytes.NewReader([]byte{0x7f, 0, 4, 0}), 1024); !errors.Is(err, ErrAbridgedLimit) {
		t.Fatalf("limit err=%v", err)
	}
}

func TestAbridgedWireVectors(t *testing.T) {
	var wire bytes.Buffer
	if err := WriteAbridged(&wire, []byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire.Bytes(), []byte{1, 1, 2, 3, 4}) {
		t.Fatalf("wire=%x", wire.Bytes())
	}
	wire.Reset()
	payload := bytes.Repeat([]byte{9}, 508)
	if err := WriteAbridged(&wire, payload); err != nil {
		t.Fatal(err)
	}
	if wire.Bytes()[0] != 0x7f || wire.Bytes()[1] != 127 || wire.Bytes()[2] != 0 || wire.Bytes()[3] != 0 {
		t.Fatalf("extended header=%x", wire.Bytes()[:4])
	}
}
