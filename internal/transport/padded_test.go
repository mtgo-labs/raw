package transport

import (
	"bytes"
	"testing"
)

func TestPaddedIntermediateVector(t *testing.T) {
	payload := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	random := bytes.NewReader([]byte{0x02, 0xaa, 0xbb})
	var wire bytes.Buffer
	if err := writePaddedIntermediate(&wire, random, payload); err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x12, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0xaa, 0xbb,
	}
	if !bytes.Equal(wire.Bytes(), want) {
		t.Fatalf("got %x, want %x", wire.Bytes(), want)
	}
	got, err := ReadPaddedIntermediate(bytes.NewReader(wire.Bytes()), len(payload))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %x, want %x", got, payload)
	}
}
