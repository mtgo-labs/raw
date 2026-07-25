package transport

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestIntermediateRoundTrip(t *testing.T) {
	payload := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	var wire bytes.Buffer
	if err := WriteIntermediate(&wire, payload); err != nil {
		t.Fatal(err)
	}
	got, err := ReadIntermediate(&wire, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %x, want %x", got, payload)
	}
}

func TestIntermediateRejectsLengths(t *testing.T) {
	for _, payload := range [][]byte{nil, {1}, {1, 2, 3}} {
		if err := WriteIntermediate(io.Discard, payload); !errors.Is(err, ErrIntermediateLength) {
			t.Fatalf("write %x error = %v", payload, err)
		}
	}
	for _, wire := range [][]byte{{0, 0, 0, 0}, {1, 0, 0, 0}, {5, 0, 0, 0}} {
		if _, err := ReadIntermediate(bytes.NewReader(wire), 32); !errors.Is(err, ErrIntermediateLength) {
			t.Fatalf("read %x error = %v", wire, err)
		}
	}
}

func TestIntermediateBoundsBeforeAllocation(t *testing.T) {
	wire := []byte{0x00, 0x10, 0x00, 0x00}
	if _, err := ReadIntermediate(bytes.NewReader(wire), 1024); !errors.Is(err, ErrIntermediateLimit) {
		t.Fatalf("error = %v, want ErrIntermediateLimit", err)
	}
}

type shortWriter struct{ output bytes.Buffer }

func (writer *shortWriter) Write(data []byte) (int, error) {
	if len(data) > 1 {
		data = data[:1]
	}
	return writer.output.Write(data)
}

func TestIntermediateHandlesShortWrites(t *testing.T) {
	writer := new(shortWriter)
	if err := WriteIntermediate(writer, []byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(writer.output.Bytes(), []byte{4, 0, 0, 0, 1, 2, 3, 4}) {
		t.Fatalf("wire = %x", writer.output.Bytes())
	}
}
