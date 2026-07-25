package transport

import (
	"bytes"
	"errors"
	"net"
	"testing"
)

func TestPlainRoundTrip(t *testing.T) {
	body := []byte{1, 2, 3, 4}
	var wire bytes.Buffer
	if err := WritePlain(&wire, 0x1122334455667788, body); err != nil {
		t.Fatal(err)
	}
	message, err := ReadPlain(&wire, 32)
	if err != nil {
		t.Fatal(err)
	}
	if message.MessageID != 0x1122334455667788 || !bytes.Equal(message.Body, body) {
		t.Fatalf("message = %+v", message)
	}
}

func TestPlainReadUnblocksOnClose(t *testing.T) {
	client, server := net.Pipe()
	result := make(chan error, 1)
	go func() {
		_, err := ReadPlain(server, 1024)
		result <- err
	}()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err == nil {
		t.Fatal("read unexpectedly succeeded after close")
	}
	_ = server.Close()
}

func BenchmarkWriteIntermediate(b *testing.B) {
	payload := make([]byte, 1024)
	var output bytes.Buffer
	output.Grow(1028)
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		output.Reset()
		if err := WriteIntermediate(&output, payload); err != nil {
			b.Fatal(err)
		}
	}
}

func TestPlainRejectsInvalidValues(t *testing.T) {
	if err := WritePlain(&bytes.Buffer{}, 0, []byte{1, 2, 3, 4}); !errors.Is(err, ErrPlainHeader) {
		t.Fatalf("zero ID error = %v", err)
	}
	if err := WritePlain(&bytes.Buffer{}, 1, []byte{1}); !errors.Is(err, ErrPlainBody) {
		t.Fatalf("unaligned body error = %v", err)
	}
	var wire bytes.Buffer
	if err := WritePlain(&wire, 1, []byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	data := wire.Bytes()
	data[4] = 1
	if _, err := ReadPlain(bytes.NewReader(data), 32); !errors.Is(err, ErrPlainHeader) {
		t.Fatalf("auth key ID error = %v", err)
	}
}
