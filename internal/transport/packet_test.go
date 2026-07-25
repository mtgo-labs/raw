package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
)

func TestWritePacketHeaderVectors(t *testing.T) {
	tests := []struct {
		name string
		mode PacketMode
		want []byte
	}{
		{name: "abridged", mode: PacketAbridged, want: []byte{0xef}},
		{name: "intermediate", mode: PacketIntermediate, want: []byte{0xee, 0xee, 0xee, 0xee}},
		{name: "padded intermediate", mode: PacketPaddedIntermediate, want: []byte{0xdd, 0xdd, 0xdd, 0xdd}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var wire bytes.Buffer
			if err := WritePacketHeader(&wire, test.mode); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(wire.Bytes(), test.want) {
				t.Fatalf("got %x, want %x", wire.Bytes(), test.want)
			}
		})
	}
}

func TestDialPacketWritesProtocolHeader(t *testing.T) {
	tests := []struct {
		name string
		mode PacketMode
		want []byte
	}{
		{name: "abridged", mode: PacketAbridged, want: []byte{0xef}},
		{name: "intermediate", mode: PacketIntermediate, want: []byte{0xee, 0xee, 0xee, 0xee}},
		{name: "padded intermediate", mode: PacketPaddedIntermediate, want: []byte{0xdd, 0xdd, 0xdd, 0xdd}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			received := make(chan []byte, 1)
			serverErr := make(chan error, 1)
			go func() {
				connection, err := listener.Accept()
				if err != nil {
					serverErr <- err
					return
				}
				defer connection.Close()
				wire := make([]byte, len(test.want))
				if _, err := io.ReadFull(connection, wire); err != nil {
					serverErr <- err
					return
				}
				received <- wire
			}()
			connection, err := DialPacket(context.Background(), listener.Addr().String(), test.mode)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			select {
			case err := <-serverErr:
				t.Fatal(err)
			case wire := <-received:
				if !bytes.Equal(wire, test.want) {
					t.Fatalf("got %x, want %x", wire, test.want)
				}
			}
		})
	}
}

func TestPacketConnAbridgedRoundTrip(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	writer, err := NewPacketConn(left, PacketAbridged)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewPacketConn(right, PacketAbridged)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{3}, 8)
	done := make(chan error, 1)
	go func() { done <- writer.WritePacket(payload) }()
	got, err := reader.ReadPacket(64)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("got=%x err=%v", got, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type writeCountingConn struct {
	net.Conn
	writes int
}

func (connection *writeCountingConn) Write(payload []byte) (int, error) {
	connection.writes++
	return connection.Conn.Write(payload)
}

func TestPacketConnReservedIntermediateWritesOneFrame(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	counting := &writeCountingConn{Conn: left}
	writer, err := NewPacketConn(counting, PacketIntermediate)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{3}, 16)
	packet := make([]byte, PacketFrameHeadroom+len(payload))
	copy(packet[PacketFrameHeadroom:], payload)
	done := make(chan error, 1)
	go func() { done <- WritePacketReserved(writer, packet, PacketFrameHeadroom) }()
	got, err := ReadIntermediate(right, 64)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("got=%x err=%v", got, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if counting.writes != 1 {
		t.Fatalf("writes=%d, want 1", counting.writes)
	}
}

func TestPacketConnPaddedIntermediateRoundTrip(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	writer, err := NewPacketConn(left, PacketPaddedIntermediate)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewPacketConn(right, PacketPaddedIntermediate)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{3}, 16)
	done := make(chan error, 1)
	go func() { done <- writer.WritePacket(payload) }()
	got, err := reader.ReadPacket(64)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("got=%x err=%v", got, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPacketConnPlainRoundTrip(t *testing.T) {
	for _, mode := range []PacketMode{PacketIntermediate, PacketAbridged, PacketPaddedIntermediate} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			writer, err := NewPacketConn(left, mode)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := NewPacketConn(right, mode)
			if err != nil {
				t.Fatal(err)
			}
			body := []byte{1, 2, 3, 4}
			done := make(chan error, 1)
			go func() { done <- WritePlain(writer, 7, body) }()
			message, err := ReadPlain(reader, 64)
			if err != nil || message.MessageID != 7 || !bytes.Equal(message.Body, body) {
				t.Fatalf("message=%+v err=%v", message, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
