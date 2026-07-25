package transport

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// TestDialNetPollPacketConnRoundTrip exercises the exact wrapping path that
// client.wrapPacket uses: dial netpoll -> NewPacketConn -> WritePacket/ReadPacket.
// The server simulates a Telegram intermediate-transport peer: it consumes the
// client's 0xee header, then echoes a bare length-prefixed packet back.
func TestDialNetPollPacketConnRoundTrip(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		// Consume the 4-byte intermediate protocol header from client.
		header := make([]byte, 4)
		if _, err := io.ReadFull(conn, header); err != nil {
			serverErr <- err
			return
		}
		// Read one length-prefixed intermediate packet.
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			serverErr <- err
			return
		}
		payloadLen := binary.LittleEndian.Uint32(lenBuf)
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			serverErr <- err
			return
		}
		// Echo: bare length-prefixed packet (no protocol header from server).
		echo := make([]byte, 4+len(payload))
		binary.LittleEndian.PutUint32(echo[:4], uint32(len(payload)))
		copy(echo[4:], payload)
		if _, err := conn.Write(echo); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rawConn, err := DialNetPoll(ctx, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rawConn.Close()

	packetConn, err := NewPacketConn(rawConn, PacketIntermediate)
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()

	// Client sends protocol header (same as DialPacket).
	if err := WritePacketHeader(packetConn, PacketIntermediate); err != nil {
		t.Fatal(err)
	}

	// 4-byte-aligned payload for intermediate framing.
	message := []byte("echo-via-netpoll!!!!")
	if err := packetConn.WritePacket(message); err != nil {
		t.Fatal(err)
	}

	reply, err := packetConn.ReadPacket(1024)
	if err != nil {
		t.Fatal(err)
	}

	if string(reply) != string(message) {
		t.Fatalf("got %q, want %q", reply, message)
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not complete in time")
	}
}
