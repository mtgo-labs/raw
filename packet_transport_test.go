package raw

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
)

type packetTransportStub struct {
	net.Conn
	configured   uint8
	configureErr error
	closed       atomic.Bool
}

func (connection *packetTransportStub) ConfigurePacketTransport(mode uint8) error {
	connection.configured = mode
	return connection.configureErr
}

func (*packetTransportStub) ReadPacket(int) ([]byte, error)        { return nil, nil }
func (*packetTransportStub) WritePacket([]byte) error              { return nil }
func (*packetTransportStub) WritePacketReserved([]byte, int) error { return nil }
func (*packetTransportStub) ReadPlainPacket(int) ([]byte, error)   { return nil, nil }
func (*packetTransportStub) WritePlainPacket(uint64, []byte) error { return nil }

func (connection *packetTransportStub) Close() error {
	connection.closed.Store(true)
	return connection.Conn.Close()
}

func TestWrapPacketUsesStructuralPacketTransport(t *testing.T) {
	tests := []struct {
		name   string
		mode   TransportKind
		marker []byte
	}{
		{name: "intermediate", mode: TransportIntermediate, marker: []byte{0xee, 0xee, 0xee, 0xee}},
		{name: "abridged", mode: TransportAbridged, marker: []byte{0xef}},
		{name: "padded intermediate", mode: TransportPaddedIntermediate, marker: []byte{0xdd, 0xdd, 0xdd, 0xdd}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			left, right := net.Pipe()
			defer right.Close()
			connection := &packetTransportStub{Conn: left}
			markerErr := make(chan error, 1)
			go func() {
				marker := make([]byte, len(test.marker))
				_, err := io.ReadFull(right, marker)
				if err == nil && string(marker) != string(test.marker) {
					err = errors.New("unexpected transport marker")
				}
				markerErr <- err
			}()

			client := &Client{config: Config{Transport: test.mode}}
			wrapped, err := client.wrapPacket(connection)
			if err != nil {
				t.Fatal(err)
			}
			if wrapped != connection {
				t.Fatalf("wrapPacket returned %T, want original packet transport", wrapped)
			}
			if connection.configured != uint8(test.mode) {
				t.Fatalf("configured mode = %d, want %d", connection.configured, test.mode)
			}
			if err := <-markerErr; err != nil {
				t.Fatal(err)
			}
			_ = connection.Close()
		})
	}
}

func TestWrapPacketClosesPacketTransportOnConfigureError(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	wantErr := errors.New("configure failed")
	connection := &packetTransportStub{Conn: left, configureErr: wantErr}
	client := &Client{config: Config{Transport: TransportIntermediate}}

	if _, err := client.wrapPacket(connection); !errors.Is(err, wantErr) {
		t.Fatalf("wrapPacket error = %v, want %v", err, wantErr)
	}
	if !connection.closed.Load() {
		t.Fatal("packet transport was not closed")
	}
}
