package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// setNoDelay disables Nagle's algorithm on a TCP connection. MTProto sends
// small encrypted packets that must be delivered immediately; without
// TCP_NODELAY the kernel may buffer them for up to 40 ms waiting for the
// previous segment's ACK.
func setNoDelay(connection net.Conn) {
	if tcp, ok := connection.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
}

// DialIntermediate opens a TCP connection for intermediate MTProto framing.
// The returned connection is owned by the caller and must be closed there.
func DialIntermediate(ctx context.Context, address string) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("transport: nil dial context")
	}
	if address == "" {
		return nil, errors.New("transport: empty dial address")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("transport: dial intermediate TCP: %w", err)
	}
	setNoDelay(connection)
	return connection, nil
}
