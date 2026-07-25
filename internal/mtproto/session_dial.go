package mtproto

import (
	"context"
	"net"

	"github.com/mtgo-labs/raw/internal/transport"
)

// DialSession opens an intermediate TCP connection and initializes a session.
// The caller owns and closes the returned connection.
func DialSession(ctx context.Context, address string, authKey AuthKey, salt int64, sessionID [8]byte, pendingCapacity int) (net.Conn, *Session, error) {
	return DialPacketSession(ctx, address, transport.PacketIntermediate, authKey, salt, sessionID, pendingCapacity)
}

func DialPacketSession(ctx context.Context, address string, mode transport.PacketMode, authKey AuthKey, salt int64, sessionID [8]byte, pendingCapacity int) (net.Conn, *Session, error) {
	connection, err := transport.DialPacket(ctx, address, mode)
	if err != nil {
		return nil, nil, err
	}
	return connection, NewSession(authKey, salt, sessionID, pendingCapacity), nil
}
