package mtproto

import (
	"errors"
	"io"
	"time"

	"github.com/mtgo-labs/raw/tl"
)

var ErrSessionPing = errors.New("mtproto: ping send failed")

// SendSessionPing sends one content-related ping without registering RPC
// pending state. The pong is correlated by the route owner.
func SendSessionPing(
	writer io.Writer,
	random io.Reader,
	state *SessionState,
	authKey AuthKey,
	now time.Time,
	pingID int64,
	disconnectDelay int32,
) (uint64, error) {
	if state == nil || disconnectDelay <= 0 {
		return 0, ErrSessionPing
	}
	messageID, salt, sessionID, sequenceNo := state.NextMessage(now, true)
	if _, err := SendEncryptedObjectWithSalt(
		writer,
		random,
		authKey,
		salt,
		sessionID,
		messageID,
		sequenceNo,
		&tl.MTPPingDelayDisconnect{PingID: pingID, DisconnectDelay: disconnectDelay},
	); err != nil {
		return 0, err
	}
	return messageID, nil
}
