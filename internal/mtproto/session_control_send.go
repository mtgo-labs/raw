package mtproto

import (
	"errors"
	"io"
	"time"

	"github.com/mtgo-labs/raw/tl"
)

var ErrSessionControlSend = errors.New("mtproto: control send failed")

// SendSessionControl sends one non-content control object. It uses an even
// sequence number and never registers pending request state.
func SendSessionControl(writer io.Writer, random io.Reader, state *SessionState, authKey AuthKey, now time.Time, object tl.Object) (uint64, error) {
	if state == nil || object == nil {
		return 0, ErrSessionControlSend
	}
	messageID, salt, sessionID, sequenceNo := state.NextMessage(now, false)
	if _, err := SendEncryptedObjectWithSalt(writer, random, authKey, salt, sessionID, messageID, sequenceNo, object); err != nil {
		return 0, err
	}
	return messageID, nil
}
