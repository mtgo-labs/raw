package mtproto

import (
	"fmt"
	"io"
	"time"
)

// SendPFSBind sends auth.bindTempAuthKey with an inner binding message that
// uses the exact same MTProto message ID as the outer request.
func (session *Session) SendPFSBind(writer io.Writer, random io.Reader, now time.Time, binding *PFSBinding) (uint64, error) {
	if session == nil || session.closed.Load() || writer == nil || random == nil || binding == nil {
		return 0, ErrInvalidPFSBinding
	}
	authKey := *session.authKey.Load()
	if authKey.ID == 0 || authKey.ID != binding.TemporaryID() {
		return 0, ErrInvalidPFSBinding
	}
	messageID, salt, sessionID, sequenceNo := session.state.NextMessage(now, true)
	request, err := binding.BindRequestAt(random, messageID, now)
	if err != nil {
		return 0, err
	}
	if _, err := session.pending.Add(messageID); err != nil {
		return 0, err
	}
	if _, err := SendEncryptedObjectWithSalt(writer, random, authKey, salt, sessionID, messageID, sequenceNo, request); err != nil {
		session.pending.Cancel(messageID, fmt.Errorf("%w: %v", ErrSessionSend, err))
		return 0, err
	}
	return messageID, nil
}
