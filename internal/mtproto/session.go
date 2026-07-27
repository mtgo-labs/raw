package mtproto

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"time"

	"github.com/mtgo-labs/raw/internal/transport"
	"github.com/mtgo-labs/raw/tl"
)

var ErrSessionClosed = errors.New("mtproto: session is closed")

// Session composes the direct encrypted wire primitives for one DC. It does
// not own a connection, start goroutines, or apply retry policy.
type Session struct {
	state   *SessionState
	pending *PendingTable
	authKey atomic.Pointer[AuthKey]
	closed  atomic.Bool
}

func NewSession(authKey AuthKey, salt int64, sessionID [8]byte, pendingCapacity int) *Session {
	session := &Session{state: NewSessionState(salt, sessionID, authKey.TimeOffset), pending: NewPendingTable(pendingCapacity)}
	session.authKey.Store(&authKey)
	return session
}

func (session *Session) Send(writer io.Writer, random io.Reader, now time.Time, object tl.Object) (uint64, error) {
	if session == nil || session.closed.Load() {
		return 0, ErrSessionClosed
	}
	return SendSessionObject(writer, random, session.state, session.pending, *session.authKey.Load(), now, object)
}
func (session *Session) Prepare(now time.Time, object tl.Object) (tl.MTPMessage, *PendingRequest, error) {
	if session == nil || session.closed.Load() {
		return tl.MTPMessage{}, nil, ErrSessionClosed
	}
	return PrepareSessionObject(session.state, session.pending, now, object)
}

func (session *Session) SendPrepared(
	writer io.Writer,
	random io.Reader,
	now time.Time,
	messages []tl.MTPMessage,
	acknowledgementIDs []int64,
	forceContainer bool,
) (uint64, error) {
	if session == nil {
		return 0, ErrSessionClosed
	}
	if session.closed.Load() {
		cancelPreparedMessages(session.pending, messages, ErrSessionClosed)
		return 0, ErrSessionClosed
	}
	return SendPreparedSessionObjects(
		writer,
		random,
		session.state,
		session.pending,
		*session.authKey.Load(),
		now,
		messages,
		acknowledgementIDs,
		forceContainer,
	)
}

func (session *Session) Cancel(messageID uint64, err error) bool {
	return session != nil && session.pending.Cancel(messageID, err)
}

func (session *Session) SendControl(writer io.Writer, random io.Reader, now time.Time, object tl.Object) (uint64, error) {
	if session == nil || session.closed.Load() {
		return 0, ErrSessionClosed
	}
	return SendSessionControl(writer, random, session.state, *session.authKey.Load(), now, object)
}

func (session *Session) SendPing(writer io.Writer, random io.Reader, now time.Time, pingID int64, disconnectDelay int32) (uint64, error) {
	if session == nil || session.closed.Load() {
		return 0, ErrSessionClosed
	}
	return SendSessionPing(writer, random, session.state, *session.authKey.Load(), now, pingID, disconnectDelay)
}

func (session *Session) Receive(reader io.Reader, maxPayload int) (InboundResult, uint64, uint32, error) {
	if session == nil || session.closed.Load() {
		return InboundResult{}, 0, 0, ErrSessionClosed
	}
	var (
		result     InboundResult
		messageID  uint64
		sequenceNo uint32
	)
	err := transport.ReadPacketView(reader, maxPayload, func(payload []byte) error {
		var err error
		result, messageID, sequenceNo, err = ReceiveSessionPayload(payload, session.state, session.pending, *session.authKey.Load())
		return err
	})
	return result, messageID, sequenceNo, err
}

func (session *Session) NeedsFutureSalts() bool {
	return session != nil && !session.closed.Load() && session.state.needsFutureSalts()
}

func (session *Session) SendFutureSaltsRequest(writer io.Writer, random io.Reader, now time.Time) (uint64, bool, error) {
	if session == nil || session.closed.Load() {
		return 0, false, ErrSessionClosed
	}
	messageID, salt, sessionID, sequenceNo, ok := session.state.nextFutureSaltRequest(now)
	if !ok {
		return 0, false, nil
	}
	if _, err := SendEncryptedObjectWithSalt(
		writer,
		random,
		*session.authKey.Load(),
		salt,
		sessionID,
		messageID,
		sequenceNo,
		&tl.MTPGetFutureSalts{Num: maxFutureSalts},
	); err != nil {
		session.state.failFutureSaltRequest(messageID)
		return 0, true, err
	}
	return messageID, true, nil
}

func (session *Session) Wait(ctx context.Context, messageID uint64) (*PendingRequest, error) {
	if session == nil {
		return nil, ErrSessionClosed
	}
	return session.pending.Wait(ctx, messageID)
}

func (session *Session) WaitPrepared(ctx context.Context, request *PendingRequest) (*PendingRequest, error) {
	if session == nil {
		return nil, ErrSessionClosed
	}
	return session.pending.WaitRequest(ctx, request)
}

func (session *Session) RecoveryMessages() []tl.MTPMessage {
	if session == nil || session.closed.Load() {
		return nil
	}
	return session.pending.RecoveryMessages()
}

func (session *Session) AuthKey() AuthKey {
	if session == nil {
		return AuthKey{}
	}
	return *session.authKey.Load()
}

// ReplaceAuthKey switches encryption to a newly bound temporary key.
func (session *Session) ReplaceAuthKey(authKey AuthKey) error {
	if session == nil || authKey.ID == 0 || session.closed.Load() {
		return ErrSessionClosed
	}
	session.authKey.Store(&authKey)
	return nil
}

// ReplaceAuthKeyWithSalt switches both encryption key and session salt after
// a temporary key has been bound.
func (session *Session) ReplaceAuthKeyWithSalt(authKey AuthKey, salt int64) error {
	if err := session.ReplaceAuthKey(authKey); err != nil {
		return err
	}
	session.state.ReplaceSalt(salt)
	return nil
}

func (session *Session) SessionID() [8]byte {
	if session == nil {
		return [8]byte{}
	}
	return session.state.SessionID()
}

func (session *Session) Close(err error) int {
	if session == nil || session.closed.Load() {
		return 0
	}
	if session.closed.Swap(true) {
		return 0
	}
	if err == nil {
		err = ErrSessionClosed
	}
	return session.pending.Close(err)
}

func (session *Session) Salt() int64  { return session.state.Salt() }
func (session *Session) Pending() int { return session.pending.Len() }
