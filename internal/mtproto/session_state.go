package mtproto

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mtgo-labs/raw/tl"
)

var ErrSessionControl = errors.New("mtproto: unsupported session control event")

// SessionState owns the mutable wire state needed by encrypted messages.
type SessionState struct {
	mu                   sync.Mutex
	salt                 int64
	future               FutureSaltTable
	sequence             uint32
	sessionID            [8]byte
	timeOffset           int64
	lastMessageID        uint64
	incoming             incomingMessageIDs
	futureSaltRequestID  uint64
	lastSessionCreatedID int64
	futureSaltsNeeded    atomic.Bool
}

func (state *SessionState) validateIncomingMessageIDs(messageID uint64, object tl.Object, now time.Time) error {
	if state == nil || object == nil {
		return ErrSessionControl
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	serverTime := adjustUnixSeconds(now.Unix(), state.timeOffset)
	return state.incoming.validateAndAdd(messageID, object, serverTime)
}

func (state *SessionState) hasIncomingMessage(messageID uint64) bool {
	if state == nil || messageID == 0 {
		return false
	}
	state.mu.Lock()
	_, found := state.incoming.search(messageID)
	state.mu.Unlock()
	return found
}

func NewSessionState(salt int64, sessionID [8]byte, timeOffset int64) *SessionState {
	state := &SessionState{salt: salt, sessionID: sessionID, timeOffset: timeOffset}
	state.futureSaltsNeeded.Store(salt != 0)
	return state
}

func (state *SessionState) Salt() int64 {
	if state == nil {
		return 0
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.salt
}

func (state *SessionState) ReplaceSalt(salt int64) {
	if state == nil {
		return
	}
	state.mu.Lock()
	state.salt = salt
	state.updateFutureSaltNeedLocked()
	state.mu.Unlock()
}

func (state *SessionState) SessionID() [8]byte {
	if state == nil {
		return [8]byte{}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.sessionID
}

func (state *SessionState) Reset(sessionID [8]byte) {
	if state == nil || sessionID == [8]byte{} {
		return
	}
	state.mu.Lock()
	state.sequence = 0
	state.sessionID = sessionID
	state.lastMessageID = 0
	state.incoming = incomingMessageIDs{}
	state.futureSaltRequestID = 0
	state.updateFutureSaltNeedLocked()
	state.mu.Unlock()
}

func (state *SessionState) CorrectTime(now time.Time, sourceMessageID uint64, force bool) error {
	if state == nil || sourceMessageID == 0 {
		return ErrSessionRecovery
	}
	serverTime := int64(sourceMessageID >> 32)
	if serverTime <= 0 {
		return ErrSessionRecovery
	}
	offset := serverTime - now.Unix()
	state.mu.Lock()
	if force || offset > state.timeOffset {
		// The monotonic floor survives time corrections: lowering it here
		// would let the next time-derived id fall below ids the server has
		// already accepted, drawing MSGID_DECREASE_RETRY. Only Reset, which
		// rotates the session id, may clear the floor.
		state.timeOffset = offset
	}
	state.mu.Unlock()
	return nil
}

func (state *SessionState) ApplyNewSession(firstMessageID, uniqueID uint64, salt int64) (bool, bool, error) {
	if state == nil || firstMessageID == 0 || uniqueID == 0 || salt == 0 {
		return false, false, ErrSessionRecovery
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.lastSessionCreatedID == int64(uniqueID) {
		return false, false, nil
	}
	previous := state.lastSessionCreatedID != 0
	state.lastSessionCreatedID = int64(uniqueID)
	state.salt = salt
	state.updateFutureSaltNeedLocked()
	return true, previous, nil
}

func (state *SessionState) inboundEnvelope(now time.Time) (int64, [8]byte) {
	if state == nil {
		return 0, [8]byte{}
	}
	state.mu.Lock()
	state.activateFutureSaltLocked(adjustUnixSeconds(now.Unix(), state.timeOffset))
	salt, sessionID := state.salt, state.sessionID
	state.mu.Unlock()
	return salt, sessionID
}

// NextSequence returns the next MTProto sequence number. Content-related
// messages consume one sequence slot and use odd numbers; non-content messages
// use the corresponding even number.
func (state *SessionState) NextSequence(contentRelated bool) uint32 {
	if state == nil {
		return 0
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if contentRelated {
		sequence := state.sequence*2 + 1
		state.sequence++
		return sequence
	}
	return state.sequence * 2
}

// ApplyControl applies only stateful control data. Retry, resend, and pending
// request policy remain with the session owner.
func (state *SessionState) ApplyControl(event ControlEvent) error {
	if state == nil {
		return ErrSessionControl
	}
	if event.Kind != ControlBadSalt || event.NewSalt == 0 {
		return ErrSessionControl
	}
	state.mu.Lock()
	state.salt = event.NewSalt
	state.updateFutureSaltNeedLocked()
	state.mu.Unlock()
	return nil
}

func (state *SessionState) ApplyFutureSalts(values *tl.MTPFutureSalts) error {
	if state == nil {
		return ErrSessionControl
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := state.future.Apply(values); err != nil {
		return err
	}
	state.updateFutureSaltNeedLocked()
	return nil
}

func (state *SessionState) FutureSalt(serverTime int64) (int64, bool) {
	if state == nil {
		return 0, false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.future.Select(serverTime)
}

// NextMessage reserves the wire metadata for one outbound message.
func (state *SessionState) NextMessage(now time.Time, contentRelated bool) (uint64, int64, [8]byte, uint32) {
	if state == nil {
		return 0, 0, [8]byte{}, 0
	}
	state.mu.Lock()
	state.activateFutureSaltLocked(adjustUnixSeconds(now.Unix(), state.timeOffset))
	messageID, salt, sessionID, sequenceNo := state.nextMessageLocked(now, contentRelated)
	state.mu.Unlock()
	return messageID, salt, sessionID, sequenceNo
}

func (state *SessionState) nextFutureSaltRequest(now time.Time) (uint64, int64, [8]byte, uint32, bool) {
	if state == nil || !state.futureSaltsNeeded.Load() {
		return 0, 0, [8]byte{}, 0, false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	state.activateFutureSaltLocked(adjustUnixSeconds(now.Unix(), state.timeOffset))
	if state.futureSaltRequestID != 0 || state.salt == 0 || state.future.Remaining() >= 2 {
		return 0, 0, [8]byte{}, 0, false
	}
	messageID, salt, sessionID, sequenceNo := state.nextMessageLocked(now, true)
	state.futureSaltRequestID = messageID
	state.futureSaltsNeeded.Store(false)
	return messageID, salt, sessionID, sequenceNo, true
}

func (state *SessionState) failFutureSaltRequest(messageID uint64) {
	if state == nil || messageID == 0 {
		return
	}
	state.mu.Lock()
	if state.futureSaltRequestID == messageID {
		state.futureSaltRequestID = 0
		state.updateFutureSaltNeedLocked()
	}
	state.mu.Unlock()
}

func (state *SessionState) applyFutureSaltsResponse(values *tl.MTPFutureSalts) error {
	if state == nil || values == nil || values.ReqMessageID == 0 || values.Now <= 0 {
		return ErrInvalidFutureSalt
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if uint64(values.ReqMessageID) != state.futureSaltRequestID {
		return ErrInvalidFutureSalt
	}
	if err := state.future.Apply(values); err != nil {
		return err
	}
	state.futureSaltRequestID = 0
	state.activateFutureSaltLocked(int64(values.Now))
	return nil
}

func (state *SessionState) needsFutureSalts() bool {
	return state != nil && state.futureSaltsNeeded.Load()
}

func (state *SessionState) nextMessageLocked(now time.Time, contentRelated bool) (uint64, int64, [8]byte, uint32) {
	messageID := clientMessageID(now, state.timeOffset)
	if messageID <= state.lastMessageID {
		messageID = state.lastMessageID + 4
	}
	state.lastMessageID = messageID
	sequenceNo := state.sequence * 2
	if contentRelated {
		sequenceNo++
		state.sequence++
	}
	salt, sessionID := state.salt, state.sessionID
	return messageID, salt, sessionID, sequenceNo
}

func (state *SessionState) activateFutureSaltLocked(serverTime int64) {
	if salt, ok := state.future.Activate(serverTime); ok {
		state.salt = salt
	}
	state.updateFutureSaltNeedLocked()
}

func (state *SessionState) updateFutureSaltNeedLocked() {
	state.futureSaltsNeeded.Store(
		state.salt != 0 &&
			state.futureSaltRequestID == 0 &&
			state.future.Remaining() < 2,
	)
}
