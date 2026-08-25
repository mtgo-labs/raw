package mtproto

import (
	"errors"
	"slices"
	"time"

	"github.com/mtgo-labs/raw/tl"
)

var ErrSessionRecovery = errors.New("mtproto: invalid session recovery event")

// RecoveryTarget identifies one unresolved outbound request selected for
// retransmission. Targets are produced by the receive path; the route owner
// completes them with RecoverTargets while holding its write lock, so the
// re-sent ids reach the wire in allocation order.
type RecoveryTarget struct {
	request *PendingRequest
}

func (table *PendingTable) recoveryTargets(match func(*PendingRequest) bool) []RecoveryTarget {
	if table == nil {
		return nil
	}
	table.mu.Lock()
	targets := make([]RecoveryTarget, 0, len(table.entries))
	for _, request := range table.entries {
		if !request.Done && request.message.Body != nil && match(request) {
			targets = append(targets, RecoveryTarget{request: request})
		}
	}
	table.mu.Unlock()
	slices.SortFunc(targets, func(left, right RecoveryTarget) int {
		switch {
		case left.request.wireMessageID < right.request.wireMessageID:
			return -1
		case left.request.wireMessageID > right.request.wireMessageID:
			return 1
		default:
			return 0
		}
	})
	return targets
}

func (table *PendingTable) reassign(target RecoveryTarget, message tl.MTPMessage) bool {
	if table == nil || target.request == nil || message.MessageID == 0 {
		return false
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	request := target.request
	if request.Done || table.entries[request.wireMessageID] != request {
		return false
	}
	newMessageID := uint64(message.MessageID)
	if existing := table.entries[newMessageID]; existing != nil && existing != request {
		return false
	}
	delete(table.entries, request.wireMessageID)
	request.wireMessageID = newMessageID
	request.message = message
	request.containerID = 0
	request.acknowledged = false
	table.entries[newMessageID] = request
	return true
}

// recoverTargets allocates one fresh message id per target and re-keys its
// pending entry. It must run under the same write lock that serializes the
// follow-up wire write, or the fresh ids can reach the server out of order.
func recoverTargets(state *SessionState, pending *PendingTable, now time.Time, targets []RecoveryTarget) []tl.MTPMessage {
	if state == nil || pending == nil || len(targets) == 0 {
		return nil
	}
	messages := make([]tl.MTPMessage, 0, len(targets))
	for _, target := range targets {
		messageID, _, _, sequenceNo := state.NextMessage(now, true)
		message := target.request.message
		message.MessageID = int64(messageID)
		message.Seqno = int32(sequenceNo)
		if pending.reassign(target, message) {
			messages = append(messages, message)
		}
	}
	return messages
}

func recoverPending(
	state *SessionState,
	pending *PendingTable,
	now time.Time,
	match func(*PendingRequest) bool,
) []tl.MTPMessage {
	if state == nil || pending == nil {
		return nil
	}
	return recoverTargets(state, pending, now, pending.recoveryTargets(match))
}

// RecoverTargets completes recovery targets by assigning fresh message ids
// and returning the messages ready to send.
func (session *Session) RecoverTargets(now time.Time, targets []RecoveryTarget) []tl.MTPMessage {
	if session == nil || session.closed.Load() {
		return nil
	}
	return recoverTargets(session.state, session.pending, now, targets)
}

func (table *PendingTable) markSent(containerID uint64, messages []tl.MTPMessage) {
	if table == nil || containerID == 0 || len(messages) == 0 {
		return
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	for _, message := range messages {
		request := table.entries[uint64(message.MessageID)]
		if request == nil || request.Done {
			continue
		}
		if containerID == uint64(message.MessageID) {
			request.containerID = 0
		} else {
			request.containerID = containerID
		}
	}
}

func (table *PendingTable) acknowledge(messageIDs []int64) {
	if table == nil || len(messageIDs) == 0 {
		return
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	for _, signedID := range messageIDs {
		messageID := uint64(signedID)
		if request := table.entries[messageID]; request != nil && !request.Done {
			request.acknowledged = true
			continue
		}
		for _, request := range table.entries {
			if !request.Done && request.containerID == messageID {
				request.acknowledged = true
			}
		}
	}
}

func (table *PendingTable) containsRelated(messageID uint64) bool {
	if table == nil || messageID == 0 {
		return false
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	if request := table.entries[messageID]; request != nil && !request.Done {
		return true
	}
	for _, request := range table.entries {
		if !request.Done && request.containerID == messageID {
			return true
		}
	}
	return false
}

func (session *Session) RecoverMessage(messageID uint64, now time.Time) []tl.MTPMessage {
	if session == nil || session.closed.Load() || messageID == 0 {
		return nil
	}
	return recoverPending(session.state, session.pending, now, func(request *PendingRequest) bool {
		return request.wireMessageID == messageID || request.containerID == messageID
	})
}

func (session *Session) RecoverBefore(firstMessageID uint64, now time.Time) []tl.MTPMessage {
	if session == nil || session.closed.Load() || firstMessageID == 0 {
		return nil
	}
	return recoverPending(session.state, session.pending, now, func(request *PendingRequest) bool {
		rootMessageID := request.wireMessageID
		if request.containerID != 0 {
			rootMessageID = request.containerID
		}
		return rootMessageID < firstMessageID
	})
}

func (session *Session) ResetAndRecover(sessionID [8]byte, now time.Time) []tl.MTPMessage {
	if session == nil || session.closed.Load() || sessionID == [8]byte{} {
		return nil
	}
	session.state.Reset(sessionID)
	return recoverPending(session.state, session.pending, now, func(*PendingRequest) bool { return true })
}
