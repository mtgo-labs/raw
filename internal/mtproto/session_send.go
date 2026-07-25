package mtproto

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/mtgo-labs/raw/tl"
)

const (
	MaxAcknowledgementIDs = 8192
	MaxContainerMessages  = 1020
	MaxContainerPayload   = 1 << 15
)

var ErrSessionSend = errors.New("mtproto: encrypted session send failed")

// PrepareSessionObject assigns wire state and reserves pending correlation
// before a request enters the bounded route send queue.
func PrepareSessionObject(state *SessionState, pending *PendingTable, now time.Time, object tl.Object) (tl.MTPMessage, *PendingRequest, error) {
	if state == nil || pending == nil || object == nil {
		return tl.MTPMessage{}, nil, ErrSessionSend
	}
	size, err := tl.EncodedSize(object)
	if err != nil || size <= 0 || size%4 != 0 || size > int(^uint32(0)>>1) {
		return tl.MTPMessage{}, nil, fmt.Errorf("%w: invalid body size", ErrSessionSend)
	}
	messageID, _, _, sequenceNo := state.NextMessage(now, true)
	message := tl.MTPMessage{
		MessageID: int64(messageID),
		Seqno:     int32(sequenceNo),
		Bytes:     int32(size),
		Body:      object,
	}
	request, err := pending.AddMessage(messageID, message)
	if err != nil {
		return tl.MTPMessage{}, nil, err
	}
	return message, request, nil
}

// SendPreparedSessionObjects sends prepared requests and optional
// acknowledgements as one direct message or one protocol container. The
// container ID is allocated after every child and is therefore greater than
// every contained ID.
func SendPreparedSessionObjects(
	writer io.Writer,
	random io.Reader,
	state *SessionState,
	pending *PendingTable,
	authKey AuthKey,
	now time.Time,
	messages []tl.MTPMessage,
	acknowledgementIDs []int64,
	forceContainer bool,
) (uint64, error) {
	if state == nil || pending == nil || len(acknowledgementIDs) > MaxAcknowledgementIDs {
		cancelPreparedMessages(pending, messages, ErrSessionSend)
		return 0, ErrSessionSend
	}
	active := messages[:0]
	for _, message := range messages {
		if !pending.Contains(uint64(message.MessageID)) {
			continue
		}
		size, err := tl.EncodedSize(message.Body)
		if err != nil || message.MessageID == 0 || message.Seqno&1 == 0 ||
			size != int(message.Bytes) {
			cancelPreparedMessages(pending, messages, ErrSessionSend)
			return 0, ErrSessionSend
		}
		active = append(active, message)
	}
	for _, messageID := range acknowledgementIDs {
		if messageID == 0 {
			cancelPreparedMessages(pending, active, ErrSessionSend)
			return 0, ErrSessionSend
		}
	}
	messageCount := len(active)
	if len(acknowledgementIDs) != 0 {
		messageCount++
	}
	if messageCount == 0 {
		return 0, nil
	}
	if messageCount > MaxContainerMessages {
		cancelPreparedMessages(pending, active, ErrSessionSend)
		return 0, ErrSessionSend
	}

	if messageCount == 1 && len(acknowledgementIDs) == 0 && !forceContainer {
		message := active[0]
		salt, sessionID := state.inboundEnvelope(now)
		pending.markSent(uint64(message.MessageID), active)
		if _, err := SendEncryptedObjectWithSalt(
			writer,
			random,
			authKey,
			salt,
			sessionID,
			uint64(message.MessageID),
			uint32(message.Seqno),
			message.Body,
		); err != nil {
			cancelPreparedMessages(pending, active, fmt.Errorf("%w: %w", ErrSessionSend, err))
			return 0, err
		}
		return uint64(message.MessageID), nil
	}

	containerMessages := make([]tl.MTPMessage, 0, messageCount)
	containerMessages = append(containerMessages, active...)
	if len(acknowledgementIDs) != 0 {
		acknowledgement := &tl.MTPMessagesAck{MessageIDs: acknowledgementIDs}
		size, err := tl.EncodedSize(acknowledgement)
		if err != nil {
			cancelPreparedMessages(pending, active, ErrSessionSend)
			return 0, err
		}
		messageID, _, _, sequenceNo := state.NextMessage(now, false)
		containerMessages = append(containerMessages, tl.MTPMessage{
			MessageID: int64(messageID),
			Seqno:     int32(sequenceNo),
			Bytes:     int32(size),
			Body:      acknowledgement,
		})
	}
	if len(containerMessages) == 1 && !forceContainer {
		message := containerMessages[0]
		salt, sessionID := state.inboundEnvelope(now)
		if _, err := SendEncryptedObjectWithSalt(
			writer,
			random,
			authKey,
			salt,
			sessionID,
			uint64(message.MessageID),
			uint32(message.Seqno),
			message.Body,
		); err != nil {
			return 0, err
		}
		return uint64(message.MessageID), nil
	}

	messageID, salt, sessionID, sequenceNo := state.NextMessage(now, false)
	container := &tl.MTPMessageContainer{Messages: containerMessages}
	pending.markSent(messageID, active)
	if _, err := SendEncryptedObjectWithSalt(
		writer,
		random,
		authKey,
		salt,
		sessionID,
		messageID,
		sequenceNo,
		container,
	); err != nil {
		cancelPreparedMessages(pending, active, fmt.Errorf("%w: %w", ErrSessionSend, err))
		return 0, err
	}
	return messageID, nil
}

// SendSessionObject reserves pending state before writing one encrypted
// content-related object. A failed write completes and removes that request.
func SendSessionObject(writer io.Writer, random io.Reader, state *SessionState, pending *PendingTable, authKey AuthKey, now time.Time, object tl.Object) (uint64, error) {
	message, _, err := PrepareSessionObject(state, pending, now, object)
	if err != nil {
		return 0, err
	}
	messages := [...]tl.MTPMessage{message}
	return SendPreparedSessionObjects(writer, random, state, pending, authKey, now, messages[:], nil, false)
}

func cancelPreparedMessages(pending *PendingTable, messages []tl.MTPMessage, err error) {
	for _, message := range messages {
		pending.Cancel(uint64(message.MessageID), err)
	}
}
