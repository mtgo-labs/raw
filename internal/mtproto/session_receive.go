package mtproto

import (
	"io"
	"time"

	"github.com/mtgo-labs/raw/internal/transport"
	"github.com/mtgo-labs/raw/tl"
)

// InboundResult reports protocol work completed by one decrypted message.
type InboundResult struct {
	Resolved       int
	Controls       []ControlEvent
	AcknowledgeIDs []int64
	Pings          []InboundPing
	Pongs          []InboundPong
	Object         tl.Object
	Updates        []tl.UpdatesClass
	RetryMessages  []tl.MTPMessage
	ResendIDs      []int64
	ResetSession   bool
}

type InboundPing struct {
	MessageID uint64
	PingID    int64
}

type InboundPong struct {
	MessageID uint64
	PingID    int64
}

// ReceiveSessionObject decrypts, decodes, and routes one inbound object into
// session state and pending requests.
func ReceiveSessionObject(reader io.Reader, state *SessionState, pending *PendingTable, authKey AuthKey, maxPayload int) (InboundResult, uint64, uint32, error) {
	if state == nil || pending == nil {
		return InboundResult{}, 0, 0, ErrSessionControl
	}
	payload, err := transport.ReadPacket(reader, maxPayload)
	if err != nil {
		return InboundResult{}, 0, 0, err
	}
	return receiveSessionPayloadAt(payload, state, pending, authKey, time.Now())
}

// ReceiveSessionPayload decrypts one already-framed packet. Session uses this
// after reading so a concurrently rotated PFS key is selected for the packet
// that follows the rotation.
func ReceiveSessionPayload(payload []byte, state *SessionState, pending *PendingTable, authKey AuthKey) (InboundResult, uint64, uint32, error) {
	return receiveSessionPayloadAt(payload, state, pending, authKey, time.Now())
}

func receiveSessionPayloadAt(payload []byte, state *SessionState, pending *PendingTable, authKey AuthKey, now time.Time) (InboundResult, uint64, uint32, error) {
	if state == nil || pending == nil {
		return InboundResult{}, 0, 0, ErrSessionControl
	}
	if transportError, ok := ParseTransportError(payload); ok {
		return InboundResult{}, 0, 0, transportError
	}
	salt, sessionID := state.inboundEnvelope(now)
	var (
		messageID    uint64
		sequenceNo   uint32
		body         []byte
		envelopeSalt int64
		err          error
	)
	if salt == 0 {
		messageID, sequenceNo, body, envelopeSalt, err = decryptMessageWithoutExpectedSalt(authKey, sessionID, payload)
	} else {
		messageID, sequenceNo, body, err = DecryptMessageWithSalt(authKey, salt, sessionID, payload)
	}
	if err != nil {
		return InboundResult{}, messageID, sequenceNo, err
	}
	object, err := tl.Decode(body, tl.DefaultDecodeLimits())
	if err != nil {
		return InboundResult{}, messageID, sequenceNo, err
	}
	if salt == 0 && envelopeSalt != 0 && !confirmsBootstrapSalt(object, envelopeSalt) {
		return InboundResult{}, messageID, sequenceNo, ErrEncryptedMessage
	}
	if err := state.validateIncomingMessageIDs(messageID, object, now); err != nil {
		return InboundResult{}, messageID, sequenceNo, err
	}
	result, err := routeInboundObjectAt(state, pending, object, messageID, now)
	if err == nil && requiresAcknowledgement(object) {
		result.AcknowledgeIDs = append(result.AcknowledgeIDs, int64(messageID))
	}
	return result, messageID, sequenceNo, err
}

func confirmsBootstrapSalt(object tl.Object, envelopeSalt int64) bool {
	switch value := object.(type) {
	case *tl.MTPBadServerSalt:
		return value.NewServerSalt == envelopeSalt
	case *tl.MTPMessageContainer:
		for _, message := range value.Messages {
			badSalt, ok := message.Body.(*tl.MTPBadServerSalt)
			if ok && badSalt.NewServerSalt == envelopeSalt {
				return true
			}
		}
	}
	return false
}

// RouteInboundObject routes one already-decoded object. Containers are
// traversed once; arbitrary nested application objects are never recursively
// dispatched.
func RouteInboundObject(state *SessionState, pending *PendingTable, object tl.Object) (InboundResult, error) {
	return routeInboundObjectAt(state, pending, object, 0, time.Now())
}

func routeInboundObject(state *SessionState, pending *PendingTable, object tl.Object, messageID uint64) (InboundResult, error) {
	return routeInboundObjectAt(state, pending, object, messageID, time.Now())
}

func routeInboundObjectAt(
	state *SessionState,
	pending *PendingTable,
	object tl.Object,
	messageID uint64,
	now time.Time,
) (InboundResult, error) {
	if state == nil || pending == nil || object == nil {
		return InboundResult{}, ErrSessionControl
	}
	if container, ok := object.(*tl.MTPMessageContainer); ok {
		result := InboundResult{}
		for _, message := range container.Messages {
			entry := message
			if entry.Body == nil {
				return result, ErrPendingContainer
			}
			child, err := routeInboundObjectAt(state, pending, entry.Body, uint64(entry.MessageID), now)
			if err != nil {
				return result, err
			}
			result.Resolved += child.Resolved
			result.Controls = append(result.Controls, child.Controls...)
			result.AcknowledgeIDs = append(result.AcknowledgeIDs, child.AcknowledgeIDs...)
			if requiresAcknowledgement(entry.Body) {
				result.AcknowledgeIDs = append(result.AcknowledgeIDs, entry.MessageID)
			}
			result.Pings = append(result.Pings, child.Pings...)
			result.Pongs = append(result.Pongs, child.Pongs...)
			result.Updates = append(result.Updates, child.Updates...)
			result.RetryMessages = append(result.RetryMessages, child.RetryMessages...)
			result.ResendIDs = append(result.ResendIDs, child.ResendIDs...)
			result.ResetSession = result.ResetSession || child.ResetSession
			if child.Object != nil {
				result.Object = child.Object
			}
		}
		return result, nil
	}
	if values, ok := object.(*tl.MTPFutureSalts); ok {
		if err := state.applyFutureSaltsResponse(values); err != nil {
			return InboundResult{}, err
		}
		return InboundResult{Resolved: 1, Object: object}, nil
	}
	switch value := object.(type) {
	case *tl.MTPPing:
		return InboundResult{
			Pings:  []InboundPing{{MessageID: messageID, PingID: value.PingID}},
			Object: object,
		}, nil
	case *tl.MTPPingDelayDisconnect:
		return InboundResult{
			Pings:  []InboundPing{{MessageID: messageID, PingID: value.PingID}},
			Object: object,
		}, nil
	case *tl.MTPPong:
		return InboundResult{
			Pongs:  []InboundPong{{MessageID: uint64(value.MessageID), PingID: value.PingID}},
			Object: object,
		}, nil
	case *tl.MTPNewSessionCreated:
		applied, previous, err := state.ApplyNewSession(
			uint64(value.FirstMessageID),
			uint64(value.UniqueID),
			value.ServerSalt,
		)
		if err != nil {
			return InboundResult{}, err
		}
		result := InboundResult{Object: object}
		if previous {
			result.Updates = []tl.UpdatesClass{&tl.UpdatesTooLong{}}
		}
		if applied {
			result.RetryMessages = recoverPending(state, pending, now, func(request *PendingRequest) bool {
				rootMessageID := request.wireMessageID
				if request.containerID != 0 {
					rootMessageID = request.containerID
				}
				return rootMessageID < uint64(value.FirstMessageID)
			})
		}
		return result, nil
	case *tl.MTPMessagesAllInfo:
		if len(value.MessageIDs) != len(value.Info) {
			return InboundResult{}, ErrSessionRecovery
		}
		result := InboundResult{Object: object}
		for index, messageID := range value.MessageIDs {
			info := recoverFromMessageInfo(
				state,
				pending,
				uint64(messageID),
				int32(value.Info[index]),
				0,
				now,
			)
			result.RetryMessages = append(result.RetryMessages, info.RetryMessages...)
		}
		return result, nil
	case *tl.MTPMessageDetailedInfo:
		result := recoverFromMessageInfo(
			state,
			pending,
			uint64(value.MessageID),
			value.Status,
			uint64(value.AnswerMessageID),
			now,
		)
		result.Object = object
		return result, nil
	case *tl.MTPMessageNewDetailedInfo:
		result := recoverFromMessageInfo(
			state,
			pending,
			0,
			value.Status,
			uint64(value.AnswerMessageID),
			now,
		)
		result.Object = object
		return result, nil
	case *tl.MTPMessagesStateInfo:
		return InboundResult{Object: object}, nil
	}
	if event, err := ClassifyControlMessage(object); err == nil {
		event.SourceMessageID = int64(messageID)
		result := InboundResult{Controls: []ControlEvent{event}}
		switch event.Kind {
		case ControlAcknowledge:
			pending.acknowledge(event.MessageIDs)
		case ControlBadSalt:
			if err := state.ApplyControl(event); err != nil {
				return InboundResult{}, err
			}
			result.RetryMessages = recoverPending(state, pending, now, func(request *PendingRequest) bool {
				return request.wireMessageID == uint64(event.MessageID) ||
					request.containerID == uint64(event.MessageID)
			})
		case ControlBadMessage:
			switch event.ErrorCode {
			case 16:
				if err := state.CorrectTime(now, messageID, false); err != nil {
					return InboundResult{}, err
				}
				result.RetryMessages = recoverPending(state, pending, now, func(request *PendingRequest) bool {
					return request.wireMessageID == uint64(event.MessageID) ||
						request.containerID == uint64(event.MessageID)
				})
			case 17:
				if err := state.CorrectTime(now, messageID, true); err != nil {
					return InboundResult{}, err
				}
				result.ResetSession = true
			case 20:
				result.RetryMessages = recoverPending(state, pending, now, func(request *PendingRequest) bool {
					return request.wireMessageID == uint64(event.MessageID) ||
						request.containerID == uint64(event.MessageID)
				})
			default:
				result.ResetSession = true
			}
		case ControlResend:
			// Pinned mtcute and TDLib do not resend client-received messages.
		}
		return result, nil
	}
	resolved, err := pending.ResolveMessage(object)
	if err != nil {
		return InboundResult{}, err
	}
	result := InboundResult{Resolved: resolved, Object: object}
	if update, ok := object.(tl.UpdatesClass); ok {
		result.Updates = []tl.UpdatesClass{update}
	}
	return result, nil
}

func recoverFromMessageInfo(
	state *SessionState,
	pending *PendingTable,
	messageID uint64,
	status int32,
	answerMessageID uint64,
	now time.Time,
) InboundResult {
	if messageID != 0 {
		if !pending.containsRelated(messageID) {
			return InboundResult{}
		}
		retry := func() InboundResult {
			return InboundResult{RetryMessages: recoverPending(state, pending, now, func(request *PendingRequest) bool {
				return request.wireMessageID == messageID || request.containerID == messageID
			})}
		}
		switch status & 7 {
		case 1, 2, 3:
			return retry()
		case 0:
			if answerMessageID != 0 {
				return retry()
			}
		case 4:
			pending.acknowledge([]int64{int64(messageID)})
		}
		if answerMessageID == 0 && status&64 != 0 {
			return retry()
		}
	}
	if answerMessageID != 0 && !state.hasIncomingMessage(answerMessageID) {
		return InboundResult{ResendIDs: []int64{int64(answerMessageID)}}
	}
	return InboundResult{}
}

func requiresAcknowledgement(object tl.Object) bool {
	switch object.(type) {
	case *tl.MTPMessageContainer,
		*tl.MTPMessagesAck,
		*tl.MTPBadMessageNotification,
		*tl.MTPBadServerSalt,
		*tl.MTPMessagesAllInfo,
		*tl.MTPMessagesStateInfo,
		*tl.MTPMessageDetailedInfo,
		*tl.MTPMessageNewDetailedInfo,
		*tl.MTPHTTPWait:
		return false
	default:
		return true
	}
}
