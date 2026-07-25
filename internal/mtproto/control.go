package mtproto

import (
	"errors"

	"github.com/mtgo-labs/raw/tl"
)

var ErrInvalidControlMessage = errors.New("mtproto: invalid control message")

// ControlKind identifies a protocol control object without applying policy.
type ControlKind uint8

const (
	ControlAcknowledge ControlKind = iota + 1
	ControlBadMessage
	ControlBadSalt
	ControlResend
)

// ControlEvent is the minimal state needed by the session owner.
type ControlEvent struct {
	Kind            ControlKind
	SourceMessageID int64
	MessageIDs      []int64
	MessageID       int64
	SequenceNo      int32
	ErrorCode       int32
	NewSalt         int64
}

// ClassifyControlMessage validates and classifies a generated MTProto control
// object. It does not retry, resend, mutate salts, or touch pending state.
func ClassifyControlMessage(object tl.Object) (ControlEvent, error) {
	switch value := object.(type) {
	case *tl.MTPMessagesAck:
		if len(value.MessageIDs) == 0 {
			return ControlEvent{}, ErrInvalidControlMessage
		}
		return ControlEvent{Kind: ControlAcknowledge, MessageIDs: value.MessageIDs}, nil
	case *tl.MTPBadMessageNotification:
		if value.BadMessageID == 0 {
			return ControlEvent{}, ErrInvalidControlMessage
		}
		return ControlEvent{Kind: ControlBadMessage, MessageID: value.BadMessageID, SequenceNo: value.BadMessageSeqno, ErrorCode: value.ErrorCode}, nil
	case *tl.MTPBadServerSalt:
		if value.BadMessageID == 0 || value.ErrorCode != 48 || value.NewServerSalt == 0 {
			return ControlEvent{}, ErrInvalidControlMessage
		}
		return ControlEvent{Kind: ControlBadSalt, MessageID: value.BadMessageID, SequenceNo: value.BadMessageSeqno, ErrorCode: value.ErrorCode, NewSalt: value.NewServerSalt}, nil
	case *tl.MTPMessageResendReq:
		if len(value.MessageIDs) == 0 {
			return ControlEvent{}, ErrInvalidControlMessage
		}
		return ControlEvent{Kind: ControlResend, MessageIDs: value.MessageIDs}, nil
	default:
		return ControlEvent{}, ErrInvalidControlMessage
	}
}
