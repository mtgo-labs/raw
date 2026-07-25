package mtproto

import (
	"errors"

	"github.com/mtgo-labs/raw/tl"
)

const maxControlMessageIDs = 1024

var ErrInvalidControlIDs = errors.New("mtproto: invalid control message IDs")

// BuildAcknowledgement creates a bounded msgs_ack control object.
func BuildAcknowledgement(messageIDs []int64) (*tl.MTPMessagesAck, error) {
	if !validControlIDs(messageIDs) {
		return nil, ErrInvalidControlIDs
	}
	return &tl.MTPMessagesAck{MessageIDs: append([]int64(nil), messageIDs...)}, nil
}

// BuildResendRequest creates a bounded msg_resend_req control object.
func BuildResendRequest(messageIDs []int64) (*tl.MTPMessageResendReq, error) {
	if !validControlIDs(messageIDs) {
		return nil, ErrInvalidControlIDs
	}
	return &tl.MTPMessageResendReq{MessageIDs: append([]int64(nil), messageIDs...)}, nil
}

func validControlIDs(messageIDs []int64) bool {
	if len(messageIDs) == 0 || len(messageIDs) > maxControlMessageIDs {
		return false
	}
	for _, messageID := range messageIDs {
		if messageID == 0 {
			return false
		}
	}
	return true
}
