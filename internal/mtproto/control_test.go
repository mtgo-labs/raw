package mtproto

import (
	"errors"
	"testing"

	"github.com/mtgo-labs/raw/tl"
)

func TestClassifyControlMessage(t *testing.T) {
	tests := []struct {
		name string
		obj  tl.Object
		kind ControlKind
	}{
		{name: "ack", obj: &tl.MTPMessagesAck{MessageIDs: []int64{1, 2}}, kind: ControlAcknowledge},
		{name: "bad message", obj: &tl.MTPBadMessageNotification{BadMessageID: 3, BadMessageSeqno: 4, ErrorCode: 16}, kind: ControlBadMessage},
		{name: "bad salt", obj: &tl.MTPBadServerSalt{BadMessageID: 5, BadMessageSeqno: 6, ErrorCode: 48, NewServerSalt: 7}, kind: ControlBadSalt},
		{name: "resend", obj: &tl.MTPMessageResendReq{MessageIDs: []int64{8}}, kind: ControlResend},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event, err := ClassifyControlMessage(test.obj)
			if err != nil || event.Kind != test.kind {
				t.Fatalf("event=%+v err=%v", event, err)
			}
		})
	}
}

func TestClassifyControlMessageRejectsMalformed(t *testing.T) {
	for _, object := range []tl.Object{
		nil,
		&tl.MTPMessagesAck{},
		&tl.MTPBadMessageNotification{},
		&tl.MTPBadServerSalt{BadMessageID: 1, ErrorCode: 47, NewServerSalt: 2},
		&tl.MTPBadServerSalt{BadMessageID: 1, ErrorCode: 48},
		&tl.MTPMessageResendReq{},
	} {
		if _, err := ClassifyControlMessage(object); !errors.Is(err, ErrInvalidControlMessage) {
			t.Fatalf("object %T error = %v", object, err)
		}
	}
}
