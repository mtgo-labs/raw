package mtproto

import (
	"errors"
	"testing"
)

func TestBuildControlObjects(t *testing.T) {
	ack, err := BuildAcknowledgement([]int64{1, 2})
	if err != nil || len(ack.MessageIDs) != 2 {
		t.Fatalf("ack=%+v err=%v", ack, err)
	}
	resend, err := BuildResendRequest([]int64{3})
	if err != nil || len(resend.MessageIDs) != 1 {
		t.Fatalf("resend=%+v err=%v", resend, err)
	}
	input := []int64{4}
	ack, _ = BuildAcknowledgement(input)
	input[0] = 9
	if ack.MessageIDs[0] != 4 {
		t.Fatal("control object aliases caller IDs")
	}
}

func TestBuildControlObjectsRejectInvalid(t *testing.T) {
	for _, ids := range [][]int64{nil, {0}, make([]int64, maxControlMessageIDs+1)} {
		if _, err := BuildAcknowledgement(ids); !errors.Is(err, ErrInvalidControlIDs) {
			t.Fatalf("ids length %d error = %v", len(ids), err)
		}
	}
}
