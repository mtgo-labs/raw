package mtproto

import (
	"testing"
	"time"

	"github.com/mtgo-labs/raw/tl"
)

func TestSessionStateFutureSalt(t *testing.T) {
	state := NewSessionState(1, [8]byte{}, 0)
	if err := state.ApplyFutureSalts(&tl.MTPFutureSalts{Salts: []tl.MTPFutureSalt{{ValidSince: 10, ValidUntil: 20, Salt: 8}}}); err != nil {
		t.Fatal(err)
	}
	if salt, ok := state.FutureSalt(15); !ok || salt != 8 {
		t.Fatalf("salt=%d ok=%v", salt, ok)
	}
}

func TestSessionStateSequence(t *testing.T) {
	state := NewSessionState(1, [8]byte{2}, 0)
	if got := state.NextSequence(false); got != 0 {
		t.Fatalf("first non-content sequence = %d", got)
	}
	if got := state.NextSequence(true); got != 1 {
		t.Fatalf("first content sequence = %d", got)
	}
	if got := state.NextSequence(false); got != 2 {
		t.Fatalf("second non-content sequence = %d", got)
	}
	if got := state.NextSequence(true); got != 3 {
		t.Fatalf("second content sequence = %d", got)
	}
}

func TestSessionStateBadSalt(t *testing.T) {
	state := NewSessionState(1, [8]byte{}, 0)
	if err := state.ApplyControl(ControlEvent{Kind: ControlBadSalt, NewSalt: 9}); err != nil || state.Salt() != 9 {
		t.Fatalf("salt = %d err=%v", state.Salt(), err)
	}
	if err := state.ApplyControl(ControlEvent{Kind: ControlResend, MessageIDs: []int64{1}}); err != ErrSessionControl {
		t.Fatalf("resend apply error = %v", err)
	}
}

func TestSessionStateMessageIDUsesOffsetAndStaysMonotonic(t *testing.T) {
	state := NewSessionState(9, [8]byte{2}, 7)
	now := time.Unix(100, 0)
	first, salt, sessionID, sequenceNo := state.NextMessage(now, true)
	if want := ClientMessageID(time.Unix(107, 0)); first != want {
		t.Fatalf("first message ID = %d, want %d", first, want)
	}
	if salt != 9 || sessionID != [8]byte{2} || sequenceNo != 1 {
		t.Fatalf("salt=%d session=%x sequence=%d", salt, sessionID, sequenceNo)
	}
	second, _, _, sequenceNo := state.NextMessage(now, true)
	third, _, _, _ := state.NextMessage(now.Add(-time.Second), false)
	if second != first+4 || third != second+4 || sequenceNo != 3 {
		t.Fatalf("message IDs=%d,%d,%d sequence=%d", first, second, third, sequenceNo)
	}
}
