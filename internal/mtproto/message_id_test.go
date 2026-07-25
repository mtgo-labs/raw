package mtproto

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/cryptoutil"
	"github.com/mtgo-labs/raw/tl"
)

func TestIncomingMessageIDsRejectParityTimeAndReplay(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	state := NewSessionState(0, [8]byte{}, 7)
	object := &tl.MTPReqPQMulti{}
	serverTime := now.Unix() + 7

	if err := state.validateIncomingMessageIDs(
		serverMessageID(serverTime, 0)&^1,
		object,
		now,
	); !errors.Is(err, ErrIncomingMessageIDParity) {
		t.Fatalf("even ID err=%v", err)
	}
	if err := state.validateIncomingMessageIDs(
		serverMessageID(serverTime-301, 0),
		object,
		now,
	); !errors.Is(err, ErrIncomingMessageIDTime) {
		t.Fatalf("old ID err=%v", err)
	}
	if err := state.validateIncomingMessageIDs(
		serverMessageID(serverTime+31, 0),
		object,
		now,
	); !errors.Is(err, ErrIncomingMessageIDTime) {
		t.Fatalf("future ID err=%v", err)
	}

	messageID := serverMessageID(serverTime, 1)
	if err := state.validateIncomingMessageIDs(messageID, object, now); err != nil {
		t.Fatal(err)
	}
	if err := state.validateIncomingMessageIDs(messageID, object, now); !errors.Is(err, ErrIncomingMessageIDReplay) {
		t.Fatalf("duplicate ID err=%v", err)
	}
}

func TestIncomingMessageIDsKeepGreatestBoundedWindow(t *testing.T) {
	const serverTime int64 = 1_700_000_000
	var ids incomingMessageIDs
	object := &tl.MTPReqPQMulti{}
	if err := ids.validateAndAdd(serverMessageID(serverTime, 1), object, serverTime); err != nil {
		t.Fatal(err)
	}
	if err := ids.validateAndAdd(serverMessageID(serverTime, 0), object, serverTime); !errors.Is(err, ErrIncomingMessageIDReplay) {
		t.Fatalf("early stale ID err=%v", err)
	}
	for index := 1; index <= maxRecentIncomingMessageIDs; index++ {
		if index == 1 {
			continue
		}
		if err := ids.validateAndAdd(serverMessageID(serverTime, index), object, serverTime); err != nil {
			t.Fatalf("add %d: %v", index, err)
		}
	}
	if ids.recentLen != maxRecentIncomingMessageIDs {
		t.Fatalf("window length=%d", ids.recentLen)
	}
	if err := ids.validateAndAdd(serverMessageID(serverTime, 0), object, serverTime); !errors.Is(err, ErrIncomingMessageIDReplay) {
		t.Fatalf("stale ID err=%v", err)
	}
	first := serverMessageID(serverTime, 1)
	if err := ids.validateAndAdd(
		serverMessageID(serverTime, maxRecentIncomingMessageIDs+1),
		object,
		serverTime,
	); err != nil {
		t.Fatal(err)
	}
	if _, found := ids.search(first); found {
		t.Fatal("lowest ID was not evicted")
	}
	for index := 1; index < ids.recentLen; index++ {
		if ids.at(index-1) >= ids.at(index) {
			t.Fatalf("window is not sorted at %d", index)
		}
	}
}

func TestIncomingMessageIDsKeepCircularWindowSorted(t *testing.T) {
	var ids incomingMessageIDs
	for value := uint64(2); value <= 2000; value += 2 {
		if !ids.add(value) {
			t.Fatalf("add %d failed", value)
		}
	}
	for _, value := range []uint64{1501, 3001, 1751} {
		if !ids.add(value) {
			t.Fatalf("out-of-order add %d failed", value)
		}
	}
	if ids.recentLen != maxRecentIncomingMessageIDs {
		t.Fatalf("window length=%d", ids.recentLen)
	}
	for index := 1; index < ids.recentLen; index++ {
		if ids.at(index-1) >= ids.at(index) {
			t.Fatalf("window is not sorted at %d: %d >= %d", index, ids.at(index-1), ids.at(index))
		}
	}
	for _, value := range []uint64{1501, 1751, 3001} {
		if _, found := ids.search(value); !found {
			t.Fatalf("inserted value %d is missing", value)
		}
	}
}

func TestIncomingMessageIDsValidateContainerAtomically(t *testing.T) {
	const serverTime int64 = 1_700_000_000
	var ids incomingMessageIDs
	firstID := serverMessageID(serverTime, 1)
	secondID := serverMessageID(serverTime, 2)
	outerID := serverMessageID(serverTime, 3)
	container := &tl.MTPMessageContainer{Messages: []tl.MTPMessage{
		{MessageID: int64(firstID), Body: &tl.MTPReqPQMulti{}},
		{MessageID: int64(secondID), Body: &tl.MTPPong{}},
	}}
	if err := ids.validateAndAdd(outerID, container, serverTime); err != nil {
		t.Fatal(err)
	}
	if ids.recentLen != 3 {
		t.Fatalf("window length=%d", ids.recentLen)
	}

	replayed := &tl.MTPMessageContainer{Messages: []tl.MTPMessage{
		{MessageID: int64(firstID), Body: &tl.MTPReqPQMulti{}},
	}}
	if err := ids.validateAndAdd(
		serverMessageID(serverTime, 4),
		replayed,
		serverTime,
	); !errors.Is(err, ErrIncomingMessageIDReplay) {
		t.Fatalf("replayed child err=%v", err)
	}
	if ids.recentLen != 3 {
		t.Fatalf("failed container mutated window length=%d", ids.recentLen)
	}

	outOfOrder := &tl.MTPMessageContainer{Messages: []tl.MTPMessage{
		{MessageID: int64(serverMessageID(serverTime, 6)), Body: &tl.MTPReqPQMulti{}},
	}}
	if err := ids.validateAndAdd(
		serverMessageID(serverTime, 5),
		outOfOrder,
		serverTime,
	); !errors.Is(err, ErrIncomingMessageIDOrder) {
		t.Fatalf("container order err=%v", err)
	}
}

func TestIncomingMessageIDsAllowTimeCorrectionControls(t *testing.T) {
	const serverTime int64 = 1_700_000_000
	var ids incomingMessageIDs
	oldTime := serverTime - 301

	if err := ids.validateAndAdd(serverMessageID(oldTime, 1), &tl.MTPBadMessageNotification{
		BadMessageID: 1, ErrorCode: 16,
	}, serverTime); err != nil {
		t.Fatalf("bad-message time correction: %v", err)
	}
	if err := ids.validateAndAdd(serverMessageID(oldTime, 2), &tl.MTPBadServerSalt{
		BadMessageID: 2, ErrorCode: 48, NewServerSalt: 3,
	}, serverTime); err != nil {
		t.Fatalf("bad-server-salt correction: %v", err)
	}
}

func TestReceiveSessionPayloadRejectsReplayedMessageID(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	authKey, err := NewAuthKey(
		bytes.Repeat([]byte{0x42}, 256),
		[16]byte{},
		[32]byte{},
		now.Unix(),
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	state := NewSessionState(1, [8]byte{4}, 0)
	pending := NewPendingTable(1)
	body, err := tl.Encode(&tl.MTPReqPQMulti{})
	if err != nil {
		t.Fatal(err)
	}
	message, err := encryptMessageWithSalt(
		&constantReader{value: 7},
		authKey,
		1,
		[8]byte{4},
		serverMessageID(now.Unix(), 1),
		2,
		body,
		cryptoutil.ServerToClient,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, _, err := receiveSessionPayloadAt(message.Payload, state, pending, authKey, now); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := receiveSessionPayloadAt(
		message.Payload,
		state,
		pending,
		authKey,
		now,
	); !errors.Is(err, ErrIncomingMessageIDReplay) {
		t.Fatalf("replay err=%v", err)
	}
}

func BenchmarkValidateIncomingMessageID(b *testing.B) {
	now := time.Unix(1_700_000_000, 0)
	state := NewSessionState(0, [8]byte{}, 0)
	object := &tl.MTPReqPQMulti{}
	for index := 1; index <= maxRecentIncomingMessageIDs; index++ {
		if err := state.validateIncomingMessageIDs(
			serverMessageID(now.Unix(), index),
			object,
			now,
		); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for index := range b.N {
		if err := state.validateIncomingMessageIDs(
			serverMessageID(now.Unix(), maxRecentIncomingMessageIDs+index+1),
			object,
			now,
		); err != nil {
			b.Fatal(err)
		}
	}
}

func serverMessageID(serverTime int64, sequence int) uint64 {
	return uint64(serverTime)<<32 | uint64(sequence)<<2 | 1
}
