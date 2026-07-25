package mtproto

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/tl"
)

func TestBadServerSaltReassignsPendingRequest(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	session := NewSession(recoveryTestAuthKey(t), 1, [8]byte{1}, 2)
	message, request, err := session.Prepare(now, &tl.MTPReqPQMulti{Nonce: [16]byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	session.pending.markSent(uint64(message.MessageID), []tl.MTPMessage{message})
	result, err := routeInboundObjectAt(
		session.state,
		session.pending,
		&tl.MTPBadServerSalt{BadMessageID: message.MessageID, ErrorCode: 48, NewServerSalt: 9},
		serverMessageID(now.Unix(), 1),
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if session.Salt() != 9 || len(result.RetryMessages) != 1 {
		t.Fatalf("salt=%d retries=%+v", session.Salt(), result.RetryMessages)
	}
	retry := result.RetryMessages[0]
	if retry.MessageID == message.MessageID || retry.Seqno&1 == 0 || session.Pending() != 1 {
		t.Fatalf("original=%+v retry=%+v pending=%d", message, retry, session.Pending())
	}
	if resolved, err := session.pending.ResolveRPCResult(&tl.MTPRPCResult{
		ReqMessageID: retry.MessageID,
		Result:       &tl.MTPReqPQMulti{},
	}); err != nil || !resolved {
		t.Fatalf("resolve=%t err=%v", resolved, err)
	}
	completed, err := session.WaitPrepared(context.Background(), request)
	if err != nil || completed != request {
		t.Fatalf("completed=%+v err=%v", completed, err)
	}
}

func TestBadMessageCorrectsTimeAndRetries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	session := NewSession(recoveryTestAuthKey(t), 1, [8]byte{1}, 1)
	message, _, err := session.Prepare(now, &tl.MTPReqPQMulti{})
	if err != nil {
		t.Fatal(err)
	}
	serverTime := now.Unix() + 20
	result, err := routeInboundObjectAt(
		session.state,
		session.pending,
		&tl.MTPBadMessageNotification{BadMessageID: message.MessageID, ErrorCode: 16},
		serverMessageID(serverTime, 1),
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.RetryMessages) != 1 || uint64(result.RetryMessages[0].MessageID)>>32 != uint64(serverTime) {
		t.Fatalf("retries=%+v server time=%d", result.RetryMessages, serverTime)
	}
}

func TestBadMessageHighResetsAndRecoversSession(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	session := NewSession(recoveryTestAuthKey(t), 1, [8]byte{1}, 1)
	original, request, err := session.Prepare(now, &tl.MTPReqPQMulti{})
	if err != nil {
		t.Fatal(err)
	}
	serverTime := now.Unix() - 20
	result, err := routeInboundObjectAt(
		session.state,
		session.pending,
		&tl.MTPBadMessageNotification{BadMessageID: original.MessageID, ErrorCode: 17},
		serverMessageID(serverTime, 1),
		now,
	)
	if err != nil || !result.ResetSession || len(result.RetryMessages) != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	newSessionID := [8]byte{9}
	retries := session.ResetAndRecover(newSessionID, now)
	if len(retries) != 1 || retries[0].MessageID == original.MessageID || retries[0].Seqno != 1 {
		t.Fatalf("original=%+v retries=%+v", original, retries)
	}
	if session.SessionID() != newSessionID || request.wireMessageID != uint64(retries[0].MessageID) {
		t.Fatalf("session=%x request wire=%x", session.SessionID(), request.wireMessageID)
	}
}

func TestNewSessionCreatedRecoversForgottenContainer(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	session := NewSession(recoveryTestAuthKey(t), 1, [8]byte{1}, 2)
	first, _, err := session.Prepare(now, &tl.MTPReqPQMulti{Nonce: [16]byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := session.Prepare(now, &tl.MTPReqPQMulti{Nonce: [16]byte{2}})
	if err != nil {
		t.Fatal(err)
	}
	containerID, _, _, _ := session.state.NextMessage(now, false)
	session.pending.markSent(containerID, []tl.MTPMessage{first, second})
	created := &tl.MTPNewSessionCreated{
		FirstMessageID: int64(containerID + 4),
		UniqueID:       17,
		ServerSalt:     9,
	}
	result, err := routeInboundObjectAt(session.state, session.pending, created, serverMessageID(now.Unix(), 1), now)
	if err != nil || len(result.RetryMessages) != 2 || session.Salt() != 9 {
		t.Fatalf("result=%+v salt=%d err=%v", result, session.Salt(), err)
	}
	duplicate, err := routeInboundObjectAt(session.state, session.pending, created, serverMessageID(now.Unix(), 3), now)
	if err != nil || len(duplicate.RetryMessages) != 0 {
		t.Fatalf("duplicate=%+v err=%v", duplicate, err)
	}
}

func TestDetailedInfoRequestsMissingAnswer(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	session := NewSession(recoveryTestAuthKey(t), 1, [8]byte{1}, 1)
	message, request, err := session.Prepare(now, &tl.MTPReqPQMulti{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := routeInboundObjectAt(
		session.state,
		session.pending,
		&tl.MTPMessageDetailedInfo{MessageID: message.MessageID, AnswerMessageID: 19, Status: 4},
		serverMessageID(now.Unix(), 1),
		now,
	)
	if err != nil || len(result.ResendIDs) != 1 || result.ResendIDs[0] != 19 || !request.acknowledged {
		t.Fatalf("result=%+v request=%+v err=%v", result, request, err)
	}
}

func TestServiceMessagesDoNotQueueAcknowledgements(t *testing.T) {
	for _, object := range []tl.Object{
		&tl.MTPMessagesAck{MessageIDs: []int64{1}},
		&tl.MTPBadMessageNotification{BadMessageID: 1},
		&tl.MTPBadServerSalt{BadMessageID: 1, NewServerSalt: 1},
		&tl.MTPMessagesAllInfo{},
		&tl.MTPMessagesStateInfo{},
		&tl.MTPMessageDetailedInfo{},
		&tl.MTPMessageNewDetailedInfo{},
		&tl.MTPHTTPWait{},
	} {
		if requiresAcknowledgement(object) {
			t.Fatalf("%T unexpectedly requires acknowledgement", object)
		}
	}
	for _, object := range []tl.Object{&tl.MTPPong{}, &tl.MTPPing{}, &tl.MTPNewSessionCreated{}} {
		if !requiresAcknowledgement(object) {
			t.Fatalf("%T must be acknowledged", object)
		}
	}
}

func TestMessagesAllInfoRetriesMissingAndGeneratedResponses(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	session := NewSession(recoveryTestAuthKey(t), 1, [8]byte{1}, 2)
	first, _, err := session.Prepare(now, &tl.MTPReqPQMulti{Nonce: [16]byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := session.Prepare(now, &tl.MTPReqPQMulti{Nonce: [16]byte{2}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := routeInboundObjectAt(session.state, session.pending, &tl.MTPMessagesAllInfo{
		MessageIDs: []int64{first.MessageID, second.MessageID},
		Info:       []byte{1, 68},
	}, serverMessageID(now.Unix(), 1), now)
	if err != nil || len(result.RetryMessages) != 2 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestNewSessionCreatedSignalsMissedUpdates(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	session := NewSession(recoveryTestAuthKey(t), 1, [8]byte{1}, 1)
	first := &tl.MTPNewSessionCreated{FirstMessageID: 1, UniqueID: 1, ServerSalt: 2}
	if _, err := routeInboundObjectAt(session.state, session.pending, first, serverMessageID(now.Unix(), 1), now); err != nil {
		t.Fatal(err)
	}
	second := &tl.MTPNewSessionCreated{FirstMessageID: 1, UniqueID: 2, ServerSalt: 3}
	result, err := routeInboundObjectAt(session.state, session.pending, second, serverMessageID(now.Unix(), 3), now)
	if err != nil || len(result.Updates) != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if _, ok := result.Updates[0].(*tl.UpdatesTooLong); !ok {
		t.Fatalf("update=%T", result.Updates[0])
	}
}

func recoveryTestAuthKey(t *testing.T) AuthKey {
	t.Helper()
	authKey, err := NewAuthKey(bytes.Repeat([]byte{0x42}, 256), [16]byte{}, [32]byte{}, 0, testNow())
	if err != nil {
		t.Fatal(err)
	}
	return authKey
}
