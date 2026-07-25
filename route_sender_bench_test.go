package raw

import (
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/tl"
)

func BenchmarkRouteSenderBatch32(b *testing.B) {
	sender := newRouteSender(nil, nil, nil, time.Now, 32, nil)
	var messages [32]tl.MTPMessage
	var acknowledgements [32]int64
	for index := range messages {
		messages[index] = tl.MTPMessage{
			MessageID: int64(index + 1),
			Seqno:     int32(index*2 + 1),
			Bytes:     20,
			Body:      &tl.MTPReqPQMulti{},
		}
		acknowledgements[index] = int64(index + 1)
	}

	b.ReportAllocs()
	for b.Loop() {
		for _, message := range messages {
			if err := sender.enqueueRequest(message); err != nil {
				b.Fatal(err)
			}
		}
		if err := sender.enqueueAcknowledgements(acknowledgements[:]); err != nil {
			b.Fatal(err)
		}
		requests, acks, forceContainer := sender.takeBatch()
		if len(requests) != len(messages) || len(acks) != len(acknowledgements) || forceContainer {
			b.Fatalf("requests=%d acknowledgements=%d force=%t", len(requests), len(acks), forceContainer)
		}
		sender.recycleBatch(requests, acks)
	}
}

func BenchmarkSessionRecovery100(b *testing.B) {
	now := time.Unix(1_700_000_000, 0)
	sessionState := mtproto.NewSession(testAuthKey(2), 0, [8]byte{1}, 100)
	for range 100 {
		if _, _, err := sessionState.Prepare(now, &tl.MTPReqPQMulti{}); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	for b.Loop() {
		messages := sessionState.ResetAndRecover([8]byte{2}, now)
		if len(messages) != 100 {
			b.Fatalf("recovered messages=%d", len(messages))
		}
	}
}
