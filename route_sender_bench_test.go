package raw

import (
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/tl"
)

func BenchmarkRouteSenderAckBatch32(b *testing.B) {
	sender := newRouteSender(nil, nil, nil, time.Now, 32, nil)
	var acknowledgements [32]int64
	for index := range acknowledgements {
		acknowledgements[index] = int64(index + 1)
	}

	b.ReportAllocs()
	for b.Loop() {
		if err := sender.enqueueAcknowledgements(acknowledgements[:]); err != nil {
			b.Fatal(err)
		}
		acks := sender.takeAcks()
		if len(acks) != len(acknowledgements) {
			b.Fatalf("acknowledgements=%d", len(acks))
		}
		sender.recycleAcks(acks)
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
