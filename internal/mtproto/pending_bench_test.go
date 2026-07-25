package mtproto

import (
	"testing"

	"github.com/mtgo-labs/raw/tl"
)

func BenchmarkPendingRegisterCancel(b *testing.B) {
	table := NewPendingTable(1)
	b.ReportAllocs()
	for index := range b.N {
		messageID := uint64(index + 1)
		if _, err := table.Add(messageID); err != nil {
			b.Fatal(err)
		}
		if !table.Cancel(messageID, ErrSessionClosed) {
			b.Fatal("cancel failed")
		}
		if _, ok := table.Take(messageID); !ok {
			b.Fatal("take failed")
		}
	}
}

func BenchmarkPendingTrackContainer5(b *testing.B) {
	table := NewPendingTable(5)
	messages := make([]tl.MTPMessage, 5)
	for index := range messages {
		messageID := uint64(index + 1)
		if _, err := table.Add(messageID); err != nil {
			b.Fatal(err)
		}
		messages[index].MessageID = int64(messageID)
	}
	b.ReportAllocs()
	for index := range b.N {
		table.markSent(uint64(index+100), messages)
	}
}
