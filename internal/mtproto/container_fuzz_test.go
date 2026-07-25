package mtproto

import (
	"testing"

	"github.com/mtgo-labs/raw/tl"
)

func FuzzRouteInboundContainer(f *testing.F) {
	inner := &tl.MTPMessageContainer{Messages: []tl.MTPMessage{
		{MessageID: 2, Seqno: 1, Bytes: 20, Body: &tl.MTPReqPQMulti{}},
	}}
	outer := &tl.MTPMessageContainer{Messages: []tl.MTPMessage{
		{MessageID: 1, Seqno: 1, Bytes: 44, Body: inner},
	}}
	valid, err := tl.Encode(outer)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add(valid[:4])

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 4096 {
			t.Skip()
		}
		object, err := tl.Decode(input, tl.DecodeLimits{
			MaxBytes:             4096,
			MaxVectorElements:    128,
			MaxDepth:             16,
			MaxAllocation:        16 << 10,
			MaxDecompressedBytes: 4096,
		})
		if err != nil {
			return
		}
		state := NewSessionState(1, [8]byte{}, 0)
		_, _ = RouteInboundObject(state, NewPendingTable(1), object)
	})
}
