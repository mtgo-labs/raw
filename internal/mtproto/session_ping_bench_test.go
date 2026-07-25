package mtproto

import (
	"bytes"
	"testing"
)

func BenchmarkSendSessionPing(b *testing.B) {
	authKey, err := NewAuthKey(
		bytes.Repeat([]byte{0x42}, 256),
		[16]byte{},
		[32]byte{},
		0,
		testNow(),
	)
	if err != nil {
		b.Fatal(err)
	}
	state := NewSessionState(1, [8]byte{9}, 0)
	random := &constantReader{value: 7}
	var output bytes.Buffer
	output.Grow(1024)
	now := testNow()
	b.ReportAllocs()
	for range b.N {
		output.Reset()
		if _, err := SendSessionPing(&output, random, state, authKey, now, 9, 77); err != nil {
			b.Fatal(err)
		}
	}
}
