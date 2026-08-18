package mtproto

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/cryptoutil"
	"github.com/mtgo-labs/raw/tl"
)

// BenchmarkHotPathReceiveDispatch measures the receive-loop cost of one
// inbound rpc_result before the waiter wakes: framing view dispatch,
// decrypt, envelope decode, control routing, and pending resolution.
// The response body is a realistic full Config encoding.
func BenchmarkHotPathReceiveDispatch(b *testing.B) {
	key := AuthKey{ID: 2}
	key.Key[0] = 2
	sessionID := [8]byte{2}
	now := time.Unix(1_700_000_000, 0)
	configBody, err := tl.Encode(&tl.Config{})
	if err != nil {
		b.Fatal(err)
	}
	rpcBody := make([]byte, 12+len(configBody))
	binary.LittleEndian.PutUint32(rpcBody, tl.MTPRPCResultConstructorID)
	copy(rpcBody[12:], configBody)

	const batch = 1 << 10
	first := NewSession(key, 0, sessionID, batch+8)
	salt, id := first.state.inboundEnvelope(now)
	base := uint64(1_700_000_000)<<32 | 1
	payloads := make([][]byte, batch)
	for index := range payloads {
		body := append([]byte(nil), rpcBody...)
		binary.LittleEndian.PutUint64(body[4:], uint64(index+1))
		message, err := encryptMessageWithSalt(rand.Reader, key, salt, id, base+uint64(2*index), 1, body, cryptoutil.ServerToClient)
		if err != nil {
			b.Fatal(err)
		}
		payloads[index] = message.Payload
	}
	session := first
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; b.Loop(); index++ {
		if index%batch == 0 && index != 0 {
			session = NewSession(key, 0, sessionID, batch+8)
		}
		slot := index % batch
		if _, err := session.pending.AddMessage(uint64(slot+1), tl.MTPMessage{}, false); err != nil {
			b.Fatal(err)
		}
		if _, _, _, err := receiveSessionPayloadAt(payloads[slot], session.state, session.pending, key, now); err != nil {
			b.Fatal(err)
		}
		if _, ok := session.pending.Take(uint64(slot + 1)); !ok {
			b.Fatal("pending request not resolved")
		}
	}
}
