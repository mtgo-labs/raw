package mtproto

import (
	"bytes"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/cryptoutil"
	"github.com/mtgo-labs/raw/tl"
)

func BenchmarkEncryptMessage(b *testing.B) {
	authKey, err := NewAuthKey(bytes.Repeat([]byte{0x42}, 256), [16]byte{}, [32]byte{}, 0, testNow())
	if err != nil {
		b.Fatal(err)
	}
	body := make([]byte, 256)
	var session [8]byte
	random := &constantReader{value: 7}
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		if _, err := EncryptMessage(random, authKey, session, uint64(index+1), 1, body); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSendSessionObject(b *testing.B) {
	authKey, err := NewAuthKey(bytes.Repeat([]byte{0x42}, 256), [16]byte{}, [32]byte{}, 0, testNow())
	if err != nil {
		b.Fatal(err)
	}
	state := NewSessionState(1, [8]byte{9}, 0)
	pending := NewPendingTable(b.N + 1)
	random := &constantReader{value: 7}
	var output bytes.Buffer
	output.Grow(1024)
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		output.Reset()
		if _, err := SendSessionObject(&output, random, state, pending, authKey, time.Unix(1_700_000_000+int64(index), 0), &tl.MTPReqPQMulti{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptMessageWithSalt(b *testing.B) {
	authKey, err := NewAuthKey(bytes.Repeat([]byte{0x42}, 256), [16]byte{}, [32]byte{}, 0, testNow())
	if err != nil {
		b.Fatal(err)
	}
	body, err := tl.Encode(&tl.MTPRPCResult{ReqMessageID: 13, Result: &tl.MTPReqPQMulti{}})
	if err != nil {
		b.Fatal(err)
	}
	message, err := encryptMessageWithSalt(
		&constantReader{value: 7},
		authKey,
		3,
		[8]byte{4},
		serverMessageID(testNow().Unix(), 1),
		2,
		body,
		cryptoutil.ServerToClient,
	)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for range b.N {
		_, _, body, err := decryptMessageWithSalt(authKey, 3, [8]byte{4}, message.Payload, cryptoutil.ServerToClient)
		if err != nil || len(body) == 0 {
			b.Fatal(err)
		}
	}
}
