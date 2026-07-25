package mtproto

import (
	"bytes"
	"testing"

	"github.com/mtgo-labs/raw/internal/cryptoutil"
)

func FuzzDecryptMessage(f *testing.F) {
	authKey, err := NewAuthKey(bytes.Repeat([]byte{0x42}, 256), [16]byte{}, [32]byte{}, 0, testNow())
	if err != nil {
		f.Fatal(err)
	}
	sessionID := [8]byte{1}
	valid, err := encryptMessage(&constantReader{value: 7}, authKey, sessionID, 4, 1, []byte{1, 2, 3, 4}, cryptoutil.ServerToClient)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid.Payload)
	f.Add([]byte{})
	f.Add(valid.Payload[:24])
	wrongKeyID := append([]byte(nil), valid.Payload...)
	wrongKeyID[0] ^= 1
	f.Add(wrongKeyID)
	wrongMessageKey := append([]byte(nil), valid.Payload...)
	wrongMessageKey[8] ^= 1
	f.Add(wrongMessageKey)

	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 4096 {
			t.Skip()
		}
		messageID, _, body, err := DecryptMessage(authKey, sessionID, payload)
		if err == nil && (messageID == 0 || len(body) == 0 || len(body)%4 != 0) {
			t.Fatalf("accepted message ID %d with body length %d", messageID, len(body))
		}
	})
}
