package mtproto

import (
	"bytes"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/cryptoutil"
)

func TestEncryptedMessageRoundTrip(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 256)
	authKey, err := NewAuthKey(secret, [16]byte{}, [32]byte{}, 0, testNow())
	if err != nil {
		t.Fatal(err)
	}
	var session [8]byte
	body := []byte{1, 2, 3, 4}
	message, err := EncryptMessage(&constantReader{value: 7}, authKey, session, 0x1122334455667788, 1, body)
	if err != nil {
		t.Fatal(err)
	}
	if message.AuthKeyID != authKey.ID || len(message.Payload) < 24+messageHeaderSize || len(message.Payload)%16 != 8 {
		t.Fatalf("unexpected encrypted message: %+v", message)
	}
	serverMessage, err := encryptMessage(&constantReader{value: 7}, authKey, session, 0x1122334455667788, 1, body, cryptoutil.ServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	messageID, sequenceNo, got, err := DecryptMessage(authKey, session, serverMessage.Payload)
	if err != nil || messageID != 0x1122334455667788 || sequenceNo != 1 || !bytes.Equal(got, body) {
		t.Fatalf("decrypted message = %x/%d/%x, error=%v", messageID, sequenceNo, got, err)
	}
	serverMessage.Payload[30] ^= 1
	if _, _, _, err := DecryptMessage(authKey, session, serverMessage.Payload); err == nil {
		t.Fatalf("tampered message error = %v", err)
	}
}

func testNow() time.Time { return time.Unix(1_700_000_000, 0) }
