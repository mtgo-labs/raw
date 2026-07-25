package mtproto

import (
	"bytes"
	"testing"

	"github.com/mtgo-labs/raw/internal/cryptoutil"
	"github.com/mtgo-labs/raw/internal/transport"
)

func TestEncryptedTransportRoundTrip(t *testing.T) {
	authKey, err := NewAuthKey(bytes.Repeat([]byte{0x42}, 256), [16]byte{}, [32]byte{}, 0, testNow())
	if err != nil {
		t.Fatal(err)
	}
	var session [8]byte
	var wire bytes.Buffer
	body := []byte{1, 2, 3, 4}
	if _, err := SendEncrypted(&wire, &constantReader{value: 7}, authKey, session, 0x100, 1, body); err != nil {
		t.Fatal(err)
	}
	// The client direction is intentionally not accepted by the server
	// decryptor; construct a server-direction packet for the receive path.
	serverMessage, err := encryptMessage(&constantReader{value: 7}, authKey, session, 0x200, 2, body, cryptoutil.ServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	wire.Reset()
	if err := transport.WriteIntermediate(&wire, serverMessage.Payload); err != nil {
		t.Fatal(err)
	}
	messageID, sequenceNo, got, err := ReceiveEncrypted(&wire, authKey, session, 4096)
	if err != nil || messageID != 0x200 || sequenceNo != 2 || !bytes.Equal(got, body) {
		t.Fatalf("message = %x/%d/%x, error=%v", messageID, sequenceNo, got, err)
	}
}
