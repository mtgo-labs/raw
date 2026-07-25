package mtproto

import (
	"fmt"
	"io"

	"github.com/mtgo-labs/raw/tl"
)

// SendEncryptedObject encodes and sends one client-to-server TL object.
func SendEncryptedObject(writer io.Writer, random io.Reader, authKey AuthKey, sessionID [8]byte, messageID uint64, sequenceNo uint32, object tl.Object) (EncryptedMessage, error) {
	return SendEncryptedObjectWithSalt(writer, random, authKey, 0, sessionID, messageID, sequenceNo, object)
}

func SendEncryptedObjectWithSalt(writer io.Writer, random io.Reader, authKey AuthKey, salt int64, sessionID [8]byte, messageID uint64, sequenceNo uint32, object tl.Object) (EncryptedMessage, error) {
	if object == nil {
		return EncryptedMessage{}, ErrEncryptedMessage
	}
	body, err := tl.Encode(object)
	if err != nil {
		return EncryptedMessage{}, fmt.Errorf("mtproto: encode encrypted object: %w", err)
	}
	return SendEncryptedWithSalt(writer, random, authKey, salt, sessionID, messageID, sequenceNo, body)
}

// ReceiveEncryptedObject reads and decodes one server-to-client TL object.
func ReceiveEncryptedObject(reader io.Reader, authKey AuthKey, sessionID [8]byte, maxPayload int) (tl.Object, uint64, uint32, error) {
	return ReceiveEncryptedObjectWithSalt(reader, authKey, 0, sessionID, maxPayload)
}

func ReceiveEncryptedObjectWithSalt(reader io.Reader, authKey AuthKey, salt int64, sessionID [8]byte, maxPayload int) (tl.Object, uint64, uint32, error) {
	messageID, sequenceNo, body, err := ReceiveEncryptedWithSalt(reader, authKey, salt, sessionID, maxPayload)
	if err != nil {
		return nil, messageID, sequenceNo, err
	}
	object, err := tl.Decode(body, tl.DefaultDecodeLimits())
	if err != nil {
		return nil, messageID, sequenceNo, fmt.Errorf("mtproto: decode encrypted object: %w", err)
	}
	return object, messageID, sequenceNo, nil
}
