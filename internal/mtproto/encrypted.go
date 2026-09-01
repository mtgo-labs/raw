package mtproto

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"github.com/mtgo-labs/raw/internal/cryptoutil"
	"github.com/mtgo-labs/raw/internal/transport"
)

// SendEncrypted encrypts one client message and writes it over intermediate
// framing. The returned message retains the constructed payload for tracing or
// tests; the writer owns only its output stream.
func SendEncrypted(writer io.Writer, random io.Reader, authKey AuthKey, sessionID [8]byte, messageID uint64, sequenceNo uint32, body []byte) (EncryptedMessage, error) {
	return SendEncryptedWithSalt(writer, random, authKey, 0, sessionID, messageID, sequenceNo, body)
}

func SendEncryptedWithSalt(writer io.Writer, random io.Reader, authKey AuthKey, salt int64, sessionID [8]byte, messageID uint64, sequenceNo uint32, body []byte) (EncryptedMessage, error) {
	message, err := EncryptMessageWithSalt(random, authKey, salt, sessionID, messageID, sequenceNo, body)
	if err != nil {
		return EncryptedMessage{}, err
	}
	if err := transport.WritePacketReserved(writer, message.packet, transport.PacketFrameHeadroom); err != nil {
		return EncryptedMessage{}, err
	}
	return message, nil
}

// ReceiveEncrypted reads one bounded server message from intermediate framing
// and verifies/decrypts it before returning body bytes.
func ReceiveEncrypted(reader io.Reader, authKey AuthKey, sessionID [8]byte, maxPayload int) (uint64, uint32, []byte, error) {
	return ReceiveEncryptedWithSalt(reader, authKey, 0, sessionID, maxPayload)
}

func ReceiveEncryptedWithSalt(reader io.Reader, authKey AuthKey, salt int64, sessionID [8]byte, maxPayload int) (uint64, uint32, []byte, error) {
	payload, err := transport.ReadPacket(reader, maxPayload)
	if err != nil {
		return 0, 0, nil, err
	}
	return DecryptMessageWithSalt(authKey, salt, sessionID, payload)
}

const (
	minMessagePadding = 12
	maxMessagePadding = 1024
	messageHeaderSize = 32
)

var (
	ErrEncryptedMessage    = errors.New("mtproto: invalid encrypted message")
	ErrEncryptedAuthKey    = errors.New("mtproto: encrypted message auth-key mismatch")
	ErrEncryptedMessageKey = errors.New("mtproto: encrypted message key mismatch")
)

// EncryptedMessage is the MTProto 2.0 encrypted envelope without transport
// framing. Payload contains the exact auth-key ID, message key, and ciphertext.
type EncryptedMessage struct {
	AuthKeyID  uint64
	MessageKey [16]byte
	Payload    []byte
	packet     []byte
}

// EncryptMessage builds one client-to-server MTProto 2.0 message.
func EncryptMessage(random io.Reader, authKey AuthKey, sessionID [8]byte, messageID uint64, sequenceNo uint32, body []byte) (EncryptedMessage, error) {
	return EncryptMessageWithSalt(random, authKey, 0, sessionID, messageID, sequenceNo, body)
}

func EncryptMessageWithSalt(random io.Reader, authKey AuthKey, salt int64, sessionID [8]byte, messageID uint64, sequenceNo uint32, body []byte) (EncryptedMessage, error) {
	return encryptMessageWithSalt(random, authKey, salt, sessionID, messageID, sequenceNo, body, cryptoutil.ClientToServer)
}

func encryptMessage(random io.Reader, authKey AuthKey, sessionID [8]byte, messageID uint64, sequenceNo uint32, body []byte, direction cryptoutil.MessageDirection) (EncryptedMessage, error) {
	return encryptMessageWithSalt(random, authKey, 0, sessionID, messageID, sequenceNo, body, direction)
}

func encryptMessageWithSalt(random io.Reader, authKey AuthKey, salt int64, sessionID [8]byte, messageID uint64, sequenceNo uint32, body []byte, direction cryptoutil.MessageDirection) (EncryptedMessage, error) {
	if random == nil || authKey.ID == 0 || messageID == 0 || len(body) == 0 || len(body)%4 != 0 {
		return EncryptedMessage{}, ErrEncryptedMessage
	}
	padding := alignedPadding(len(body))
	if padding < minMessagePadding || padding > maxMessagePadding {
		return EncryptedMessage{}, ErrEncryptedMessage
	}
	packet := make([]byte, transport.PacketFrameHeadroom+24+messageHeaderSize+len(body)+padding)
	payload := packet[transport.PacketFrameHeadroom:]
	plain := payload[24:]
	copy(plain[32:], body)
	if _, err := io.ReadFull(random, plain[32+len(body):]); err != nil {
		return EncryptedMessage{}, fmt.Errorf("%w: padding: %v", ErrEncryptedMessage, err)
	}
	putPlainHeader(plain, salt, sessionID, messageID, sequenceNo, len(body))
	messageKey, err := cryptoutil.ComputeMessageKey(authKey.Key[:], plain, direction)
	if err != nil {
		return EncryptedMessage{}, err
	}
	block, iv, err := cryptoutil.NewMessageAES256(authKey.Key[:], messageKey, direction)
	if err != nil {
		return EncryptedMessage{}, err
	}
	if err := cryptoutil.EncryptIGE(plain, plain, block, iv[:]); err != nil {
		return EncryptedMessage{}, err
	}
	putUint64(payload, authKey.ID)
	copy(payload[8:24], messageKey[:])
	copy(payload[24:], plain)
	return EncryptedMessage{AuthKeyID: authKey.ID, MessageKey: messageKey, Payload: payload, packet: packet}, nil
}

// DecryptMessage verifies and decrypts one server-to-client MTProto 2.0
// message. It rejects unauthenticated padding and body lengths.
func DecryptMessage(authKey AuthKey, sessionID [8]byte, payload []byte) (uint64, uint32, []byte, error) {
	return decryptMessage(authKey, sessionID, payload, cryptoutil.ServerToClient)
}

func DecryptMessageWithSalt(authKey AuthKey, salt int64, sessionID [8]byte, payload []byte) (uint64, uint32, []byte, error) {
	return decryptMessageWithSalt(authKey, salt, sessionID, payload, cryptoutil.ServerToClient)
}

func decryptMessage(authKey AuthKey, sessionID [8]byte, payload []byte, direction cryptoutil.MessageDirection) (uint64, uint32, []byte, error) {
	return decryptMessageWithSalt(authKey, 0, sessionID, payload, direction)
}

func decryptMessageWithSalt(authKey AuthKey, salt int64, sessionID [8]byte, payload []byte, direction cryptoutil.MessageDirection) (uint64, uint32, []byte, error) {
	messageID, sequenceNo, body, _, err := decryptMessageEnvelope(authKey, salt, sessionID, payload, direction, true)
	return messageID, sequenceNo, body, err
}

func decryptMessageWithoutExpectedSalt(authKey AuthKey, sessionID [8]byte, payload []byte) (uint64, uint32, []byte, int64, error) {
	return decryptMessageEnvelope(authKey, 0, sessionID, payload, cryptoutil.ServerToClient, false)
}

func decryptMessageEnvelope(authKey AuthKey, salt int64, sessionID [8]byte, payload []byte, direction cryptoutil.MessageDirection, validateSalt bool) (uint64, uint32, []byte, int64, error) {
	if authKey.ID == 0 || len(payload) < 24+messageHeaderSize || (len(payload)-24)%16 != 0 {
		return 0, 0, nil, 0, ErrEncryptedMessage
	}
	if readUint64(payload) != authKey.ID {
		return 0, 0, nil, 0, ErrEncryptedAuthKey
	}
	var messageKey [16]byte
	copy(messageKey[:], payload[8:24])
	plain := make([]byte, len(payload)-24)
	copy(plain, payload[24:])
	block, iv, err := cryptoutil.NewMessageAES256(authKey.Key[:], messageKey, direction)
	if err != nil {
		return 0, 0, nil, 0, err
	}
	if err := cryptoutil.DecryptIGE(plain, plain, block, iv[:]); err != nil {
		return 0, 0, nil, 0, err
	}
	envelopeSalt, messageID, sequenceNo, bodyLength, err := readPlainHeader(plain, salt, sessionID, validateSalt)
	if err != nil {
		return 0, 0, nil, 0, err
	}
	if bodyLength == 0 || bodyLength%4 != 0 || bodyLength > len(plain)-messageHeaderSize || len(plain)-messageHeaderSize-bodyLength < minMessagePadding || len(plain)-messageHeaderSize-bodyLength > maxMessagePadding {
		return 0, 0, nil, 0, ErrEncryptedMessage
	}
	computed, err := cryptoutil.ComputeMessageKey(authKey.Key[:], plain, direction)
	if err != nil || subtle.ConstantTimeCompare(computed[:], messageKey[:]) != 1 {
		return 0, 0, nil, 0, ErrEncryptedMessageKey
	}
	// The body is a subslice of the decrypted plaintext, not a copy: the
	// receive path already hands buffer-backed slices to waiters, and
	// keeping header and padding (≤ 1 KiB) alive with a live body is
	// cheaper than a second message-size allocation and copy per inbound
	// message. The payload argument stays read-only.
	body := plain[messageHeaderSize : messageHeaderSize+bodyLength]
	return messageID, sequenceNo, body, envelopeSalt, nil
}

func alignedPadding(bodyLength int) int {
	padding := minMessagePadding
	for (messageHeaderSize+bodyLength+padding)%16 != 0 {
		padding++
	}
	return padding
}

func putPlainHeader(output []byte, salt int64, sessionID [8]byte, messageID uint64, sequenceNo uint32, bodyLength int) {
	putUint64(output, uint64(salt))
	copy(output[8:16], sessionID[:])
	putUint64(output[16:24], messageID)
	putUint32(output[24:28], sequenceNo)
	putUint32(output[28:32], uint32(bodyLength))
}

func readPlainHeader(input []byte, salt int64, sessionID [8]byte, validateSalt bool) (int64, uint64, uint32, int, error) {
	if len(input) < messageHeaderSize || subtle.ConstantTimeCompare(input[8:16], sessionID[:]) != 1 {
		return 0, 0, 0, 0, ErrEncryptedMessage
	}
	envelopeSalt := int64(readUint64(input))
	if validateSalt && envelopeSalt != salt {
		return 0, 0, 0, 0, ErrEncryptedMessage
	}
	messageID := readUint64(input[16:])
	if messageID == 0 {
		return 0, 0, 0, 0, ErrEncryptedMessage
	}
	return envelopeSalt, messageID, readUint32(input[24:]), int(readUint32(input[28:])), nil
}

func putUint64(output []byte, value uint64) {
	output[0] = byte(value)
	output[1] = byte(value >> 8)
	output[2] = byte(value >> 16)
	output[3] = byte(value >> 24)
	output[4] = byte(value >> 32)
	output[5] = byte(value >> 40)
	output[6] = byte(value >> 48)
	output[7] = byte(value >> 56)
}
func putUint32(output []byte, value uint32) {
	output[0] = byte(value)
	output[1] = byte(value >> 8)
	output[2] = byte(value >> 16)
	output[3] = byte(value >> 24)
}
func readUint64(input []byte) uint64 {
	return uint64(input[0]) | uint64(input[1])<<8 | uint64(input[2])<<16 | uint64(input[3])<<24 | uint64(input[4])<<32 | uint64(input[5])<<40 | uint64(input[6])<<48 | uint64(input[7])<<56
}
func readUint32(input []byte) uint32 {
	return uint32(input[0]) | uint32(input[1])<<8 | uint32(input[2])<<16 | uint32(input[3])<<24
}
