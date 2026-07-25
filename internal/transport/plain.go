package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var (
	ErrPlainHeader = errors.New("transport: invalid plain MTProto header")
	ErrPlainBody   = errors.New("transport: invalid plain MTProto body")
)

// PlainMessage is one unencrypted MTProto message used during authorization.
type PlainMessage struct {
	MessageID uint64
	Body      []byte
}

// WritePlain writes an unencrypted MTProto message using the writer's packet
// framing. Intermediate framing keeps the header and body as separate writes.
func WritePlain(writer io.Writer, messageID uint64, body []byte) error {
	if writer == nil {
		return errors.New("transport: nil writer")
	}
	if messageID == 0 {
		return ErrPlainHeader
	}
	if len(body) == 0 || len(body)%4 != 0 {
		return ErrPlainBody
	}
	length := 20 + len(body)
	if length%4 != 0 || length > DefaultMaxIntermediatePayload {
		return ErrPlainBody
	}
	if packetWriter, ok := writer.(interface {
		writePlainPacket(uint64, []byte) error
	}); ok {
		return packetWriter.writePlainPacket(messageID, body)
	}
	return writePlainIntermediate(writer, messageID, body)
}

func writePlainIntermediate(writer io.Writer, messageID uint64, body []byte) error {
	length := 20 + len(body)
	var frameHeader [4]byte
	binary.LittleEndian.PutUint32(frameHeader[:], uint32(length))
	if err := writeFull(writer, frameHeader[:]); err != nil {
		return fmt.Errorf("transport: write plain frame header: %w", err)
	}
	var plainHeader [20]byte
	binary.LittleEndian.PutUint64(plainHeader[8:16], messageID)
	binary.LittleEndian.PutUint32(plainHeader[16:20], uint32(len(body)))
	if err := writeFull(writer, plainHeader[:]); err != nil {
		return fmt.Errorf("transport: write plain header: %w", err)
	}
	if err := writeFull(writer, body); err != nil {
		return fmt.Errorf("transport: write plain body: %w", err)
	}
	return nil
}

func makePlainPayload(messageID uint64, body []byte) []byte {
	payload := make([]byte, 20+len(body))
	binary.LittleEndian.PutUint64(payload[8:16], messageID)
	binary.LittleEndian.PutUint32(payload[16:20], uint32(len(body)))
	copy(payload[20:], body)
	return payload
}

// ReadPlain reads one bounded unencrypted MTProto message using the reader's
// packet framing. The returned body is newly allocated and owned by the caller.
func ReadPlain(reader io.Reader, maxBody int) (PlainMessage, error) {
	if maxBody <= 0 {
		maxBody = DefaultMaxIntermediatePayload - 20
	}
	payload, err := readPlainPacket(reader, maxBody+20)
	if err != nil {
		return PlainMessage{}, err
	}
	if len(payload) < 20 || binary.LittleEndian.Uint64(payload[:8]) != 0 || binary.LittleEndian.Uint64(payload[8:16]) == 0 {
		return PlainMessage{}, ErrPlainHeader
	}
	bodyLength := int(binary.LittleEndian.Uint32(payload[16:20]))
	if bodyLength == 0 || bodyLength%4 != 0 || bodyLength > len(payload)-20 || bodyLength > maxBody {
		return PlainMessage{}, ErrPlainBody
	}
	trailing := len(payload) - 20 - bodyLength
	packet, padded := reader.(*PacketConn)
	if trailing != 0 && (!padded || packet.mode != PacketPaddedIntermediate || trailing > 15) {
		return PlainMessage{}, ErrPlainBody
	}
	return PlainMessage{MessageID: binary.LittleEndian.Uint64(payload[8:16]), Body: payload[20 : 20+bodyLength]}, nil
}
func readPlainPacket(reader io.Reader, maxPayload int) ([]byte, error) {
	if packetReader, ok := reader.(interface {
		readPlainPacket(int) ([]byte, error)
	}); ok {
		return packetReader.readPlainPacket(maxPayload)
	}
	return ReadPacket(reader, maxPayload)
}
