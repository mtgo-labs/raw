package mtproto

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/mtgo-labs/raw/internal/transport"
	"github.com/mtgo-labs/raw/tl"
)

// ClientMessageID returns a protocol-aligned client message ID for now.
func ClientMessageID(now time.Time) uint64 {
	return clientMessageID(now, 0)
}

func clientMessageID(now time.Time, timeOffset int64) uint64 {
	seconds := uint64(adjustUnixSeconds(now.Unix(), timeOffset))
	fraction := (uint64(now.Nanosecond()) << 32) / uint64(time.Second)
	fraction &^= 3
	if fraction == 0 {
		fraction = 4
	}
	return (seconds << 32) | fraction
}

func adjustUnixSeconds(seconds, offset int64) int64 {
	const (
		maxInt64 = int64(^uint64(0) >> 1)
		minInt64 = -maxInt64 - 1
	)
	if offset > 0 && seconds > maxInt64-offset ||
		offset < 0 && seconds < minInt64-offset {
		return seconds
	}
	return seconds + offset
}

// SendPlainObject encodes one TL object and sends it as an unencrypted
// authorization message. The caller owns the connection.
func SendPlainObject(writer io.Writer, now time.Time, object tl.Object) (uint64, error) {
	messageID := ClientMessageID(now)
	return sendPlainObject(writer, messageID, object)
}

func sendPlainObject(writer io.Writer, messageID uint64, object tl.Object) (uint64, error) {
	if object == nil {
		return 0, errors.New("mtproto: nil plain object")
	}
	body, err := tl.Encode(object)
	if err != nil {
		return 0, fmt.Errorf("mtproto: encode plain object: %w", err)
	}
	if err := transport.WritePlain(writer, messageID, body); err != nil {
		return 0, err
	}
	return messageID, nil
}

// ReceivePlainObject reads and decodes one unencrypted TL authorization
// message with bounded payload allocation.
func ReceivePlainObject(reader io.Reader, maxBody int) (tl.Object, uint64, error) {
	message, err := transport.ReadPlain(reader, maxBody)
	if err != nil {
		return nil, 0, err
	}
	object, err := tl.Decode(message.Body, tl.DefaultDecodeLimits())
	if err != nil {
		return nil, message.MessageID, fmt.Errorf("mtproto: decode plain object: %w", err)
	}
	return object, message.MessageID, nil
}
