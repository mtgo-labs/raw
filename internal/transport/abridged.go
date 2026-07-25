package transport

import (
	"errors"
	"fmt"
	"io"
)

var (
	ErrAbridgedLength = errors.New("transport: invalid abridged packet length")
	ErrAbridgedLimit  = errors.New("transport: abridged packet exceeds limit")
)

// WriteAbridged writes Telegram's abridged transport packet. The payload is
// written directly after its one- or four-byte length prefix.
func WriteAbridged(writer io.Writer, payload []byte) error {
	if writer == nil || len(payload) == 0 || len(payload)%4 != 0 {
		return ErrAbridgedLength
	}
	words := len(payload) / 4
	if words < 0x7f {
		if err := writeFull(writer, []byte{byte(words)}); err != nil {
			return fmt.Errorf("transport: write abridged header: %w", err)
		}
	} else if words <= 0xffffff {
		header := [4]byte{0x7f, byte(words), byte(words >> 8), byte(words >> 16)}
		if err := writeFull(writer, header[:]); err != nil {
			return fmt.Errorf("transport: write abridged header: %w", err)
		}
	} else {
		return ErrAbridgedLength
	}
	if err := writeFull(writer, payload); err != nil {
		return fmt.Errorf("transport: write abridged payload: %w", err)
	}
	return nil
}

func ReadAbridged(reader io.Reader, maxPayload int) ([]byte, error) {
	if reader == nil {
		return nil, ErrAbridgedLength
	}
	if maxPayload <= 0 {
		maxPayload = DefaultMaxIntermediatePayload
	}
	var first [1]byte
	if _, err := io.ReadFull(reader, first[:]); err != nil {
		return nil, fmt.Errorf("transport: read abridged header: %w", err)
	}
	words := uint32(first[0])
	if words == 0x7f {
		var extended [3]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return nil, fmt.Errorf("transport: read abridged header: %w", err)
		}
		words = uint32(extended[0]) | uint32(extended[1])<<8 | uint32(extended[2])<<16
	}
	if words == 0 {
		return nil, ErrAbridgedLength
	}
	length := uint64(words) * 4
	if length > uint64(maxPayload) {
		return nil, ErrAbridgedLimit
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, fmt.Errorf("transport: read abridged payload: %w", err)
	}
	return payload, nil
}
