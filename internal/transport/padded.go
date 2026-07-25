package transport

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ErrPaddedIntermediateLength indicates an invalid padded intermediate packet
// length.
var ErrPaddedIntermediateLength = errors.New("transport: invalid padded intermediate packet length")

func WritePaddedIntermediate(writer io.Writer, payload []byte) error {
	return writePaddedIntermediate(writer, rand.Reader, payload)
}

func writePaddedIntermediate(writer io.Writer, random io.Reader, payload []byte) error {
	if writer == nil {
		return errors.New("transport: nil writer")
	}
	if random == nil || len(payload) == 0 || len(payload) > int(^uint32(0))-15 {
		return ErrPaddedIntermediateLength
	}
	var selector [1]byte
	if _, err := io.ReadFull(random, selector[:]); err != nil {
		return fmt.Errorf("transport: generate padded intermediate padding: %w", err)
	}
	paddingLen := int(selector[0] & 15)
	var padding [15]byte
	if _, err := io.ReadFull(random, padding[:paddingLen]); err != nil {
		return fmt.Errorf("transport: generate padded intermediate bytes: %w", err)
	}
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(payload)+paddingLen))
	if err := writeFull(writer, header[:]); err != nil {
		return fmt.Errorf("transport: write padded intermediate header: %w", err)
	}
	if err := writeFull(writer, payload); err != nil {
		return fmt.Errorf("transport: write padded intermediate payload: %w", err)
	}
	if err := writeFull(writer, padding[:paddingLen]); err != nil {
		return fmt.Errorf("transport: write padded intermediate padding: %w", err)
	}
	return nil
}

func ReadPaddedIntermediate(reader io.Reader, maxPayload int) ([]byte, error) {
	data, err := readPaddedIntermediatePayload(reader, maxPayload)
	if err != nil {
		return nil, err
	}
	if len(data) == 4 {
		return data, nil
	}
	// Encrypted MTProto packets are 16-byte aligned; the remainder is the
	// transport's random padding. Reject malformed alignment rather than
	// passing padding into the encrypted decoder.
	if len(data)%16 != 0 {
		data = data[:len(data)-len(data)%16]
	}
	if len(data) == 0 {
		return nil, ErrPaddedIntermediateLength
	}
	return data, nil
}

func readPaddedIntermediatePayload(reader io.Reader, maxPayload int) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("transport: nil reader")
	}
	if maxPayload <= 0 {
		maxPayload = DefaultMaxIntermediatePayload
	}
	if maxPayload > int(^uint32(0))-15 {
		maxPayload = int(^uint32(0)) - 15
	}
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, fmt.Errorf("transport: read padded intermediate header: %w", err)
	}
	length := uint64(binary.LittleEndian.Uint32(header[:]))
	if length == 0 || length > uint64(maxPayload)+15 {
		return nil, ErrIntermediateLimit
	}
	data := make([]byte, int(length))
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, fmt.Errorf("transport: read padded intermediate payload: %w", err)
	}
	return data, nil
}
