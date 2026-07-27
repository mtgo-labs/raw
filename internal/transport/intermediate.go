// Package transport contains direct MTProto wire transports. It has no
// middleware, plugin, or request-dispatch layers.
package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const DefaultMaxIntermediatePayload = 16 << 20

var (
	ErrIntermediateLength = errors.New("transport: invalid intermediate packet length")
	ErrIntermediateLimit  = errors.New("transport: intermediate packet exceeds limit")
)

func WritePacket(writer io.Writer, payload []byte) error {
	if packetWriter, ok := writer.(interface{ WritePacket([]byte) error }); ok {
		return packetWriter.WritePacket(payload)
	}
	return WriteIntermediate(writer, payload)
}

func ReadPacket(reader io.Reader, maxPayload int) ([]byte, error) {
	if packetReader, ok := reader.(interface{ ReadPacket(int) ([]byte, error) }); ok {
		return packetReader.ReadPacket(maxPayload)
	}
	return ReadIntermediate(reader, maxPayload)
}

func ReadPacketView(reader io.Reader, maxPayload int, consume func([]byte) error) error {
	if packetReader, ok := reader.(interface {
		ReadPacketView(int, func([]byte) error) error
	}); ok {
		return packetReader.ReadPacketView(maxPayload, consume)
	}
	payload, err := ReadPacket(reader, maxPayload)
	if err != nil {
		return err
	}
	return consume(payload)
}

// WriteIntermediate writes one intermediate-transport packet without copying
// payload. The payload length must be a non-zero multiple of four bytes.
func WriteIntermediate(writer io.Writer, payload []byte) error {
	if writer == nil {
		return errors.New("transport: nil writer")
	}
	if len(payload) == 0 || len(payload)%4 != 0 || uint64(len(payload)) > uint64(^uint32(0)) {
		return ErrIntermediateLength
	}
	frame := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	if err := writeFull(writer, frame); err != nil {
		return fmt.Errorf("transport: write intermediate: %w", err)
	}
	return nil
}

// ReadIntermediate reads one bounded intermediate-transport packet.
func ReadIntermediate(reader io.Reader, maxPayload int) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("transport: nil reader")
	}
	if maxPayload <= 0 {
		maxPayload = DefaultMaxIntermediatePayload
	}
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, fmt.Errorf("transport: read intermediate header: %w", err)
	}
	length := int(binary.LittleEndian.Uint32(header[:]))
	if length == 0 || length%4 != 0 {
		return nil, ErrIntermediateLength
	}
	if length > maxPayload {
		return nil, ErrIntermediateLimit
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, fmt.Errorf("transport: read intermediate payload: %w", err)
	}
	return payload, nil
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		count, err := writer.Write(data)
		if count > 0 {
			data = data[count:]
		}
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
