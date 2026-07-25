package transport

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

type PacketMode uint8

const (
	PacketIntermediate PacketMode = iota
	PacketAbridged
	PacketPaddedIntermediate
)

const PacketFrameHeadroom = 4

type PacketConn struct {
	net.Conn
	mode   PacketMode
	reader *bufio.Reader
}

func WritePacketReserved(writer io.Writer, packet []byte, payloadOffset int) error {
	if writer == nil || payloadOffset < 0 || payloadOffset >= len(packet) {
		return errors.New("transport: invalid reserved packet")
	}
	if packetWriter, ok := writer.(interface {
		WritePacketReserved([]byte, int) error
	}); ok {
		return packetWriter.WritePacketReserved(packet, payloadOffset)
	}
	return WritePacket(writer, packet[payloadOffset:])
}

func WritePacketHeader(writer io.Writer, mode PacketMode) error {
	if writer == nil || mode > PacketPaddedIntermediate {
		return errors.New("transport: invalid packet header")
	}
	var header []byte
	switch mode {
	case PacketAbridged:
		header = []byte{0xef}
	case PacketPaddedIntermediate:
		header = []byte{0xdd, 0xdd, 0xdd, 0xdd}
	default:
		header = []byte{0xee, 0xee, 0xee, 0xee}
	}
	if err := writeFull(writer, header); err != nil {
		return fmt.Errorf("transport: write packet header: %w", err)
	}
	return nil
}

func NewPacketConn(connection net.Conn, mode PacketMode) (*PacketConn, error) {
	if connection == nil || mode > PacketPaddedIntermediate {
		return nil, errors.New("transport: invalid packet connection")
	}
	return &PacketConn{Conn: connection, mode: mode, reader: bufio.NewReaderSize(connection, 32768)}, nil
}

func (connection *PacketConn) WritePacket(payload []byte) error {
	if connection.mode == PacketAbridged {
		return WriteAbridged(connection.Conn, payload)
	}
	if connection.mode == PacketPaddedIntermediate {
		return WritePaddedIntermediate(connection.Conn, payload)
	}
	return WriteIntermediate(connection.Conn, payload)
}

func (connection *PacketConn) WritePacketReserved(packet []byte, payloadOffset int) error {
	if connection == nil || payloadOffset < 0 || payloadOffset >= len(packet) {
		return errors.New("transport: invalid reserved packet")
	}
	payload := packet[payloadOffset:]
	if connection.mode != PacketIntermediate {
		return connection.WritePacket(payload)
	}
	if payloadOffset < PacketFrameHeadroom || len(payload) == 0 || len(payload)%4 != 0 ||
		uint64(len(payload)) > uint64(^uint32(0)) {
		return ErrIntermediateLength
	}
	frame := packet[payloadOffset-PacketFrameHeadroom:]
	binary.LittleEndian.PutUint32(frame[:PacketFrameHeadroom], uint32(len(payload)))
	if err := writeFull(connection.Conn, frame); err != nil {
		return fmt.Errorf("transport: write intermediate packet: %w", err)
	}
	return nil
}
func (connection *PacketConn) writePlainPacket(messageID uint64, body []byte) error {
	if connection.mode == PacketIntermediate {
		return writePlainIntermediate(connection.Conn, messageID, body)
	}
	return connection.WritePacket(makePlainPayload(messageID, body))
}

func (connection *PacketConn) ReadPacket(maxPayload int) ([]byte, error) {
	if connection.mode == PacketAbridged {
		return ReadAbridged(connection.reader, maxPayload)
	}
	if connection.mode == PacketPaddedIntermediate {
		return ReadPaddedIntermediate(connection.reader, maxPayload)
	}
	return ReadIntermediate(connection.reader, maxPayload)
}
func (connection *PacketConn) readPlainPacket(maxPayload int) ([]byte, error) {
	if connection.mode == PacketPaddedIntermediate {
		return readPaddedIntermediatePayload(connection.reader, maxPayload)
	}
	return connection.ReadPacket(maxPayload)
}

func DialPacket(ctx context.Context, address string, mode PacketMode) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("transport: nil dial context")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	setNoDelay(connection)
	if err := WritePacketHeader(connection, mode); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return NewPacketConn(connection, mode)
}
