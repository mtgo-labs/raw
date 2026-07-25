package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
)

var forbiddenObfuscatedHeaders = []uint32{
	0xdddddddd, 0xeeeeeeee, 0x44414548, 0x54534f50,
	0x20544547, 0x4954504f, 0x02010316,
}

func validObfuscatedNonce(nonce []byte) bool {
	if len(nonce) != 64 || nonce[0] == 0xef {
		return false
	}
	if slices.Contains(forbiddenObfuscatedHeaders, binary.LittleEndian.Uint32(nonce[:4])) {
		return false
	}
	return binary.LittleEndian.Uint32(nonce[4:8]) != 0
}

// ObfuscatedConn encrypts the underlying byte stream with Telegram's
// obfuscated2 AES-CTR handshake. Packet framing remains supplied by PacketConn.
type ObfuscatedConn struct {
	net.Conn

	readMu  sync.Mutex
	writeMu sync.Mutex
	enc     cipher.Stream
	dec     cipher.Stream

	writeBuffer []byte
}

func NewObfuscatedConn(connection net.Conn, marker byte) (net.Conn, error) {
	if connection == nil {
		return nil, errors.New("transport: nil obfuscated connection")
	}
	nonce := make([]byte, 64)
	for {
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, fmt.Errorf("transport: generate obfuscated nonce: %w", err)
		}
		if validObfuscatedNonce(nonce) {
			break
		}
	}
	return newObfuscatedConn(connection, marker, nonce, true)
}

// NewObfuscatedConnWithNonce is deterministic and intended for protocol tests.
func NewObfuscatedConnWithNonce(connection net.Conn, marker byte, nonce []byte) (net.Conn, error) {
	if len(nonce) != 64 {
		return nil, errors.New("transport: invalid obfuscated nonce")
	}
	copyNonce := append([]byte(nil), nonce...)
	if !validObfuscatedNonce(copyNonce) {
		return nil, errors.New("transport: forbidden obfuscated nonce")
	}
	return newObfuscatedConn(connection, marker, copyNonce, true)
}

func newObfuscatedConn(connection net.Conn, marker byte, nonce []byte, send bool) (net.Conn, error) {
	if marker == 0 {
		return nil, errors.New("transport: invalid obfuscated marker")
	}
	nonce[56], nonce[57], nonce[58], nonce[59] = marker, marker, marker, marker
	encKey, encIV := nonce[8:40], nonce[40:56]
	reversed := make([]byte, 48)
	for index := range reversed {
		reversed[index] = nonce[55-index]
	}
	decKey, decIV := reversed[:32], reversed[32:]
	encBlock, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	decBlock, err := aes.NewCipher(decKey)
	if err != nil {
		return nil, err
	}
	enc := cipher.NewCTR(encBlock, encIV)
	dec := cipher.NewCTR(decBlock, decIV)
	if send {
		encrypted := make([]byte, 64)
		enc.XORKeyStream(encrypted, nonce)
		copy(nonce[56:64], encrypted[56:64])
		if err := writeFull(connection, nonce); err != nil {
			return nil, fmt.Errorf("transport: write obfuscated nonce: %w", err)
		}
	}
	return &ObfuscatedConn{Conn: connection, enc: enc, dec: dec}, nil
}

func (connection *ObfuscatedConn) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	connection.writeMu.Lock()
	defer connection.writeMu.Unlock()
	if cap(connection.writeBuffer) < len(payload) {
		connection.writeBuffer = make([]byte, len(payload))
	}
	encoded := connection.writeBuffer[:len(payload)]
	connection.enc.XORKeyStream(encoded, payload)
	if err := writeFull(connection.Conn, encoded); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (connection *ObfuscatedConn) Read(payload []byte) (int, error) {
	connection.readMu.Lock()
	defer connection.readMu.Unlock()
	count, err := connection.Conn.Read(payload)
	if count > 0 {
		connection.dec.XORKeyStream(payload[:count], payload[:count])
	}
	return count, err
}
