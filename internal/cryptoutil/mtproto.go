package cryptoutil

import (
	"crypto/sha1"
	"crypto/sha256"
	"errors"
)

const authKeySize = 256

var (
	ErrInvalidAuthKeySize = errors.New(
		"cryptoutil: MTProto authorization key must be 256 bytes",
	)
	ErrInvalidMessageDirection = errors.New(
		"cryptoutil: invalid MTProto message direction",
	)
)

// MessageDirection identifies the sender for MTProto 2.0 key derivation.
type MessageDirection uint8

const (
	// ClientToServer derives keys for an outgoing client message.
	ClientToServer MessageDirection = iota + 1
	// ServerToClient derives keys for an incoming server message.
	ServerToClient
)

// ComputeMessageKey derives the 128-bit MTProto 2.0 message key from the
// complete padded plaintext.
func ComputeMessageKey(
	authKey, plaintext []byte,
	direction MessageDirection,
) ([16]byte, error) {
	var messageKey [16]byte
	if len(authKey) != authKeySize {
		return messageKey, ErrInvalidAuthKeySize
	}
	if len(plaintext)%16 != 0 {
		return messageKey, ErrInvalidAESDataSize
	}
	offset, err := messageDirectionOffset(direction)
	if err != nil {
		return messageKey, err
	}

	digest := sha256.New()
	digest.Write(authKey[88+offset : 120+offset])
	digest.Write(plaintext)
	var fullHash [sha256.Size]byte
	sum := digest.Sum(fullHash[:0])
	copy(messageKey[:], sum[8:24])
	clear(fullHash[:])
	return messageKey, nil
}

// NewMessageAES256 derives and expands the MTProto 2.0 AES key and returns its
// 256-bit IGE IV.
func NewMessageAES256(
	authKey []byte,
	messageKey [16]byte,
	direction MessageDirection,
) (AES256, [32]byte, error) {
	key, iv, err := deriveMessageAESKeyIV(authKey, messageKey, direction)
	if err != nil {
		return AES256{}, [32]byte{}, err
	}
	block, err := NewAES256(key[:])
	clear(key[:])
	if err != nil {
		return AES256{}, [32]byte{}, err
	}
	return block, iv, nil
}

func deriveMessageAESKeyIV(
	authKey []byte,
	messageKey [16]byte,
	direction MessageDirection,
) ([32]byte, [32]byte, error) {
	var key [32]byte
	var iv [32]byte
	if len(authKey) != authKeySize {
		return key, iv, ErrInvalidAuthKeySize
	}
	offset, err := messageDirectionOffset(direction)
	if err != nil {
		return key, iv, err
	}

	digest := sha256.New()
	_, _ = digest.Write(messageKey[:])
	_, _ = digest.Write(authKey[offset : offset+36])
	var hashA [sha256.Size]byte
	digest.Sum(hashA[:0])

	digest.Reset()
	_, _ = digest.Write(authKey[40+offset : 76+offset])
	_, _ = digest.Write(messageKey[:])
	var hashB [sha256.Size]byte
	digest.Sum(hashB[:0])

	copy(key[:8], hashA[:8])
	copy(key[8:24], hashB[8:24])
	copy(key[24:], hashA[24:])

	copy(iv[:8], hashB[:8])
	copy(iv[8:24], hashA[8:24])
	copy(iv[24:], hashB[24:])
	return key, iv, nil
}

// DeriveNonceAESKeyIV derives the temporary AES key and IV used during
// authorization-key negotiation.
func DeriveNonceAESKeyIV(
	serverNonce [16]byte,
	newNonce [32]byte,
) ([32]byte, [32]byte) {
	var input [64]byte
	copy(input[:32], newNonce[:])
	copy(input[32:48], serverNonce[:])
	hash1 := sha1.Sum(input[:48])

	copy(input[:16], serverNonce[:])
	copy(input[16:48], newNonce[:])
	hash2 := sha1.Sum(input[:48])

	copy(input[:32], newNonce[:])
	copy(input[32:], newNonce[:])
	hash3 := sha1.Sum(input[:])

	var key [32]byte
	copy(key[:20], hash1[:])
	copy(key[20:], hash2[:12])

	var iv [32]byte
	copy(iv[:8], hash2[12:])
	copy(iv[8:28], hash3[:])
	copy(iv[28:], newNonce[:4])
	return key, iv
}

func messageDirectionOffset(direction MessageDirection) (int, error) {
	switch direction {
	case ClientToServer:
		return 0, nil
	case ServerToClient:
		return 8, nil
	default:
		return 0, ErrInvalidMessageDirection
	}
}
