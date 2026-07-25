// Package mtproto contains the low-level MTProto authorization and session
// state machines. It deliberately has no transport or high-level API layer.
package mtproto

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"time"
)

const authKeyBytes = 256

var (
	ErrInvalidAuthKey    = errors.New("mtproto: authorization key must be 256 bytes")
	ErrInvalidAuthNonces = errors.New("mtproto: authorization nonces do not match")
)

// AuthKey is the immutable material required to encrypt an MTProto session.
// Key is copied into the value so callers can clear their input buffer.
type AuthKey struct {
	Key        [authKeyBytes]byte
	ID         uint64
	AuxHash    uint64
	Salt       [8]byte
	TimeOffset int64
}

// NewAuthKey builds the persistent authorization-key state from the DH shared
// secret and the nonces negotiated during authorization.
func NewAuthKey(sharedSecret []byte, serverNonce [16]byte, newNonce [32]byte, serverTime int64, now time.Time) (AuthKey, error) {
	if len(sharedSecret) != authKeyBytes {
		return AuthKey{}, ErrInvalidAuthKey
	}
	var value AuthKey
	copy(value.Key[:], sharedSecret)
	digest := sha1.Sum(value.Key[:])
	value.AuxHash = binary.LittleEndian.Uint64(digest[:8])
	value.ID = binary.LittleEndian.Uint64(digest[12:])
	for index := range value.Salt {
		value.Salt[index] = newNonce[index] ^ serverNonce[index]
	}
	value.TimeOffset = serverTime - now.Unix()
	return value, nil
}

// RestoreAuthKey reconstructs persistent authorization-key state without
// repeating the authorization handshake. The session salt is owned by
// SessionState and is restored separately.
func RestoreAuthKey(key []byte, id uint64, timeOffset int64) (AuthKey, error) {
	if len(key) != authKeyBytes {
		return AuthKey{}, ErrInvalidAuthKey
	}
	if id == 0 {
		return AuthKey{}, ErrInvalidAuthKey
	}
	var value AuthKey
	copy(value.Key[:], key)
	digest := sha1.Sum(value.Key[:])
	value.AuxHash = binary.LittleEndian.Uint64(digest[:8])
	value.ID = id
	value.TimeOffset = timeOffset
	return value, nil
}

// NewNonceHash computes the 128-bit DH result hash used by dh_gen_ok,
// dh_gen_retry, and dh_gen_fail.
func NewNonceHash(newNonce [32]byte, kind byte, authKeyAuxHash uint64) [16]byte {
	var input [41]byte
	copy(input[:32], newNonce[:])
	input[32] = kind
	binary.LittleEndian.PutUint64(input[33:], authKeyAuxHash)
	digest := sha1.Sum(input[:])
	var output [16]byte
	copy(output[:], digest[4:])
	return output
}
