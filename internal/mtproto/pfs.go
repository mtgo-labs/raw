package mtproto

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/mtgo-labs/raw/internal/cryptoutil"
	"github.com/mtgo-labs/raw/tl"
)

var (
	ErrInvalidPFSBinding = errors.New("mtproto: invalid PFS binding message")
	ErrPFSBindingExpired = errors.New("mtproto: PFS temporary key expired")
)

// BuildPFSBindingMessage creates the MTProto 1.0 encrypted_message payload
// required by auth.bindTempAuthKey. It never sends the request itself; the
// caller invokes auth.bindTempAuthKey over the temporary session. Telegram
// permits one temporary binding per permanent key; binding a new temporary key
// intentionally replaces the previous binding on the server.
func BuildPFSBindingMessage(random io.Reader, permanent, temporary AuthKey, tempSessionID [8]byte, expiresAt int32, messageID uint64) ([]byte, error) {
	payload, _, err := buildPFSBindingMessage(random, permanent, temporary, tempSessionID, expiresAt, messageID)
	return payload, err
}

func buildPFSBindingMessage(random io.Reader, permanent, temporary AuthKey, tempSessionID [8]byte, expiresAt int32, messageID uint64) ([]byte, int64, error) {
	if random == nil || permanent.ID == 0 || temporary.ID == 0 || messageID == 0 || expiresAt <= 0 {
		return nil, 0, ErrInvalidPFSBinding
	}
	var nonce [8]byte
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		return nil, 0, fmt.Errorf("%w: nonce: %v", ErrInvalidPFSBinding, err)
	}
	inner, err := tl.Encode(&tl.MTPBindAuthKeyInner{
		Nonce: int64(binary.LittleEndian.Uint64(nonce[:])), TempAuthKeyID: int64(temporary.ID),
		PermAuthKeyID: int64(permanent.ID), TempSessionID: int64(binary.LittleEndian.Uint64(tempSessionID[:])), ExpiresAt: expiresAt,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("%w: encode inner: %v", ErrInvalidPFSBinding, err)
	}
	if len(inner) != 40 {
		return nil, 0, ErrInvalidPFSBinding
	}
	var plain [16 + 8 + 4 + 4 + 40]byte
	if _, err := io.ReadFull(random, plain[:16]); err != nil {
		return nil, 0, fmt.Errorf("%w: random prefix: %v", ErrInvalidPFSBinding, err)
	}
	binary.LittleEndian.PutUint64(plain[16:24], messageID)
	binary.LittleEndian.PutUint32(plain[24:28], 0)
	binary.LittleEndian.PutUint32(plain[28:32], uint32(len(inner)))
	copy(plain[32:], inner)
	clear(inner)
	digest := sha1.Sum(plain[:])
	var messageKey [16]byte
	copy(messageKey[:], digest[4:20])
	padding := make([]byte, (16-len(plain)%16)%16)
	if _, err := io.ReadFull(random, padding); err != nil {
		return nil, 0, fmt.Errorf("%w: padding: %v", ErrInvalidPFSBinding, err)
	}
	encrypted := make([]byte, len(plain)+len(padding))
	copy(encrypted, plain[:])
	copy(encrypted[len(plain):], padding)
	key, iv := pfsAESKeyIV(permanent.Key[:], messageKey[:])
	block, err := cryptoutil.NewAES256(key[:])
	if err != nil {
		return nil, 0, err
	}
	if err := cryptoutil.EncryptIGE(encrypted, encrypted, block, iv[:]); err != nil {
		return nil, 0, fmt.Errorf("%w: encrypt: %v", ErrInvalidPFSBinding, err)
	}
	output := make([]byte, 24+len(encrypted))
	binary.LittleEndian.PutUint64(output[:8], permanent.ID)
	copy(output[8:24], messageKey[:])
	copy(output[24:], encrypted)
	return output, int64(binary.LittleEndian.Uint64(nonce[:])), nil
}

// BuildPFSBindRequest creates the raw auth.bindTempAuthKey request. The
// request must be sent through the temporary session; its encrypted_message
// is authenticated by the permanent key.
func BuildPFSBindRequest(random io.Reader, permanent, temporary AuthKey, tempSessionID [8]byte, expiresAt int32, messageID uint64) (*tl.AuthBindTempAuthKeyRequest, error) {
	payload, nonce, err := buildPFSBindingMessage(random, permanent, temporary, tempSessionID, expiresAt, messageID)
	if err != nil {
		return nil, err
	}
	return &tl.AuthBindTempAuthKeyRequest{PermAuthKeyID: int64(permanent.ID), Nonce: nonce, ExpiresAt: expiresAt, EncryptedMessage: payload}, nil
}

// PFSBinding owns the active temporary key for one permanent key. Installing
// a new temporary key atomically replaces the previous one.
type PFSBinding struct {
	mu            sync.RWMutex
	permanent     AuthKey
	temporary     AuthKey
	tempSessionID [8]byte
	expiresAt     int64
	bound         bool
}

func NewPFSBinding(permanent AuthKey) (*PFSBinding, error) {
	if permanent.ID == 0 {
		return nil, ErrInvalidPFSBinding
	}
	return &PFSBinding{permanent: permanent}, nil
}

func (binding *PFSBinding) InstallTemporary(temporary AuthKey, sessionID [8]byte, expiresAt time.Time) error {
	if binding == nil || temporary.ID == 0 || expiresAt.IsZero() {
		return ErrInvalidPFSBinding
	}
	binding.mu.Lock()
	binding.temporary = temporary
	binding.tempSessionID = sessionID
	binding.expiresAt = expiresAt.Unix()
	binding.bound = false
	binding.mu.Unlock()
	return nil
}

func (binding *PFSBinding) MarkBound() error {
	if binding == nil {
		return ErrInvalidPFSBinding
	}
	binding.mu.Lock()
	defer binding.mu.Unlock()
	if binding.temporary.ID == 0 || binding.expiresAt == 0 {
		return ErrInvalidPFSBinding
	}
	binding.bound = true
	return nil
}

func (binding *PFSBinding) Current(now time.Time) (AuthKey, [8]byte, bool) {
	if binding == nil {
		return AuthKey{}, [8]byte{}, false
	}
	binding.mu.RLock()
	defer binding.mu.RUnlock()
	if !binding.bound || binding.expiresAt <= now.Unix() {
		return AuthKey{}, [8]byte{}, false
	}
	return binding.temporary, binding.tempSessionID, true
}

func (binding *PFSBinding) BindRequest(random io.Reader, messageID uint64) (*tl.AuthBindTempAuthKeyRequest, error) {
	return binding.BindRequestAt(random, messageID, time.Now())
}

func (binding *PFSBinding) BindRequestAt(random io.Reader, messageID uint64, now time.Time) (*tl.AuthBindTempAuthKeyRequest, error) {
	if binding == nil {
		return nil, ErrInvalidPFSBinding
	}
	binding.mu.RLock()
	permanent, temporary := binding.permanent, binding.temporary
	sessionID, expiresAt := binding.tempSessionID, binding.expiresAt
	binding.mu.RUnlock()
	if expiresAt <= now.Unix() || temporary.ID == 0 {
		return nil, ErrPFSBindingExpired
	}
	return BuildPFSBindRequest(random, permanent, temporary, sessionID, int32(expiresAt), messageID)
}

func (binding *PFSBinding) TemporaryID() uint64 {
	if binding == nil {
		return 0
	}
	binding.mu.RLock()
	defer binding.mu.RUnlock()
	return binding.temporary.ID
}

func (binding *PFSBinding) ClearTemporary() {
	if binding == nil {
		return
	}
	binding.mu.Lock()
	binding.temporary = AuthKey{}
	binding.tempSessionID = [8]byte{}
	binding.expiresAt = 0
	binding.bound = false
	binding.mu.Unlock()
}

func pfsAESKeyIV(authKey []byte, messageKey []byte) ([32]byte, [32]byte) {
	a := sha1.New()
	a.Write(messageKey)
	a.Write(authKey[:32])
	sha1A := a.Sum(nil)
	b := sha1.New()
	b.Write(authKey[32:48])
	b.Write(messageKey)
	b.Write(authKey[48:64])
	sha1B := b.Sum(nil)
	c := sha1.New()
	c.Write(authKey[64:96])
	c.Write(messageKey)
	sha1C := c.Sum(nil)
	d := sha1.New()
	d.Write(messageKey)
	d.Write(authKey[96:128])
	sha1D := d.Sum(nil)
	var key, iv [32]byte
	copy(key[:8], sha1A[:8])
	copy(key[8:20], sha1B[8:20])
	copy(key[20:], sha1C[4:16])
	copy(iv[:12], sha1A[8:20])
	copy(iv[12:20], sha1B[:8])
	copy(iv[20:24], sha1C[16:20])
	copy(iv[24:], sha1D[:8])
	return key, iv
}
