package mtproto

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	"github.com/mtgo-labs/raw/internal/cryptoutil"
	"github.com/mtgo-labs/raw/tl"
)

var (
	ErrInvalidResPQ     = errors.New("mtproto: invalid resPQ")
	ErrResPQNonce       = errors.New("mtproto: resPQ nonce mismatch")
	ErrResPQKeyNotFound = errors.New("mtproto: resPQ has no known RSA key")
	ErrNilAuthKeyStore  = errors.New("mtproto: auth-key persistence callback is nil")
)

// AuthKeyStore persists a completed permanent authorization key. The callback
// runs synchronously before FinalizeAuthKey returns.
type AuthKeyStore func(AuthKey) error

// FinalizeAuthKey verifies the server's final DH result and synchronously
// persists the key only after verification succeeds.
func FinalizeAuthKey(authKey AuthKey, nonce, serverNonce [16]byte, newNonce [32]byte, result tl.MTPSetClientDHParamsAnswerClass, store AuthKeyStore) error {
	if store == nil {
		return ErrNilAuthKeyStore
	}
	if err := VerifyDHGenResult(authKey, nonce, serverNonce, newNonce, result); err != nil {
		return err
	}
	return store(authKey)
}

// ResPQSelection is the validated input required to build p_q_inner_data.
type ResPQSelection struct {
	ServerNonce [16]byte
	P           uint64
	Q           uint64
	Fingerprint uint64
	PublicKey   *rsa.PublicKey
}

// BuildPQInnerData encodes and RSA-encrypts the authorization request that
// follows a validated resPQ response.
func BuildPQInnerData(random io.Reader, selection ResPQSelection, pq []byte, nonce, serverNonce [16]byte, newNonce [32]byte, dc int32) (*tl.MTPReqDHParams, error) {
	if selection.PublicKey == nil || len(pq) == 0 || selection.P == 0 || selection.Q == 0 {
		return nil, ErrInvalidResPQ
	}
	inner, err := tl.Encode(&tl.MTPPQInnerDataDC{
		PQ: pq, P: uint64Bytes(selection.P), Q: uint64Bytes(selection.Q),
		Nonce: nonce, ServerNonce: serverNonce, NewNonce: newNonce, DC: dc,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode p_q_inner_data: %v", ErrInvalidResPQ, err)
	}
	ciphertext, err := cryptoutil.EncryptRSAPadded(random, selection.PublicKey, inner)
	clear(inner)
	if err != nil {
		return nil, fmt.Errorf("%w: RSA encrypt: %v", ErrInvalidResPQ, err)
	}
	return &tl.MTPReqDHParams{
		Nonce: nonce, ServerNonce: serverNonce,
		P: uint64Bytes(selection.P), Q: uint64Bytes(selection.Q),
		PublicKeyFingerprint: int64(selection.Fingerprint), EncryptedData: ciphertext[:],
	}, nil
}

// BuildPQInnerDataTemp builds the RSA-encrypted p_q_inner_data_temp request
// used to create a temporary authorization key for PFS.
func BuildPQInnerDataTemp(random io.Reader, selection ResPQSelection, pq []byte, nonce, serverNonce [16]byte, newNonce [32]byte, dc, expiresIn int32) (*tl.MTPReqDHParams, error) {
	if expiresIn <= 0 {
		return nil, ErrInvalidResPQ
	}
	if selection.PublicKey == nil || len(pq) == 0 || selection.P == 0 || selection.Q == 0 {
		return nil, ErrInvalidResPQ
	}
	inner, err := tl.Encode(&tl.MTPPQInnerDataTempDC{
		PQ: pq, P: uint64Bytes(selection.P), Q: uint64Bytes(selection.Q),
		Nonce: nonce, ServerNonce: serverNonce, NewNonce: newNonce,
		DC: dc, ExpiresIn: expiresIn,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode temporary p_q_inner_data: %v", ErrInvalidResPQ, err)
	}
	ciphertext, err := cryptoutil.EncryptRSAPadded(random, selection.PublicKey, inner)
	clear(inner)
	if err != nil {
		return nil, fmt.Errorf("%w: RSA encrypt temporary: %v", ErrInvalidResPQ, err)
	}
	return &tl.MTPReqDHParams{
		Nonce: nonce, ServerNonce: serverNonce,
		P: uint64Bytes(selection.P), Q: uint64Bytes(selection.Q),
		PublicKeyFingerprint: int64(selection.Fingerprint), EncryptedData: ciphertext[:],
	}, nil
}

func uint64Bytes(value uint64) []byte {
	output := make([]byte, 8)
	for index := range output {
		output[len(output)-1-index] = byte(value >> (8 * index))
	}
	first := 0
	for first < len(output)-1 && output[first] == 0 {
		first++
	}
	return output[first:]
}

// ValidateResPQ checks the response nonce, factors pq, and selects a pinned
// Telegram RSA key. It performs no network I/O and does not retain res.
func ValidateResPQ(random io.Reader, nonce [16]byte, res *tl.MTPResPQ, allowOld bool) (ResPQSelection, error) {
	if res == nil {
		return ResPQSelection{}, ErrInvalidResPQ
	}
	if res.Nonce != nonce {
		return ResPQSelection{}, ErrResPQNonce
	}
	if random == nil {
		random = rand.Reader
	}
	p, q, err := cryptoutil.FactorPQ(random, res.PQ)
	if err != nil {
		return ResPQSelection{}, fmt.Errorf("%w: pq: %v", ErrInvalidResPQ, err)
	}
	fingerprints := make([]uint64, len(res.ServerPublicKeyFingerprints))
	for index, fingerprint := range res.ServerPublicKeyFingerprints {
		fingerprints[index] = uint64(fingerprint)
	}
	publicKey, fingerprint, ok := cryptoutil.FindTelegramRSAKey(fingerprints, allowOld)
	if !ok {
		return ResPQSelection{}, fmt.Errorf("%w: offered %016x", ErrResPQKeyNotFound, fingerprints)
	}
	return ResPQSelection{ServerNonce: res.ServerNonce, P: p, Q: q, Fingerprint: fingerprint, PublicKey: publicKey}, nil
}
