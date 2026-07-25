package mtproto

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/mtgo-labs/raw/internal/cryptoutil"
	"github.com/mtgo-labs/raw/tl"
)

const maxEncryptedDHAnswer = 4096

var (
	ErrInvalidDHAnswer   = errors.New("mtproto: invalid encrypted DH answer")
	ErrDHAnswerNonce     = errors.New("mtproto: encrypted DH answer nonce mismatch")
	ErrDHAnswerIntegrity = errors.New("mtproto: encrypted DH answer hash mismatch")
)

// ClientDHResult contains the encrypted request and the derived state needed
// to verify the server's dh_gen result.
type ClientDHResult struct {
	Request *tl.MTPSetClientDHParams
	AuthKey AuthKey
	GB      []byte
}

// BuildClientDH creates client_DH_inner_data, encrypts it for
// set_client_DH_params, and derives the shared authorization key.
func BuildClientDH(random io.Reader, nonce, serverNonce [16]byte, newNonce [32]byte, retryID int64, now time.Time, inner *tl.MTPServerDHInnerData) (ClientDHResult, error) {
	if random == nil || inner == nil || inner.Nonce != nonce || inner.ServerNonce != serverNonce {
		return ClientDHResult{}, ErrInvalidDHAnswer
	}
	prime := new(big.Int).SetBytes(inner.DHPrime)
	if err := cryptoutil.ValidateDHPrime(random, prime, int(inner.G)); err != nil {
		return ClientDHResult{}, fmt.Errorf("%w: prime: %v", ErrInvalidDHAnswer, err)
	}
	ga := new(big.Int).SetBytes(inner.GA)
	if err := cryptoutil.ValidateDHPublicValue(prime, ga); err != nil {
		return ClientDHResult{}, fmt.Errorf("%w: g_a: %v", ErrInvalidDHAnswer, err)
	}
	upper := new(big.Int).Sub(prime, big.NewInt(2))
	exponent, err := rand.Int(random, upper)
	if err != nil {
		return ClientDHResult{}, fmt.Errorf("%w: exponent: %v", ErrInvalidDHAnswer, err)
	}
	exponent.Add(exponent, big.NewInt(1))
	g := big.NewInt(int64(inner.G))
	gb := new(big.Int).Exp(g, exponent, prime)
	if err := cryptoutil.ValidateDHPublicValue(prime, gb); err != nil {
		return ClientDHResult{}, fmt.Errorf("%w: g_b: %v", ErrInvalidDHAnswer, err)
	}
	shared := new(big.Int).Exp(ga, exponent, prime)
	gbBytes, err := fixedDHBytes(gb)
	if err != nil {
		return ClientDHResult{}, err
	}
	sharedBytes, err := fixedDHBytes(shared)
	if err != nil {
		return ClientDHResult{}, err
	}
	clientInner := &tl.MTPClientDHInnerData{Nonce: nonce, ServerNonce: serverNonce, RetryID: retryID, GB: gbBytes}
	encoded, err := tl.Encode(clientInner)
	if err != nil {
		return ClientDHResult{}, fmt.Errorf("%w: encode: %v", ErrInvalidDHAnswer, err)
	}
	digest := sha1.Sum(encoded)
	plain := make([]byte, sha1.Size+len(encoded))
	copy(plain, digest[:])
	copy(plain[sha1.Size:], encoded)
	clear(encoded)
	padding := make([]byte, (16-len(plain)%16)%16)
	if _, err := io.ReadFull(random, padding); err != nil {
		return ClientDHResult{}, fmt.Errorf("%w: padding: %v", ErrInvalidDHAnswer, err)
	}
	plain = append(plain, padding...)
	key, iv := cryptoutil.DeriveNonceAESKeyIV(serverNonce, newNonce)
	block, err := cryptoutil.NewAES256(key[:])
	if err != nil {
		return ClientDHResult{}, err
	}
	if err := cryptoutil.EncryptIGE(plain, plain, block, iv[:]); err != nil {
		return ClientDHResult{}, err
	}
	authKey, err := NewAuthKey(sharedBytes, serverNonce, newNonce, int64(inner.ServerTime), now)
	clear(sharedBytes)
	if err != nil {
		return ClientDHResult{}, err
	}
	return ClientDHResult{Request: &tl.MTPSetClientDHParams{Nonce: nonce, ServerNonce: serverNonce, EncryptedData: plain}, AuthKey: authKey, GB: gbBytes}, nil
}

func fixedDHBytes(value *big.Int) ([]byte, error) {
	if value == nil || value.Sign() <= 0 || value.BitLen() > 2048 {
		return nil, ErrInvalidDHAnswer
	}
	output := make([]byte, 256)
	bytes := value.Bytes()
	copy(output[len(output)-len(bytes):], bytes)
	return output, nil
}

// DecryptServerDHParams decrypts and validates server_DH_inner_data from the
// temporary nonce-derived AES-IGE channel. The returned object is detached
// from the encrypted input and safe for the caller to retain.
func DecryptServerDHParams(random io.Reader, serverNonce [16]byte, newNonce [32]byte, nonce [16]byte, encrypted []byte) (*tl.MTPServerDHInnerData, error) {
	if len(encrypted) == 0 || len(encrypted) > maxEncryptedDHAnswer || len(encrypted)%16 != 0 {
		return nil, ErrInvalidDHAnswer
	}
	key, iv := cryptoutil.DeriveNonceAESKeyIV(serverNonce, newNonce)
	block, err := cryptoutil.NewAES256(key[:])
	clear(key[:])
	if err != nil {
		return nil, fmt.Errorf("%w: AES key: %v", ErrInvalidDHAnswer, err)
	}
	plain := make([]byte, len(encrypted))
	if err := cryptoutil.DecryptIGE(plain, encrypted, block, iv[:]); err != nil {
		return nil, fmt.Errorf("%w: decrypt: %v", ErrInvalidDHAnswer, err)
	}
	if len(plain) < sha1.Size {
		return nil, ErrDHAnswerIntegrity
	}
	inner, err := decodeDHInner(plain[sha1.Size:], plain[:sha1.Size])
	clear(plain)
	if err != nil {
		if errors.Is(err, ErrDHAnswerIntegrity) {
			return nil, ErrDHAnswerIntegrity
		}
		return nil, fmt.Errorf("%w: decode: %v", ErrInvalidDHAnswer, err)
	}
	value, ok := inner.(*tl.MTPServerDHInnerData)
	if !ok || value.Nonce != nonce || value.ServerNonce != serverNonce {
		return nil, ErrDHAnswerNonce
	}
	if len(value.DHPrime) == 0 || len(value.GA) == 0 {
		return nil, ErrInvalidDHAnswer
	}
	prime := new(big.Int).SetBytes(value.DHPrime)
	if err := cryptoutil.ValidateDHPrime(random, prime, int(value.G)); err != nil {
		return nil, fmt.Errorf("%w: prime: %v", ErrInvalidDHAnswer, err)
	}
	if err := cryptoutil.ValidateDHPublicValue(prime, new(big.Int).SetBytes(value.GA)); err != nil {
		return nil, fmt.Errorf("%w: g_a: %v", ErrInvalidDHAnswer, err)
	}
	return value, nil
}

func equalDigest(expected, payload []byte) bool {
	digest := sha1.Sum(payload)
	return subtle.ConstantTimeCompare(expected, digest[:]) == 1
}

func decodeDHInner(payload, expectedDigest []byte) (tl.Object, error) {
	for padding := 0; padding <= 15 && padding < len(payload); padding++ {
		candidate := payload[:len(payload)-padding]
		inner, err := tl.Decode(candidate, tl.DefaultDecodeLimits())
		if err == nil && equalDigest(expectedDigest, candidate) {
			return inner, nil
		}
	}
	return nil, ErrDHAnswerIntegrity
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
