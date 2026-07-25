package mtproto

import (
	"crypto/subtle"
	"errors"

	"github.com/mtgo-labs/raw/tl"
)

var (
	ErrDHResultInvalid = errors.New("mtproto: invalid dh_gen result")
	ErrDHRetry         = errors.New("mtproto: server requested DH retry")
	ErrDHFail          = errors.New("mtproto: server rejected DH exchange")
)

// VerifyDHGenResult validates the final permanent-auth response. Retry and
// failure are returned as explicit errors so policy remains outside this
// protocol boundary.
func VerifyDHGenResult(authKey AuthKey, nonce, serverNonce [16]byte, newNonce [32]byte, result tl.MTPSetClientDHParamsAnswerClass) error {
	if result == nil {
		return ErrDHResultInvalid
	}
	switch value := result.(type) {
	case *tl.MTPDHGenOk:
		if value.Nonce != nonce || value.ServerNonce != serverNonce {
			return ErrDHResultInvalid
		}
		if !equalNonceHash(value.NewNonceHash1, NewNonceHash(newNonce, 1, authKey.AuxHash)) {
			return ErrDHResultInvalid
		}
		return nil
	case *tl.MTPDHGenRetry:
		if value.Nonce != nonce || value.ServerNonce != serverNonce || !equalNonceHash(value.NewNonceHash2, NewNonceHash(newNonce, 2, authKey.AuxHash)) {
			return ErrDHResultInvalid
		}
		return ErrDHRetry
	case *tl.MTPDHGenFail:
		if value.Nonce != nonce || value.ServerNonce != serverNonce || !equalNonceHash(value.NewNonceHash3, NewNonceHash(newNonce, 3, authKey.AuxHash)) {
			return ErrDHResultInvalid
		}
		return ErrDHFail
	default:
		return ErrDHResultInvalid
	}
}

func equalNonceHash(left, right [16]byte) bool {
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}
