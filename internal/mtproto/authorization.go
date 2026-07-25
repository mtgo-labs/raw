package mtproto

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"github.com/mtgo-labs/raw/tl"
)

const (
	maxAuthorizationBody = 4096
	maxDHGenAttempts     = 3
)

var (
	ErrInvalidAuthorization    = errors.New("mtproto: invalid authorization state")
	ErrAuthorizationResponse   = errors.New("mtproto: unexpected authorization response")
	ErrAuthorizationRetryLimit = errors.New("mtproto: DH retry limit reached")
)

// AuthorizePermanent negotiates and persists one permanent MTProto
// authorization key over a newly connected plain transport. It performs no
// reconnects and returns only after the successful key has been stored.
func AuthorizePermanent(
	ctx context.Context,
	connection net.Conn,
	random io.Reader,
	now func() time.Time,
	dcID int32,
	store AuthKeyStore,
) (AuthKey, error) {
	if ctx == nil || connection == nil || dcID <= 0 {
		return AuthKey{}, ErrInvalidAuthorization
	}
	if store == nil {
		return AuthKey{}, ErrNilAuthKeyStore
	}
	if err := ctx.Err(); err != nil {
		return AuthKey{}, err
	}
	if random == nil {
		random = rand.Reader
	}
	if now == nil {
		now = time.Now
	}

	stopCancellation := context.AfterFunc(ctx, func() {
		_ = connection.SetDeadline(time.Now())
	})
	defer func() {
		stopCancellation()
		_ = connection.SetDeadline(time.Time{})
	}()

	exchange := authorizationExchange{
		ctx:        ctx,
		connection: connection,
		now:        now,
	}
	var nonce [16]byte
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		return AuthKey{}, fmt.Errorf("%w: generate nonce: %v", ErrInvalidAuthorization, err)
	}
	if err := exchange.send(&tl.MTPReqPQMulti{Nonce: nonce}); err != nil {
		return AuthKey{}, err
	}
	object, err := exchange.receive()
	if err != nil {
		return AuthKey{}, err
	}
	resPQ, ok := object.(*tl.MTPResPQ)
	if !ok {
		return AuthKey{}, fmt.Errorf("%w: expected resPQ, got %T", ErrAuthorizationResponse, object)
	}
	selection, err := ValidateResPQ(random, nonce, resPQ, false)
	if err != nil {
		return AuthKey{}, err
	}

	var newNonce [32]byte
	if _, err := io.ReadFull(random, newNonce[:]); err != nil {
		return AuthKey{}, fmt.Errorf("%w: generate new nonce: %v", ErrInvalidAuthorization, err)
	}
	requestDH, err := BuildPQInnerData(random, selection, resPQ.PQ, nonce, resPQ.ServerNonce, newNonce, dcID)
	if err != nil {
		return AuthKey{}, err
	}
	if err := exchange.send(requestDH); err != nil {
		return AuthKey{}, err
	}
	object, err = exchange.receive()
	if err != nil {
		return AuthKey{}, err
	}
	serverDH, ok := object.(*tl.MTPServerDHParamsOk)
	if !ok || serverDH.Nonce != nonce || serverDH.ServerNonce != resPQ.ServerNonce {
		return AuthKey{}, fmt.Errorf("%w: expected server_DH_params_ok, got %T", ErrAuthorizationResponse, object)
	}
	inner, err := DecryptServerDHParams(random, resPQ.ServerNonce, newNonce, nonce, serverDH.EncryptedAnswer)
	if err != nil {
		return AuthKey{}, err
	}

	var retryID int64
	for attempt := range maxDHGenAttempts {
		clientDH, err := BuildClientDH(random, nonce, resPQ.ServerNonce, newNonce, retryID, now(), inner)
		if err != nil {
			return AuthKey{}, err
		}
		if err := exchange.send(clientDH.Request); err != nil {
			clear(clientDH.AuthKey.Key[:])
			return AuthKey{}, err
		}
		object, err = exchange.receive()
		if err != nil {
			clear(clientDH.AuthKey.Key[:])
			return AuthKey{}, err
		}
		answer, ok := object.(tl.MTPSetClientDHParamsAnswerClass)
		if !ok {
			clear(clientDH.AuthKey.Key[:])
			return AuthKey{}, fmt.Errorf("%w: expected set_client_DH_params answer, got %T", ErrAuthorizationResponse, object)
		}
		err = FinalizeAuthKey(clientDH.AuthKey, nonce, resPQ.ServerNonce, newNonce, answer, store)
		if err == nil {
			return clientDH.AuthKey, nil
		}
		if !errors.Is(err, ErrDHRetry) {
			clear(clientDH.AuthKey.Key[:])
			return AuthKey{}, err
		}
		retryID = int64(clientDH.AuthKey.AuxHash)
		clear(clientDH.AuthKey.Key[:])
		if attempt == maxDHGenAttempts-1 {
			return AuthKey{}, ErrAuthorizationRetryLimit
		}
	}
	return AuthKey{}, ErrAuthorizationRetryLimit
}

type authorizationExchange struct {
	ctx           context.Context
	connection    net.Conn
	now           func() time.Time
	lastMessageID uint64
}

func (exchange *authorizationExchange) send(object tl.Object) error {
	messageID := ClientMessageID(exchange.now())
	if messageID <= exchange.lastMessageID {
		if exchange.lastMessageID > math.MaxUint64-4 {
			return ErrInvalidAuthorization
		}
		messageID = exchange.lastMessageID + 4
	}
	if _, err := sendPlainObject(exchange.connection, messageID, object); err != nil {
		if contextErr := exchange.ctx.Err(); contextErr != nil {
			return contextErr
		}
		return err
	}
	exchange.lastMessageID = messageID
	return nil
}

func (exchange *authorizationExchange) receive() (tl.Object, error) {
	object, _, err := ReceivePlainObject(exchange.connection, maxAuthorizationBody)
	if err != nil {
		if contextErr := exchange.ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, err
	}
	return object, nil
}
