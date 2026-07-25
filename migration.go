package raw

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/tgerr"
	"github.com/mtgo-labs/raw/tl"
)

type authorizationTransfer struct {
	done chan struct{}
	err  error
}

func isPrimaryMigration(rpcError *tgerr.Error) bool {
	return rpcError != nil && rpcError.IsOneOf(
		tgerr.ErrNetworkMigrate,
		tgerr.ErrPhoneMigrate,
		tgerr.ErrUserMigrate,
	)
}

func (client *Client) changePrimaryDC(ctx context.Context, targetDC int) error {
	if client == nil || ctx == nil || targetDC <= 0 {
		return ErrUnsupportedRoute
	}
	client.mu.Lock()
	if client.closed {
		client.mu.Unlock()
		return mtproto.ErrSessionClosed
	}
	if targetDC == client.config.DCID {
		client.mu.Unlock()
		return nil
	}
	client.mu.Unlock()
	if err := client.ensurePrimaryMigrationEndpoint(ctx, targetDC); err != nil {
		return err
	}

	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return mtproto.ErrSessionClosed
	}
	sourceDC := client.config.DCID
	if targetDC == sourceDC {
		return nil
	}
	if client.conn == nil || client.session == nil {
		return ErrNotConnected
	}
	address, ok := client.config.DCAddresses[targetDC]
	if !ok {
		return ErrUnsupportedRoute
	}
	auth, hasAuth := client.config.DCAuthKeys[targetDC]
	if hasAuth && auth.Expired(client.now()) {
		return ErrAuthKeyExpired
	}
	if !hasAuth && client.config.Store == nil {
		return ErrNoAuthKey
	}
	var key mtproto.AuthKey
	var err error
	if hasAuth {
		key, err = mtproto.RestoreAuthKey(auth.Key, auth.ID, auth.TimeOffset)
		if err != nil {
			return err
		}
	}
	sessionID := auth.SessionID
	if sessionID == [8]byte{} {
		if _, err := rand.Read(sessionID[:]); err != nil {
			return err
		}
	}

	targetRouteKey := routeKey{dcid: targetDC, kind: ConnectionMain, slot: 0}
	if retryAfter := client.connectionFloodLocked(targetRouteKey).admit(client.now()); retryAfter > 0 {
		return &ConnectionFloodError{RetryAfter: retryAfter}
	}
	if route := client.routes[targetRouteKey]; route != nil {
		delete(client.routes, targetRouteKey)
		client.stopRouteIdleTimerLocked(route)
		client.stopRouteLivenessLocked(targetRouteKey, route.session)
		route.sender.stopAndCancel(mtproto.ErrSessionClosed)
		route.session.Close(mtproto.ErrSessionClosed)
		_ = client.pool.Discard(mtproto.PoolKey{
			DCID: targetDC, Kind: mtproto.ConnectionMain, Slot: 0,
		}, route.connection)
	}
	targetPoolKey := mtproto.PoolKey{DCID: targetDC, Kind: mtproto.ConnectionMain, Slot: 0}
	connection, err := client.pool.Acquire(targetPoolKey, func() (net.Conn, error) {
		return client.dialPacket(ctx, address)
	})
	if err != nil {
		return err
	}
	if !hasAuth {
		sourceState := client.permanent
		if sourceState.key.ID == 0 {
			sourceState.key = client.session.AuthKey()
			sourceState.salt = client.session.Salt()
		}
		sourceState.sessionID = client.session.SessionID()
		key, err = mtproto.AuthorizePermanent(
			ctx,
			connection,
			client.authRandom,
			client.now,
			int32(targetDC),
			func(key mtproto.AuthKey) error {
				auth = AuthKeyConfig{
					Key:        append([]byte(nil), key.Key[:]...),
					ID:         key.ID,
					Salt:       int64(binary.LittleEndian.Uint64(key.Salt[:])),
					SessionID:  sessionID,
					TimeOffset: key.TimeOffset,
				}
				previous, hadPrevious := client.config.DCAuthKeys[targetDC]
				client.config.DCAuthKeys[targetDC] = auth
				if err := client.persistAuthStateLocked(ctx, sourceState); err != nil {
					if hadPrevious {
						client.config.DCAuthKeys[targetDC] = previous
					} else {
						delete(client.config.DCAuthKeys, targetDC)
					}
					return err
				}
				return nil
			},
		)
		if err != nil {
			_ = client.pool.Discard(targetPoolKey, connection)
			return err
		}
	}
	sessionState := mtproto.NewSession(key, auth.Salt, sessionID, client.config.PendingCapacity)

	client.writeMu.Lock()
	defer client.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		sessionState.Close(err)
		_ = client.pool.Discard(targetPoolKey, connection)
		return err
	}
	oldConnection, oldSession, oldPermanent := client.conn, client.session, client.permanent
	oldSender := client.sender
	oldAddress, oldError := client.config.Address, client.err
	oldAuthKey := append([]byte(nil), client.config.AuthKey...)
	oldAuthKeyID, oldAuthKeyTimeOffset := client.config.AuthKeyID, client.config.AuthKeyTimeOffset
	oldSalt, oldSessionID := client.config.Salt, client.config.SessionID
	oldTempUntil, oldPFS, oldOrdering := client.tempUntil, client.pfs, client.ordering
	oldInitConnectionDone := client.initConnectionDone
	oldSourceAuth, hadSourceAuth := client.config.DCAuthKeys[sourceDC]
	oldSourceAddress, hadSourceAddress := client.config.DCAddresses[sourceDC]
	oldTargetAuth := auth

	sourceKey, sourceSalt := oldPermanent.key, oldPermanent.salt
	if sourceKey.ID == 0 {
		sourceKey, sourceSalt = oldSession.AuthKey(), oldSession.Salt()
	}
	client.config.DCAuthKeys[sourceDC] = AuthKeyConfig{
		Key: append([]byte(nil), sourceKey.Key[:]...), ID: sourceKey.ID,
		Salt: sourceSalt, SessionID: oldSession.SessionID(),
		TimeOffset: sourceKey.TimeOffset,
	}
	client.config.DCAddresses[sourceDC] = oldAddress
	auth.SessionID = sessionID
	client.config.DCAuthKeys[targetDC] = auth
	client.config.DCID = targetDC
	client.config.Address = address
	client.config.AuthKey = append([]byte(nil), auth.Key...)
	client.config.AuthKeyID = auth.ID
	client.config.AuthKeyTimeOffset = auth.TimeOffset
	client.config.Salt = auth.Salt
	client.config.SessionID = sessionID
	client.conn = connection
	client.session = sessionState
	client.permanent = authState{key: key, salt: auth.Salt, sessionID: sessionID}
	client.tempUntil = 0
	client.pfs = nil
	client.ordering = nil
	client.initConnectionDone = false
	client.err = nil
	if err := client.saveStateLocked(); err != nil {
		client.config.DCID = sourceDC
		client.config.Address = oldAddress
		client.config.AuthKey = oldAuthKey
		client.config.AuthKeyID = oldAuthKeyID
		client.config.AuthKeyTimeOffset = oldAuthKeyTimeOffset
		client.config.Salt = oldSalt
		client.config.SessionID = oldSessionID
		if hadSourceAuth {
			client.config.DCAuthKeys[sourceDC] = oldSourceAuth
		} else {
			delete(client.config.DCAuthKeys, sourceDC)
		}
		if hadSourceAddress {
			client.config.DCAddresses[sourceDC] = oldSourceAddress
		} else {
			delete(client.config.DCAddresses, sourceDC)
		}
		client.config.DCAuthKeys[targetDC] = oldTargetAuth
		client.conn = oldConnection
		client.session = oldSession
		client.permanent = oldPermanent
		client.tempUntil = oldTempUntil
		client.pfs = oldPFS
		client.ordering = oldOrdering
		client.initConnectionDone = oldInitConnectionDone
		client.err = oldError
		sessionState.Close(err)
		_ = client.pool.Discard(targetPoolKey, connection)
		return err
	}

	client.stopRouteLivenessLocked(
		routeKey{dcid: sourceDC, kind: ConnectionMain, slot: 0},
		oldSession,
	)
	oldSender.stopAndCancel(mtproto.ErrSessionClosed)
	oldSession.Close(mtproto.ErrSessionClosed)
	_ = client.pool.Discard(mtproto.PoolKey{
		DCID: sourceDC, Kind: mtproto.ConnectionMain, Slot: 0,
	}, oldConnection)
	client.refreshRouteIdleTimersLocked()
	newPrimaryKey := routeKey{dcid: targetDC, kind: ConnectionMain, slot: 0}
	newPrimaryRoute := &clientRoute{connection: connection, session: sessionState}
	client.sender = client.startRouteSenderLocked(newPrimaryKey, sessionState, connection, &client.writeMu)
	newPrimaryRoute.sender = client.sender
	client.startRouteLivenessLocked(newPrimaryKey, sessionState, connection, &client.writeMu)
	client.startReceiveRouteLocked(newPrimaryKey, newPrimaryRoute)
	return nil
}

func (client *Client) ensurePrimaryMigrationEndpoint(ctx context.Context, targetDC int) error {
	client.mu.Lock()
	if client.closed {
		client.mu.Unlock()
		return mtproto.ErrSessionClosed
	}
	_, ok := client.config.DCAddresses[targetDC]
	client.mu.Unlock()
	if ok {
		return nil
	}
	config, err := invokeRoute(ctx, client, &tl.HelpGetConfigRequest{}, InvokeOptions{})
	if err != nil {
		return err
	}
	if err := client.RefreshEndpoints(config); err != nil {
		return err
	}
	client.mu.Lock()
	_, ok = client.config.DCAddresses[targetDC]
	client.mu.Unlock()
	if !ok {
		return ErrUnsupportedRoute
	}
	return nil
}

func (client *Client) connectMigrationRoute(ctx context.Context, targetDC int, options InvokeOptions) error {
	if err := client.ConnectDC(ctx, targetDC); err != nil {
		return err
	}
	if options.Kind == ConnectionMain && options.Slot == 0 {
		return nil
	}
	return client.ConnectDCSlot(ctx, targetDC, options.Kind, options.Slot)
}

func (client *Client) ensureAuthorizationTransferred(ctx context.Context, targetDC int) error {
	if client == nil || ctx == nil || targetDC <= 0 {
		return ErrAuthTransfer
	}
	transfer, owner := client.beginAuthorizationTransfer(targetDC)
	if !owner {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-transfer.done:
			return transfer.err
		}
	}
	err := client.transferAuthorization(ctx, targetDC)
	client.finishAuthorizationTransfer(targetDC, transfer, err)
	return err
}

func (client *Client) beginAuthorizationTransfer(targetDC int) (*authorizationTransfer, bool) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if transfer := client.authTransfers[targetDC]; transfer != nil {
		return transfer, false
	}
	if client.authTransfers == nil {
		client.authTransfers = make(map[int]*authorizationTransfer)
	}
	transfer := &authorizationTransfer{done: make(chan struct{})}
	client.authTransfers[targetDC] = transfer
	return transfer, true
}

func (client *Client) finishAuthorizationTransfer(targetDC int, transfer *authorizationTransfer, err error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.authTransfers[targetDC] != transfer {
		return
	}
	transfer.err = err
	close(transfer.done)
	delete(client.authTransfers, targetDC)
}

func (client *Client) transferAuthorization(ctx context.Context, targetDC int) error {
	return transferAuthorization(
		targetDC,
		func(request *tl.AuthExportAuthorizationRequest) (*tl.AuthExportedAuthorization, error) {
			return invokeRoute(ctx, client, request, InvokeOptions{})
		},
		func(request *tl.AuthImportAuthorizationRequest) (tl.AuthAuthorizationClass, error) {
			return invokeRoute(ctx, client, request, InvokeOptions{DCID: targetDC})
		},
	)
}

func transferAuthorization(
	targetDC int,
	export func(*tl.AuthExportAuthorizationRequest) (*tl.AuthExportedAuthorization, error),
	importAuthorization func(*tl.AuthImportAuthorizationRequest) (tl.AuthAuthorizationClass, error),
) error {
	if targetDC <= 0 || export == nil || importAuthorization == nil {
		return ErrAuthTransfer
	}
	exported, err := export(&tl.AuthExportAuthorizationRequest{DCID: int32(targetDC)})
	if err != nil {
		return fmt.Errorf("%w: export to DC %d: %w", ErrAuthTransfer, targetDC, err)
	}
	if exported == nil || exported.ID == 0 || len(exported.Bytes) == 0 {
		return ErrAuthTransfer
	}
	authorization, err := importAuthorization(&tl.AuthImportAuthorizationRequest{
		ID: exported.ID, Bytes: exported.Bytes,
	})
	if err != nil {
		return fmt.Errorf("%w: import to DC %d: %w", ErrAuthTransfer, targetDC, err)
	}
	if _, ok := authorization.(*tl.AuthAuthorization); !ok {
		return ErrAuthTransfer
	}
	return nil
}
