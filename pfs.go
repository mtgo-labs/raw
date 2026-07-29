package raw

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/tgerr"
	"github.com/mtgo-labs/raw/tl"
)

// PFSBinding owns one permanent key and its current temporary replacement.
type PFSBinding struct {
	mu        sync.RWMutex
	state     *mtproto.PFSBinding
	createdAt int64
	temporary AuthKeyConfig
}

func NewPFSBinding(permanent AuthKeyConfig) (*PFSBinding, error) {
	key, err := mtproto.RestoreAuthKey(permanent.Key, permanent.ID, 0)
	if err != nil {
		return nil, err
	}
	state, err := mtproto.NewPFSBinding(key)
	if err != nil {
		return nil, err
	}
	return &PFSBinding{state: state, createdAt: permanent.CreatedAt}, nil
}

// InstallTemporary replaces any previous temporary key for this permanent
// binding. The key remains in memory and is never added to the session store.
func (binding *PFSBinding) InstallTemporary(auth AuthKeyConfig) error {
	if binding == nil || binding.state == nil || auth.ExpiresAt == 0 {
		return ErrInvalidConfig
	}
	key, err := mtproto.RestoreAuthKey(auth.Key, auth.ID, 0)
	if err != nil {
		return err
	}
	if err := binding.state.InstallTemporary(key, auth.SessionID, time.Unix(auth.ExpiresAt, 0)); err != nil {
		return err
	}
	auth.Key = append([]byte(nil), auth.Key...)
	binding.mu.Lock()
	binding.temporary = auth
	binding.mu.Unlock()
	return nil
}

func (binding *PFSBinding) temporaryAt(now time.Time) (AuthKeyConfig, error) {
	if binding == nil || binding.state == nil {
		return AuthKeyConfig{}, ErrInvalidConfig
	}
	binding.mu.RLock()
	auth := binding.temporary
	binding.mu.RUnlock()
	if auth.ID == 0 {
		return AuthKeyConfig{}, ErrNoAuthKey
	}
	if auth.Expired(now) {
		return AuthKeyConfig{}, ErrAuthKeyExpired
	}
	return auth, nil
}

func (binding *PFSBinding) clearTemporary() {
	if binding == nil {
		return
	}
	binding.state.ClearTemporary()
	binding.mu.Lock()
	binding.temporary = AuthKeyConfig{}
	binding.mu.Unlock()
}

// BindTemporaryAuthKey activates a temporary key on an existing route and
// sends auth.bindTempAuthKey with matching inner and outer message IDs.
func (client *Client) BindTemporaryAuthKey(ctx context.Context, dcid int, kind ConnectionKind, binding *PFSBinding) error {
	return client.BindTemporaryAuthKeyWithOptions(ctx, InvokeOptions{DCID: dcid, Kind: kind}, binding)
}

func (client *Client) BindTemporaryAuthKeyWithOptions(ctx context.Context, options InvokeOptions, binding *PFSBinding) error {
	if client == nil || ctx == nil || binding == nil || binding.state == nil || options.Kind > ConnectionDownload || options.Slot < 0 {
		return ErrInvalidConfig
	}
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		err := client.bindTemporaryAuthKeyOnce(ctx, options, binding)
		if !tgerr.IsEncryptedMessageInvalid(err) {
			return err
		}
		last = err
		now := client.now().Unix()
		if binding.createdAt != 0 && now-binding.createdAt > 60 {
			binding.clearTemporary()
			return fmt.Errorf("%w: %v", ErrPFSKeysInvalid, err)
		}
	}
	return last
}

func (client *Client) bindTemporaryAuthKeyOnce(ctx context.Context, options InvokeOptions, binding *PFSBinding) error {
	auth, err := binding.temporaryAt(client.now())
	if err != nil {
		return err
	}
	temporary, err := mtproto.RestoreAuthKey(auth.Key, auth.ID, 0)
	if err != nil {
		return err
	}
	if temporary.ID != binding.state.TemporaryID() {
		return mtproto.ErrInvalidPFSBinding
	}
	if options.DCID == 0 {
		options.DCID = client.config.DCID
	}
	client.markPFSRequired(options)

	sessionState, writeMu, oldKey, oldSalt, oldUntil, err := client.activatePFSRoute(options.DCID, options.Kind, options.Slot, temporary, auth)
	if err != nil {
		return err
	}
	rollback := func() {
		client.rollbackPFSRoute(options.DCID, options.Kind, options.Slot, temporary.ID, oldKey, oldSalt, oldUntil)
	}

	writeMu.Lock()
	messageID, err := sessionState.SendPFSBind(sessionWriter(client, options.DCID, options.Kind, options.Slot), rand.Reader, client.now(), binding.state)
	writeMu.Unlock()
	if err != nil {
		rollback()
		return err
	}
	pending, waitErr := sessionState.Wait(ctx, messageID)
	if waitErr != nil && pending == nil {
		rollback()
		return waitErr
	}
	if pending.Result.Err != nil {
		rollback()
		return pending.Result.Err
	}
	accepted, err := tl.DecodeResult(&tl.AuthBindTempAuthKeyRequest{}, pending.Result.Body, tl.DefaultDecodeLimits())
	if err != nil {
		rollback()
		return err
	}
	if !accepted {
		rollback()
		return ErrPFSBindRejected
	}
	if err := binding.state.MarkBound(); err != nil {
		rollback()
		return err
	}
	client.markPFSRoute(options, binding)
	return nil
}

// ReconnectTemporaryAuthKey reconnects one session slot and binds the newly
// installed temporary key before that slot is used for ordinary RPCs.
func (client *Client) ReconnectTemporaryAuthKey(ctx context.Context, options InvokeOptions, binding *PFSBinding) error {
	if client == nil || ctx == nil || binding == nil {
		return ErrInvalidConfig
	}
	if _, err := binding.temporaryAt(client.now()); err != nil {
		return err
	}
	if options.DCID == 0 {
		options.DCID = client.config.DCID
	}
	client.markPFSRequired(options)
	client.disconnectPFSRoute(options)
	if err := client.ConnectDCSlot(ctx, options.DCID, options.Kind, options.Slot); err != nil {
		return err
	}
	return client.BindTemporaryAuthKeyWithOptions(ctx, options, binding)
}

func (client *Client) markPFSRoute(options InvokeOptions, binding *PFSBinding) {
	if options.DCID == 0 {
		options.DCID = client.config.DCID
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if options.DCID == client.config.DCID && options.Kind == ConnectionMain && options.Slot == 0 {
		client.pfs = binding
		client.err = nil
		delete(client.pfsInvalid, routeKey{dcid: options.DCID, kind: options.Kind, slot: options.Slot})
		return
	}
	if route := client.routes[routeKey{dcid: options.DCID, kind: options.Kind, slot: options.Slot}]; route != nil {
		route.pfs = binding
		delete(client.pfsInvalid, routeKey{dcid: options.DCID, kind: options.Kind, slot: options.Slot})
	}
}

func (client *Client) invalidatePFSRoute(key routeKey, route *clientRoute) bool {
	client.mu.Lock()
	var binding *PFSBinding
	if key.dcid == client.config.DCID && key.kind == ConnectionMain && key.slot == 0 {
		binding = client.pfs
		if binding == nil || client.session != route.session {
			client.mu.Unlock()
			return false
		}
		client.stopRouteLivenessLocked(key, route.session)
		_ = client.saveStateLocked()
		client.conn = nil
		client.session = nil
		client.sender = nil
		client.pfs = nil
		client.tempUntil = 0
		client.err = ErrPFSRebindRequired
		if client.pfsInvalid == nil {
			client.pfsInvalid = make(map[routeKey]struct{})
		}
		client.pfsInvalid[key] = struct{}{}
	} else {
		current := client.routes[key]
		if current != route || current.pfs == nil {
			client.mu.Unlock()
			return false
		}
		binding = current.pfs
		delete(client.routes, key)
		client.stopRouteIdleTimerLocked(current)
		client.stopRouteLivenessLocked(key, current.session)
		if client.pfsInvalid == nil {
			client.pfsInvalid = make(map[routeKey]struct{})
		}
		client.pfsInvalid[key] = struct{}{}
	}
	client.mu.Unlock()
	binding.clearTemporary()
	route.sender.stopAndCancel(ErrPFSRebindRequired)
	route.session.Close(ErrPFSRebindRequired)
	_ = client.pool.Discard(mtproto.PoolKey{
		DCID: key.dcid, Kind: mtproto.ConnectionKind(key.kind), Slot: key.slot,
	}, route.connection)
	return true
}

func (client *Client) markPFSRequired(options InvokeOptions) {
	if options.DCID == 0 {
		options.DCID = client.config.DCID
	}
	client.mu.Lock()
	if client.pfsInvalid == nil {
		client.pfsInvalid = make(map[routeKey]struct{})
	}
	client.pfsInvalid[routeKey{dcid: options.DCID, kind: options.Kind, slot: options.Slot}] = struct{}{}
	client.mu.Unlock()
}

func (client *Client) disconnectPFSRoute(options InvokeOptions) {
	client.mu.Lock()
	key := routeKey{dcid: options.DCID, kind: options.Kind, slot: options.Slot}
	var route *clientRoute
	if options.DCID == client.config.DCID && options.Kind == ConnectionMain && options.Slot == 0 {
		if client.session != nil && client.conn != nil {
			route = &clientRoute{connection: client.conn, session: client.session, sender: client.sender}
			_ = client.saveStateLocked()
		}
		client.stopRouteLivenessLocked(key, client.session)
		client.conn = nil
		client.session = nil
		client.sender = nil
		client.pfs = nil
		client.tempUntil = 0
	} else {
		route = client.routes[key]
		delete(client.routes, key)
		client.stopRouteIdleTimerLocked(route)
		if route != nil {
			client.stopRouteLivenessLocked(key, route.session)
		}
	}
	client.mu.Unlock()
	if route == nil {
		return
	}
	route.sender.stopAndCancel(ErrPFSRebindRequired)
	route.session.Close(ErrPFSRebindRequired)
	_ = client.pool.Discard(mtproto.PoolKey{
		DCID: key.dcid, Kind: mtproto.ConnectionKind(key.kind), Slot: key.slot,
	}, route.connection)
}

func (client *Client) activatePFSRoute(dcid int, kind ConnectionKind, slot int, temporary mtproto.AuthKey, auth AuthKeyConfig) (*mtproto.Session, *sync.Mutex, mtproto.AuthKey, int64, int64, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return nil, nil, mtproto.AuthKey{}, 0, 0, mtproto.ErrSessionClosed
	}
	if dcid == client.config.DCID && kind == ConnectionMain && slot == 0 {
		if client.session == nil {
			return nil, nil, mtproto.AuthKey{}, 0, 0, ErrNotConnected
		}
		oldKey, oldSalt, oldUntil := client.session.AuthKey(), client.session.Salt(), client.tempUntil
		if err := client.session.ReplaceAuthKeyWithSalt(temporary, auth.Salt); err != nil {
			return nil, nil, mtproto.AuthKey{}, 0, 0, err
		}
		client.tempUntil = auth.ExpiresAt
		return client.session, &client.writeMu, oldKey, oldSalt, oldUntil, nil
	}
	route := client.routes[routeKey{dcid: dcid, kind: kind, slot: slot}]
	if route == nil {
		return nil, nil, mtproto.AuthKey{}, 0, 0, ErrNotConnected
	}
	oldKey, oldSalt, oldUntil := route.session.AuthKey(), route.session.Salt(), route.tempUntil
	if err := route.session.ReplaceAuthKeyWithSalt(temporary, auth.Salt); err != nil {
		return nil, nil, mtproto.AuthKey{}, 0, 0, err
	}
	route.tempUntil = auth.ExpiresAt
	return route.session, &route.writeMu, oldKey, oldSalt, oldUntil, nil
}

func (client *Client) rollbackPFSRoute(dcid int, kind ConnectionKind, slot int, temporaryID uint64, oldKey mtproto.AuthKey, oldSalt, oldUntil int64) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if dcid == client.config.DCID && kind == ConnectionMain && slot == 0 {
		if client.session != nil && client.session.AuthKey().ID == temporaryID {
			_ = client.session.ReplaceAuthKeyWithSalt(oldKey, oldSalt)
			client.tempUntil = oldUntil
		}
		return
	}
	route := client.routes[routeKey{dcid: dcid, kind: kind, slot: slot}]
	if route != nil && route.session.AuthKey().ID == temporaryID {
		_ = route.session.ReplaceAuthKeyWithSalt(oldKey, oldSalt)
		route.tempUntil = oldUntil
	}
}

func sessionWriter(client *Client, dcid int, kind ConnectionKind, slot int) interface{ Write([]byte) (int, error) } {
	client.mu.Lock()
	defer client.mu.Unlock()
	if dcid == client.config.DCID && kind == ConnectionMain && slot == 0 {
		return client.conn
	}
	route := client.routes[routeKey{dcid: dcid, kind: kind, slot: slot}]
	if route == nil {
		return nil
	}
	return route.connection
}

// routeNeedsPFSLocked reports whether the route at key requires a PFS
// (re)negotiation: no binding exists, the temp key expired, or the server
// invalidated it (404). The caller must hold client.mu.
func (client *Client) routeNeedsPFSLocked(key routeKey) bool {
	if !client.config.PFS.Enabled {
		return false
	}
	if _, invalid := client.pfsInvalid[key]; invalid {
		return true
	}
	if key.dcid == client.config.DCID && key.kind == ConnectionMain && key.slot == 0 {
		if client.pfs == nil {
			return true
		}
		return client.tempUntil != 0 && client.tempUntil <= client.now().Unix()
	}
	route := client.routes[key]
	if route == nil {
		return false
	}
	if route.pfs == nil {
		return true
	}
	return route.tempUntil != 0 && route.tempUntil <= client.now().Unix()
}

// pfsBindingLocked returns the existing PFSBinding for the route, or creates
// a new one from the permanent key. The caller must hold client.mu.
func (client *Client) pfsBindingLocked(key routeKey) *PFSBinding {
	if key.dcid == client.config.DCID && key.kind == ConnectionMain && key.slot == 0 {
		if client.pfs != nil {
			return client.pfs
		}
	} else if route := client.routes[key]; route != nil && route.pfs != nil {
		return route.pfs
	}
	if client.permanent.key.ID == 0 {
		return nil
	}
	binding, err := NewPFSBinding(AuthKeyConfig{
		Key: append([]byte(nil), client.permanent.key.Key[:]...),
		ID:  client.permanent.key.ID,
	})
	if err != nil {
		return nil
	}
	return binding
}

// routeConnectedLocked reports whether the route still has a live session and
// connection. The caller must hold client.mu.
func (client *Client) routeConnectedLocked(key routeKey) bool {
	if key.dcid == client.config.DCID && key.kind == ConnectionMain && key.slot == 0 {
		return client.conn != nil && client.session != nil
	}
	route := client.routes[key]
	return route != nil && route.connection != nil && route.session != nil
}

// pfsLifetimeSeconds returns the configured temp key lifetime, clamped to
// [1, 86400] seconds.
func (client *Client) pfsLifetimeSeconds() int32 {
	lifetime := client.config.PFS.Lifetime
	if lifetime <= 0 || lifetime > 24*time.Hour {
		lifetime = 24 * time.Hour
	}
	seconds := int32(lifetime / time.Second)
	if seconds <= 0 {
		seconds = 86400
	}
	return seconds
}

// negotiateTempAuthKey performs a DH exchange over a freshly dialed plain
// connection to obtain one temporary authorization key. The connection is
// closed after the exchange; it cannot be reused for session traffic.
func (client *Client) negotiateTempAuthKey(ctx context.Context, dcid int, expiresIn int32) (AuthKeyConfig, error) {
	address := client.config.Address
	if endpoint, ok := client.config.DCAddresses[dcid]; ok {
		address = endpoint
	} else if dcid != client.config.DCID {
		if addr, ok := defaultTelegramAddress(dcid, client.config.TestMode); ok {
			address = addr
		}
	}
	connection, err := client.dialPacket(ctx, address)
	if err != nil {
		return AuthKeyConfig{}, err
	}
	key, err := mtproto.AuthorizeTemp(ctx, connection, client.authRandom, client.now, int32(dcid), expiresIn)
	_ = connection.Close()
	if err != nil {
		return AuthKeyConfig{}, err
	}
	var sessionID [8]byte
	if _, err := io.ReadFull(rand.Reader, sessionID[:]); err != nil {
		return AuthKeyConfig{}, err
	}
	keyBytes := make([]byte, 256)
	copy(keyBytes, key.Key[:])
	return AuthKeyConfig{
		Key:        keyBytes,
		ID:         key.ID,
		SessionID:  sessionID,
		TimeOffset: key.TimeOffset,
		ExpiresAt:  client.now().Unix() + int64(expiresIn),
	}, nil
}

// connectPFS negotiates a temporary authorization key for the route identified
// by options and binds it to the permanent key. It serializes concurrent PFS
// negotiations for the same client via pfsMu. The client's mutex (client.mu)
// must NOT be held.
func (client *Client) connectPFS(ctx context.Context, options InvokeOptions) error {
	client.pfsMu.Lock()
	defer client.pfsMu.Unlock()

	if options.DCID == 0 {
		options.DCID = client.config.DCID
	}
	selectedKey := routeKey{dcid: options.DCID, kind: options.Kind, slot: options.Slot}

	// Re-check under client.mu — another goroutine may have completed PFS.
	client.mu.Lock()
	if !client.routeNeedsPFSLocked(selectedKey) {
		client.mu.Unlock()
		return nil
	}
	binding := client.pfsBindingLocked(selectedKey)
	salt := client.permanent.salt
	if s := client.routeSessionSaltLocked(selectedKey); s != 0 {
		salt = s
	}
	connected := client.routeConnectedLocked(selectedKey)
	client.mu.Unlock()

	if binding == nil {
		return ErrInvalidConfig
	}

	expiresIn := client.pfsLifetimeSeconds()
	auth, err := client.negotiateTempAuthKey(ctx, options.DCID, expiresIn)
	if err != nil {
		return err
	}
	auth.Salt = salt

	if err := binding.InstallTemporary(auth); err != nil {
		return err
	}
	if connected {
		return client.BindTemporaryAuthKeyWithOptions(ctx, options, binding)
	}
	return client.ReconnectTemporaryAuthKey(ctx, options, binding)
}

// routeSessionSaltLocked returns the live session's server salt, or zero if
// the route has no active session. The caller must hold client.mu.
func (client *Client) routeSessionSaltLocked(key routeKey) int64 {
	if key.dcid == client.config.DCID && key.kind == ConnectionMain && key.slot == 0 {
		if client.session != nil {
			return client.session.Salt()
		}
		return 0
	}
	if route := client.routes[key]; route != nil && route.session != nil {
		return route.session.Salt()
	}
	return 0
}
