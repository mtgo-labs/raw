package raw

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/internal/transport"
	"github.com/mtgo-labs/raw/session"
	"github.com/mtgo-labs/raw/tl"
)

const (
	defaultDCID              = 2
	defaultProductionAddress = "149.154.167.50:443"
	defaultTestAddress       = "149.154.167.40:443"
	defaultPendingCapacity   = 128
	defaultMaxPayload        = 16 << 20
	defaultUpdateBuffer      = 64
	defaultPoolSize          = 1
	defaultPoolIdleTimeout   = time.Minute
	defaultDeviceModel       = "mtgo-labs/raw"
	defaultAppVersion        = "0.0.0"
	defaultLanguageCode      = "en"
	defaultReconnectAttempts = 5
	defaultReconnectDelay    = 500 * time.Millisecond
	defaultReconnectMaxDelay = 30 * time.Second
	defaultPingInterval      = time.Minute
	defaultPongTimeout       = 15 * time.Second
)

func defaultTelegramAddress(dcid int, testMode bool) (string, bool) {
	if testMode {
		switch dcid {
		case 1:
			return "149.154.175.10:443", true
		case 2:
			return defaultTestAddress, true
		case 3:
			return "149.154.175.117:443", true
		default:
			return "", false
		}
	}
	switch dcid {
	case 1:
		return "149.154.175.50:443", true
	case 2:
		return defaultProductionAddress, true
	case 3:
		return "149.154.175.100:443", true
	case 4:
		return "149.154.167.91:443", true
	case 5:
		return "91.108.56.165:443", true
	default:
		return "", false
	}
}

type Client struct {
	mu                 sync.Mutex
	pfsMu              sync.Mutex
	writeMu            sync.Mutex
	sendMu             sync.Mutex
	sendWG             sync.WaitGroup
	receiveWG          sync.WaitGroup
	reconnectWG        sync.WaitGroup
	livenessWG         sync.WaitGroup
	config             Config
	conn               net.Conn
	sender             *routeSender
	session            *mtproto.Session
	done               chan struct{}
	err                error
	closed             bool
	updates            chan tl.UpdatesClass
	pool               *mtproto.ConnectionPool
	httpClient         *http.Client
	routes             map[routeKey]*clientRoute
	endpoints          *mtproto.EndpointTable
	now                func() time.Time
	authRandom         io.Reader
	permanent          authState
	tempUntil          int64
	tmpSessions        int32
	ordering           map[string]uint64
	initConnectionDone bool
	authTransfers      map[int]*authorizationTransfer
	pfs                *PFSBinding
	pfsInvalid         map[routeKey]struct{}
	connectFlood       map[routeKey]*connectionFloodControl
	reconnects         map[routeKey]*clientReconnect
	reconnectCtx       context.Context
	stopReconnect      context.CancelFunc
	reconnectDelay     func(int) time.Duration
	liveness           map[routeKey]*routeLiveness
	pingJitter         func() time.Duration
	nextPingID         func() (int64, error)
	floodWait          *floodWaitStore
}

type routeKey struct {
	dcid int
	kind ConnectionKind
	slot int
}

type clientRoute struct {
	connection         net.Conn
	sendMu             sync.Mutex
	session            *mtproto.Session
	writeMu            sync.Mutex
	tempUntil          int64
	ordering           map[string]uint64
	initConnectionDone bool
	pfs                *PFSBinding
	idle               *routeIdleTimer
	sender             *routeSender
}

func (client *Client) startRouteSenderLocked(
	key routeKey,
	sessionState *mtproto.Session,
	connection net.Conn,
	writeMu *sync.Mutex,
) *routeSender {
	sender := newRouteSender(
		writeMu,
		sessionState,
		connection,
		client.now,
		client.config.PendingCapacity,
		func(err error) {
			client.failConnectedRoute(key, sessionState, connection, err)
		},
	)
	client.sendWG.Add(1)
	go func() {
		defer client.sendWG.Done()
		sender.run()
	}()
	return sender
}

type authState struct {
	key       mtproto.AuthKey
	salt      int64
	sessionID [8]byte
}

func NewClient(config Config) (*Client, error) {
	if err := applySessionString(&config); err != nil {
		return nil, err
	}
	if config.DCID == 0 {
		config.DCID = defaultDCID
	}
	if config.Address == "" {
		if address := config.DCAddresses[config.DCID]; address != "" {
			config.Address = address
		} else if address, ok := defaultTelegramAddress(config.DCID, config.TestMode); ok {
			config.Address = address
		}
	}
	if config.Store == nil && config.InMemory {
		config.Store = session.NewMemoryStore()
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	if config.PendingCapacity == 0 {
		config.PendingCapacity = defaultPendingCapacity
	}
	if config.MaxPayload == 0 {
		config.MaxPayload = defaultMaxPayload
	}
	if !config.NoUpdates && config.UpdateBuffer == 0 {
		config.UpdateBuffer = defaultUpdateBuffer
	}
	if config.PoolSize == 0 {
		config.PoolSize = defaultPoolSize
	}
	if config.PoolIdleTimeout == 0 {
		config.PoolIdleTimeout = defaultPoolIdleTimeout
	}
	if config.Retry.MaxAttempts == 0 {
		config.Retry.MaxAttempts = 1
	}
	if config.Reconnect.MaxAttempts == 0 {
		config.Reconnect.MaxAttempts = defaultReconnectAttempts
	}
	if config.Reconnect.InitialDelay == 0 {
		config.Reconnect.InitialDelay = defaultReconnectDelay
	}
	if config.Reconnect.MaxDelay == 0 {
		config.Reconnect.MaxDelay = defaultReconnectMaxDelay
	}
	if config.Reconnect.MaxDelay < config.Reconnect.InitialDelay {
		return nil, ErrInvalidConfig
	}
	if config.Liveness.PingInterval == 0 {
		config.Liveness.PingInterval = defaultPingInterval
	}
	if config.Liveness.PongTimeout == 0 {
		config.Liveness.PongTimeout = defaultPongTimeout
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.InitConnection.DeviceModel == "" {
		config.InitConnection.DeviceModel = defaultDeviceModel
	}
	if config.InitConnection.SystemVersion == "" {
		config.InitConnection.SystemVersion = runtime.GOOS + "/" + runtime.GOARCH
	}
	if config.InitConnection.AppVersion == "" {
		config.InitConnection.AppVersion = defaultAppVersion
	}
	if config.InitConnection.SystemLanguageCode == "" {
		config.InitConnection.SystemLanguageCode = defaultLanguageCode
	}
	if config.InitConnection.LanguageCode == "" {
		config.InitConnection.LanguageCode = defaultLanguageCode
	}
	config.AuthKey = append([]byte(nil), config.AuthKey...)
	if config.DCAddresses != nil {
		addresses := make(map[int]string, len(config.DCAddresses))
		maps.Copy(addresses, config.DCAddresses)
		config.DCAddresses = addresses
	}
	authKeys := make(map[int]AuthKeyConfig, len(config.DCAuthKeys))
	for id, auth := range config.DCAuthKeys {
		auth.Key = append([]byte(nil), auth.Key...)
		authKeys[id] = auth
	}
	config.DCAuthKeys = authKeys
	endpoints := mtproto.NewEndpointTable()
	_ = endpoints.Set(mtproto.DCEndpoint{ID: config.DCID, Address: config.Address})
	for id, address := range config.DCAddresses {
		_ = endpoints.Set(mtproto.DCEndpoint{ID: id, Address: address})
	}
	reconnectCtx, stopReconnect := context.WithCancel(context.Background())
	var updates chan tl.UpdatesClass
	if !config.NoUpdates {
		updates = make(chan tl.UpdatesClass, config.UpdateBuffer)
	}
	client := &Client{
		config:        config,
		done:          make(chan struct{}),
		updates:       updates,
		pool:          mtproto.NewConnectionPool(config.PoolSize),
		routes:        make(map[routeKey]*clientRoute),
		endpoints:     endpoints,
		now:           time.Now,
		tmpSessions:   1,
		connectFlood:  make(map[routeKey]*connectionFloodControl),
		reconnects:    make(map[routeKey]*clientReconnect),
		reconnectCtx:  reconnectCtx,
		stopReconnect: stopReconnect,
		liveness:      make(map[routeKey]*routeLiveness),
		floodWait:     newFloodWaitStore(),
	}
	if config.Transport == TransportHTTP {
		client.httpClient = &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:          1,
				MaxIdleConnsPerHost:   1,
				IdleConnTimeout:       90 * time.Second,
				DisableCompression:    true,
				ResponseHeaderTimeout: 30 * time.Second,
			},
		}
	}
	client.reconnectDelay = client.defaultReconnectDelay
	client.pingJitter = client.defaultPingJitter
	client.nextPingID = randomPingID
	return client, nil
}

func (client *Client) RefreshEndpoints(config *tl.Config) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	if err := mtproto.RefreshEndpoints(client.endpoints, config); err != nil {
		return err
	}
	addresses := make(map[int]string)
	for _, endpoint := range client.endpoints.Snapshot() {
		addresses[endpoint.ID] = endpoint.Address
	}
	client.config.DCAddresses = addresses
	client.tmpSessions = 1
	if config.TmpSessions != nil && *config.TmpSessions > 0 {
		client.tmpSessions = *config.TmpSessions
	}
	return nil
}

// TemporarySessionLimit reports the parallel temporary-session count
// advertised by help.getConfig. The default is one.
func (client *Client) TemporarySessionLimit() int {
	if client == nil {
		return 0
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	return int(client.tmpSessions)
}

// ConnectConfiguredSessions opens the parallel main-session slots advertised
// by help.getConfig. Each slot has independent MTProto state and write
// ownership and can be selected through InvokeOptions.Slot.
func (client *Client) ConnectConfiguredSessions(ctx context.Context) error {
	if err := client.Connect(ctx); err != nil {
		return err
	}
	limit := client.TemporarySessionLimit()
	for slot := 1; slot < limit; slot++ {
		if err := client.ConnectDCSlot(ctx, client.config.DCID, ConnectionMain, slot); err != nil {
			return err
		}
	}
	return nil
}

func (client *Client) ConnectDC(ctx context.Context, dcid int) error {
	return client.ConnectDCWithKind(ctx, dcid, ConnectionMain)
}

func (client *Client) ConnectDCWithKind(ctx context.Context, dcid int, kind ConnectionKind) error {
	return client.ConnectDCSlot(ctx, dcid, kind, 0)
}

func (client *Client) ConnectDCSlot(ctx context.Context, dcid int, kind ConnectionKind, slot int) error {
	if kind > ConnectionDownload || slot < 0 {
		return ErrUnsupportedRoute
	}
	if dcid == 0 {
		dcid = client.config.DCID
	}
	if dcid == client.config.DCID && kind == ConnectionMain && slot == 0 {
		return client.Connect(ctx)
	}
	if client.config.PFS.Enabled {
		client.pfsMu.Lock()
		defer client.pfsMu.Unlock()
	}
	return client.connectDCSlot(ctx, dcid, kind, slot)
}

func (client *Client) connectDCSlot(ctx context.Context, dcid int, kind ConnectionKind, slot int) error {
	binding, err := client.openDCSlotConnection(ctx, dcid, kind, slot)
	if err != nil || binding == nil {
		return err
	}
	options := InvokeOptions{DCID: dcid, Kind: kind, Slot: slot}
	if err := client.BindTemporaryAuthKeyWithOptions(ctx, options, binding); err != nil {
		client.disconnectPFSRoute(options)
		return err
	}
	keyRoute := routeKey{dcid: dcid, kind: kind, slot: slot}
	client.mu.Lock()
	if route := client.routes[keyRoute]; route != nil {
		client.startRouteLivenessLocked(
			keyRoute,
			route.session,
			route.connection,
			&route.writeMu,
		)
	}
	client.mu.Unlock()
	return nil
}

func (client *Client) openDCSlotConnection(ctx context.Context, dcid int, kind ConnectionKind, slot int) (*PFSBinding, error) {
	slotLimit := client.config.PoolSize
	if dcid == client.config.DCID && kind == ConnectionMain {
		slotLimit = client.TemporarySessionLimit()
	}
	if slot >= slotLimit {
		return nil, ErrUnsupportedRoute
	}
	keyRoute := routeKey{dcid: dcid, kind: kind, slot: slot}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return nil, mtproto.ErrSessionClosed
	}
	if _, ok := client.routes[keyRoute]; ok {
		return nil, nil
	}
	var key mtproto.AuthKey
	var salt int64
	var sessionID [8]byte
	var permanent AuthKeyConfig
	if dcid == client.config.DCID {
		if client.permanent.key.ID == 0 {
			return nil, ErrNoAuthKey
		}
		key, salt = client.permanent.key, client.permanent.salt
		permanent = AuthKeyConfig{
			Key: append([]byte(nil), key.Key[:]...),
			ID:  key.ID,
		}
	} else {
		auth, ok := client.config.DCAuthKeys[dcid]
		if !ok {
			return nil, ErrNoAuthKey
		}
		if auth.Expired(client.now()) {
			return nil, ErrAuthKeyExpired
		}
		var err error
		key, err = mtproto.RestoreAuthKey(auth.Key, auth.ID, auth.TimeOffset)
		if err != nil {
			return nil, err
		}
		salt, sessionID = auth.Salt, auth.SessionID
		permanent = auth
	}
	if sessionID == [8]byte{} || slot > 0 {
		if _, err := rand.Read(sessionID[:]); err != nil {
			return nil, err
		}
	}
	address := client.config.Address
	if endpoint, ok := client.config.DCAddresses[dcid]; ok {
		address = endpoint
	} else if dcid != client.config.DCID {
		return nil, ErrUnsupportedRoute
	}
	poolKey := mtproto.PoolKey{DCID: dcid, Kind: mtproto.ConnectionKind(kind), Slot: slot}
	flood := client.connectionFloodLocked(keyRoute)
	connection, err := client.pool.Acquire(poolKey, func() (net.Conn, error) {
		if retryAfter := flood.admit(client.now()); retryAfter > 0 {
			return nil, &ConnectionFloodError{RetryAfter: retryAfter}
		}
		return client.dialPacket(ctx, address)
	})
	if err != nil {
		return nil, err
	}
	sessionState := mtproto.NewSession(key, salt, sessionID, client.config.PendingCapacity)
	var binding *PFSBinding
	var tempUntil int64
	if client.config.PFS.Enabled {
		sessionState, binding, tempUntil, err = client.preparePFSSession(
			ctx,
			connection,
			dcid,
			sessionID,
			permanent,
		)
		if err != nil {
			_ = client.pool.Discard(poolKey, connection)
			return nil, err
		}
	}
	route := &clientRoute{
		connection: connection,
		session:    sessionState,
		tempUntil:  tempUntil,
	}
	client.routes[keyRoute] = route
	route.sender = client.startRouteSenderLocked(keyRoute, route.session, route.connection, &route.writeMu)
	client.resetRouteIdleTimerLocked(keyRoute, route)
	if !client.config.PFS.Enabled {
		client.startRouteLivenessLocked(keyRoute, route.session, route.connection, &route.writeMu)
	}
	client.startReceiveRouteLocked(keyRoute, route)
	return binding, nil
}

func (client *Client) dialPacket(ctx context.Context, address string) (net.Conn, error) {
	if ctx == nil {
		return nil, context.Canceled
	}
	if client.config.Transport == TransportHTTP {
		if client.httpClient == nil {
			return nil, errors.New("raw: HTTP transport selected but http client is nil")
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conn, err := transport.NewHTTPConn(client.httpClient, address)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
	var connection net.Conn
	var err error
	if client.config.Proxy.Kind == ProxyHTTPConnect {
		connection, err = transport.DialHTTPConnect(ctx, transport.HTTPProxy{Address: client.config.Proxy.Address, Username: client.config.Proxy.Username, Password: client.config.Proxy.Password}, address)
	} else if client.config.Proxy.Kind == ProxySOCKS5 {
		connection, err = transport.DialSOCKS5(ctx, transport.SOCKS5Proxy{Address: client.config.Proxy.Address, Username: client.config.Proxy.Username, Password: client.config.Proxy.Password}, address)
	} else if client.config.DialFunc != nil {
		connection, err = client.config.DialFunc(ctx, address)
	} else {
		connection, err = (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return nil, err
	}
	if client.config.NoDelay {
		if tcpConn, ok := connection.(*net.TCPConn); ok {
			_ = tcpConn.SetNoDelay(true)
		}
	}
	return client.wrapPacket(connection)
}

func (client *Client) wrapPacket(connection net.Conn) (net.Conn, error) {
	if client.config.Transport == TransportHTTP {
		return connection, nil
	}
	if !client.config.Obfuscate {
		if packetConnection, ok := connection.(PacketTransportConn); ok {
			if err := packetConnection.ConfigurePacketTransport(uint8(client.config.Transport)); err != nil {
				_ = connection.Close()
				return nil, err
			}
			if err := transport.WritePacketHeader(connection, transport.PacketMode(client.config.Transport)); err != nil {
				_ = connection.Close()
				return nil, err
			}
			return packetConnection, nil
		}
		if err := transport.WritePacketHeader(connection, transport.PacketMode(client.config.Transport)); err != nil {
			_ = connection.Close()
			return nil, err
		}
		return transport.NewPacketConn(connection, transport.PacketMode(client.config.Transport))
	}
	marker := byte(0xee)
	switch client.config.Transport {
	case TransportAbridged:
		marker = 0xef
	case TransportPaddedIntermediate:
		marker = 0xdd
	}
	obfuscated, err := transport.NewObfuscatedConn(connection, marker)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	return transport.NewPacketConn(obfuscated, transport.PacketMode(client.config.Transport))
}

func (client *Client) Connect(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	if client.config.PFS.Enabled {
		client.pfsMu.Lock()
		defer client.pfsMu.Unlock()
	}
	return client.connectPrimary(ctx)
}

func (client *Client) connectPrimary(ctx context.Context) error {
	binding, err := client.openPrimaryConnection(ctx)
	if err != nil || binding == nil {
		return err
	}
	options := InvokeOptions{
		DCID: client.config.DCID,
		Kind: ConnectionMain,
		Slot: 0,
	}
	if err := client.BindTemporaryAuthKeyWithOptions(ctx, options, binding); err != nil {
		client.disconnectPFSRoute(options)
		return err
	}
	client.mu.Lock()
	if client.session != nil && client.conn != nil {
		client.startRouteLivenessLocked(
			routeKey{dcid: client.config.DCID, kind: ConnectionMain, slot: 0},
			client.session,
			client.conn,
			&client.writeMu,
		)
	}
	client.mu.Unlock()
	return nil
}

func (client *Client) openPrimaryConnection(ctx context.Context) (*PFSBinding, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return nil, mtproto.ErrSessionClosed
	}
	if client.conn != nil {
		return nil, nil
	}
	state, err := client.authState(ctx)
	authorize := false
	if errors.Is(err, ErrNoAuthKey) && client.config.Store != nil {
		authorize = true
	} else if err != nil {
		return nil, err
	}
	sessionID := state.sessionID
	if sessionID == [8]byte{} {
		if _, err := rand.Read(sessionID[:]); err != nil {
			return nil, err
		}
	}
	poolKey := mtproto.PoolKey{DCID: client.config.DCID, Kind: mtproto.ConnectionMain, Slot: 0}
	route := routeKey{dcid: client.config.DCID, kind: ConnectionMain, slot: 0}
	flood := client.connectionFloodLocked(route)
	address := client.config.Address
	if endpoint, ok := client.config.DCAddresses[client.config.DCID]; ok {
		address = endpoint
	}
	connection, err := client.pool.Acquire(poolKey, func() (net.Conn, error) {
		if retryAfter := flood.admit(client.now()); retryAfter > 0 {
			return nil, &ConnectionFloodError{RetryAfter: retryAfter}
		}
		return client.dialPacket(ctx, address)
	})
	if err != nil {
		return nil, err
	}
	if authorize {
		state.sessionID = sessionID
		key, err := mtproto.AuthorizePermanent(
			ctx,
			connection,
			client.authRandom,
			client.now,
			int32(client.config.DCID),
			func(key mtproto.AuthKey) error {
				state.key = key
				state.salt = int64(binary.LittleEndian.Uint64(key.Salt[:]))
				return client.persistAuthStateLocked(ctx, state)
			},
		)
		if err != nil {
			_ = client.pool.Discard(poolKey, connection)
			return nil, err
		}
		state.key = key
	}
	sessionState := mtproto.NewSession(state.key, state.salt, sessionID, client.config.PendingCapacity)
	var binding *PFSBinding
	var tempUntil int64
	if client.config.PFS.Enabled {
		permanent := AuthKeyConfig{
			Key: append([]byte(nil), state.key.Key[:]...),
			ID:  state.key.ID,
		}
		sessionState, binding, tempUntil, err = client.preparePFSSession(
			ctx,
			connection,
			client.config.DCID,
			sessionID,
			permanent,
		)
		if err != nil {
			_ = client.pool.Discard(poolKey, connection)
			return nil, err
		}
	}
	state.sessionID = sessionID
	client.conn = connection
	client.session = sessionState
	client.permanent = state
	client.pfs = nil
	client.tempUntil = tempUntil
	client.initConnectionDone = false
	client.err = nil
	if !authorize {
		if err := client.saveStateLocked(); err != nil {
			_ = client.pool.Discard(poolKey, connection)
			sessionState.Close(err)
			client.conn = nil
			client.session = nil
			return nil, err
		}
	}
	primaryRoute := &clientRoute{connection: connection, session: sessionState}
	client.sender = client.startRouteSenderLocked(route, sessionState, connection, &client.writeMu)
	primaryRoute.sender = client.sender
	if !client.config.PFS.Enabled {
		client.startRouteLivenessLocked(route, sessionState, connection, &client.writeMu)
	}
	client.startReceiveRouteLocked(route, primaryRoute)
	return binding, nil
}

// ActivateTemporaryAuthKey switches an existing route to a temporary key
// after auth.bindTempAuthKey succeeds. Temporary key material is kept in
// memory and is not written to the configured session store.
func (client *Client) ActivateTemporaryAuthKey(dcid int, kind ConnectionKind, auth AuthKeyConfig) error {
	if client == nil || kind > ConnectionDownload || auth.ExpiresAt == 0 {
		return ErrInvalidConfig
	}
	if auth.Expired(client.now()) {
		return ErrAuthKeyExpired
	}
	key, err := mtproto.RestoreAuthKey(auth.Key, auth.ID, 0)
	if err != nil {
		return err
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return mtproto.ErrSessionClosed
	}
	if dcid == 0 {
		dcid = client.config.DCID
	}
	if dcid == client.config.DCID && kind == ConnectionMain {
		if client.session == nil {
			return ErrNotConnected
		}
		if err := client.session.ReplaceAuthKeyWithSalt(key, auth.Salt); err != nil {
			return err
		}
		client.tempUntil = auth.ExpiresAt
		return nil
	}
	route := client.routes[routeKey{dcid: dcid, kind: kind}]
	if route == nil {
		return ErrNotConnected
	}
	if err := route.session.ReplaceAuthKeyWithSalt(key, auth.Salt); err != nil {
		return err
	}
	route.tempUntil = auth.ExpiresAt
	return nil
}

func (client *Client) receiveRoute(key routeKey, route *clientRoute) {
	for {
		result, _, _, err := route.session.Receive(route.connection, client.config.MaxPayload)
		if err != nil {
			if code, ok := mtproto.TransportErrorCode(err); ok && code == 429 {
				client.recordConnectionMTProtoError(key, route)
			}
			if code, ok := mtproto.TransportErrorCode(err); ok && code == 404 && client.invalidatePFSRoute(key, route) {
				return
			}
			client.failConnectedRoute(key, route.session, route.connection, err)
			return
		}
		if err := route.sender.enqueueAcknowledgements(result.AcknowledgeIDs); err != nil {
			client.failConnectedRoute(key, route.session, route.connection, err)
			return
		}
		if err := client.applyInboundRecovery(key, route, result); err != nil {
			client.failConnectedRoute(key, route.session, route.connection, err)
			return
		}
		if !client.handleRouteLiveness(key, route, result) {
			return
		}
		updates := result.Updates
		if len(updates) == 0 {
			if update, ok := result.Object.(tl.UpdatesClass); ok {
				updates = append(updates, update)
			}
		}
		if len(updates) == 0 {
			continue
		}
		for _, update := range updates {
			client.mu.Lock()
			if client.closed {
				client.mu.Unlock()
				return
			}
			if client.updates == nil {
				client.mu.Unlock()
				continue
			}
			select {
			case client.updates <- update:
				client.mu.Unlock()
			default:
				client.mu.Unlock()
				client.failTerminal(ErrUpdateOverflow)
				return
			}
		}
	}
}

func (client *Client) connectionFloodLocked(key routeKey) *connectionFloodControl {
	control := client.connectFlood[key]
	if control == nil {
		control = new(connectionFloodControl)
		client.connectFlood[key] = control
	}
	return control
}

func (client *Client) recordConnectionMTProtoError(key routeKey, route *clientRoute) {
	client.mu.Lock()
	defer client.mu.Unlock()
	owned := client.routes[key] == route
	if key == (routeKey{dcid: client.config.DCID, kind: ConnectionMain, slot: 0}) {
		owned = client.conn == route.connection && client.session == route.session
	}
	if owned {
		client.connectionFloodLocked(key).addMTProtoError(client.now())
	}
}

func (client *Client) startReceiveRouteLocked(key routeKey, route *clientRoute) {
	client.receiveWG.Add(1)
	go func() {
		defer client.receiveWG.Done()
		client.receiveRoute(key, route)
	}()
}

func (client *Client) fail(err error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return
	}
	client.failLocked(err)
}

func (client *Client) failRoute(key routeKey, route *clientRoute, err error) bool {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed ||
		key != (routeKey{dcid: client.config.DCID, kind: ConnectionMain, slot: 0}) ||
		client.conn != route.connection ||
		client.session != route.session {
		return false
	}
	client.failLocked(err)
	return true
}

func (client *Client) failLocked(err error) {
	client.err = err
	_ = client.saveStateLocked()
	client.stopRouteLivenessLocked(
		routeKey{dcid: client.config.DCID, kind: ConnectionMain, slot: 0},
		client.session,
	)
	if client.sender != nil {
		client.sender.halt()
		client.sender = nil
	}
	if client.session != nil {
		client.session.Close(err)
	}
	if client.conn != nil {
		_ = client.pool.Discard(mtproto.PoolKey{DCID: client.config.DCID, Kind: mtproto.ConnectionMain}, client.conn)
		client.conn = nil
	}
}

func (client *Client) saveStateLocked() error {
	if client.config.Store == nil || client.session == nil {
		return nil
	}
	state := client.permanent
	if state.key.ID == 0 {
		state.key = client.session.AuthKey()
		state.salt = client.session.Salt()
	}
	state.sessionID = client.session.SessionID()
	return client.persistAuthStateLocked(context.Background(), state)
}

func (client *Client) persistAuthStateLocked(ctx context.Context, state authState) error {
	authKeys := make([]session.AuthKey, 0, len(client.config.DCAuthKeys)+1)
	authKeys = append(authKeys, session.AuthKey{
		DCID:       client.config.DCID,
		Kind:       "main",
		Key:        append([]byte(nil), state.key.Key[:]...),
		ID:         state.key.ID,
		Salt:       state.salt,
		TimeOffset: state.key.TimeOffset,
	})
	for _, dcid := range slices.Sorted(maps.Keys(client.config.DCAuthKeys)) {
		auth := client.config.DCAuthKeys[dcid]
		if dcid == client.config.DCID || auth.ExpiresAt != 0 {
			continue
		}
		authKeys = append(authKeys, session.AuthKey{
			DCID:       dcid,
			Kind:       "main",
			Key:        append([]byte(nil), auth.Key...),
			ID:         auth.ID,
			Salt:       auth.Salt,
			TimeOffset: auth.TimeOffset,
		})
	}
	snapshot := session.Snapshot{
		APIID:     client.config.APIID,
		PrimaryDC: client.config.DCID,
		SessionID: state.sessionID,
		AuthKeys:  authKeys,
	}
	data, err := session.Encode(snapshot)
	if err != nil {
		return err
	}
	return client.config.Store.Save(ctx, data)
}

func (client *Client) authState(ctx context.Context) (authState, error) {
	if len(client.config.AuthKey) != 0 {
		key, err := mtproto.RestoreAuthKey(client.config.AuthKey, client.config.AuthKeyID, client.config.AuthKeyTimeOffset)
		return authState{key: key, salt: client.config.Salt, sessionID: client.config.SessionID}, err
	}
	if client.config.Store == nil {
		return authState{}, ErrNoAuthKey
	}
	data, err := client.config.Store.Load(ctx)
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			return authState{}, ErrNoAuthKey
		}
		return authState{}, err
	}
	if len(data) == 0 {
		return authState{}, ErrNoAuthKey
	}
	snapshot, err := session.Decode(data)
	if err != nil {
		return authState{}, err
	}
	var primary authState
	for _, persisted := range snapshot.AuthKeys {
		if persisted.Kind != "main" {
			continue
		}
		if persisted.DCID == snapshot.PrimaryDC {
			key, err := mtproto.RestoreAuthKey(persisted.Key, persisted.ID, persisted.TimeOffset)
			if err != nil {
				return authState{}, err
			}
			primary = authState{key: key, salt: persisted.Salt, sessionID: snapshot.SessionID}
			continue
		}
		if _, configured := client.config.DCAuthKeys[persisted.DCID]; configured {
			continue
		}
		client.config.DCAuthKeys[persisted.DCID] = AuthKeyConfig{
			Key:        append([]byte(nil), persisted.Key...),
			ID:         persisted.ID,
			Salt:       persisted.Salt,
			TimeOffset: persisted.TimeOffset,
			ExpiresAt:  persisted.ExpiresAt,
		}
	}
	if primary.key.ID != 0 {
		address := client.config.Address
		if snapshot.PrimaryDC != client.config.DCID {
			var ok bool
			address, ok = client.config.DCAddresses[snapshot.PrimaryDC]
			if !ok {
				address, ok = defaultTelegramAddress(snapshot.PrimaryDC, client.config.TestMode)
			}
			if !ok {
				return authState{}, ErrInvalidConfig
			}
		}
		if err := client.endpoints.Set(mtproto.DCEndpoint{
			ID:      snapshot.PrimaryDC,
			Address: address,
		}); err != nil {
			return authState{}, err
		}
		client.config.DCID = snapshot.PrimaryDC
		client.config.Address = address
		return primary, nil
	}
	return authState{}, ErrNoAuthKey
}

// Disconnect closes all connections and pending requests without destroying the
// client. After Disconnect, Connect can be called again to resume. Session
// state is saved before connections are dropped.
func (client *Client) Disconnect(ctx context.Context) error {
	if client == nil {
		return ErrInvalidConfig
	}
	client.mu.Lock()
	if client.closed {
		client.mu.Unlock()
		return mtproto.ErrSessionClosed
	}
	if client.conn == nil && client.session == nil {
		client.mu.Unlock()
		return nil
	}
	client.disconnectLocked()
	client.mu.Unlock()
	client.receiveWG.Wait()
	client.sendWG.Wait()
	client.reconnectWG.Wait()
	client.livenessWG.Wait()
	return nil
}

func (client *Client) disconnectLocked() {
	client.stopAllRouteLivenessLocked()
	for key, route := range client.routes {
		client.stopRouteIdleTimerLocked(route)
		route.sender.halt()
		route.session.Close(ErrDisconnected)
		_ = client.pool.Discard(mtproto.PoolKey{DCID: key.dcid, Kind: mtproto.ConnectionKind(key.kind), Slot: key.slot}, route.connection)
		delete(client.routes, key)
	}
	if client.sender != nil {
		client.sender.halt()
		client.sender = nil
	}
	if client.session != nil {
		_ = client.saveStateLocked()
		client.session.Close(ErrDisconnected)
		client.session = nil
	}
	if client.conn != nil {
		_ = client.pool.Discard(mtproto.PoolKey{DCID: client.config.DCID, Kind: mtproto.ConnectionMain, Slot: 0}, client.conn)
		client.conn = nil
	}
	client.pfs = nil
	client.tempUntil = 0
	client.initConnectionDone = false
	client.connectFlood = make(map[routeKey]*connectionFloodControl)
	client.reconnects = make(map[routeKey]*clientReconnect)
	client.liveness = make(map[routeKey]*routeLiveness)
	client.err = nil
}

func (client *Client) Close() error {
	client.stopReconnect()
	client.mu.Lock()
	if client.closed {
		client.mu.Unlock()
		client.receiveWG.Wait()
		client.sendWG.Wait()
		client.reconnectWG.Wait()
		client.livenessWG.Wait()
		return nil
	}
	err := client.closeLocked(nil)
	client.mu.Unlock()
	client.receiveWG.Wait()
	client.sendWG.Wait()
	client.reconnectWG.Wait()
	client.livenessWG.Wait()
	return err
}

func (client *Client) failTerminal(err error) {
	client.stopReconnect()
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return
	}
	_ = client.closeLocked(err)
}

func (client *Client) closeLocked(cause error) error {
	client.closed = true
	client.stopAllRouteLivenessLocked()
	closeErr := error(nil)
	pendingErr := cause
	if pendingErr == nil {
		pendingErr = mtproto.ErrSessionClosed
	}
	if client.sender != nil {
		client.sender.halt()
		client.sender = nil
	}
	if client.session != nil {
		_ = client.saveStateLocked()
		client.session.Close(pendingErr)
	}
	for key, route := range client.routes {
		client.stopRouteIdleTimerLocked(route)
		route.sender.halt()
		route.session.Close(pendingErr)
		if err := client.pool.Discard(mtproto.PoolKey{DCID: key.dcid, Kind: mtproto.ConnectionKind(key.kind), Slot: key.slot}, route.connection); closeErr == nil {
			closeErr = err
		}
		delete(client.routes, key)
	}
	if client.conn != nil {
		if err := client.pool.Discard(mtproto.PoolKey{DCID: client.config.DCID, Kind: mtproto.ConnectionMain, Slot: 0}, client.conn); closeErr == nil {
			closeErr = err
		}
		client.conn = nil
	}
	if err := client.pool.Close(); closeErr == nil {
		closeErr = err
	}
	close(client.done)
	if client.updates != nil {
		close(client.updates)
	}
	if cause != nil {
		client.err = cause
	} else {
		client.err = closeErr
	}
	return closeErr
}

func (client *Client) Done() <-chan struct{} { return client.done }

func (client *Client) Updates() <-chan tl.UpdatesClass { return client.updates }

func (client *Client) Err() error {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.err
}
