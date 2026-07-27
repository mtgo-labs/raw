package raw

import (
	"context"
	"crypto/rand"
	"net"
	"sync"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/tgerr"
	"github.com/mtgo-labs/raw/tl"
)

// Invoke sends one generated raw request, connecting the primary route on first use.
func Invoke[T any](ctx context.Context, client *Client, request tl.Request[T]) (T, error) {
	return InvokeWithOptions(ctx, client, request, InvokeOptions{})
}

// InvokeRaw sends a request and returns the raw response body without TL
// decoding. It delegates to InvokeWithRawResult and extracts the payload.
func InvokeRaw(ctx context.Context, client *Client, request tl.Object) ([]byte, error) {
	result, err := InvokeWithRawResult(ctx, client, request)
	if err != nil {
		return nil, err
	}
	return result.Payload, nil
}

// applyMiddleware composes the middleware chain around invoke. When
// middlewares is nil or empty, invoke is returned unchanged.
func applyMiddleware(middlewares []Middleware, invoke InvokeFunc) InvokeFunc {
	if len(middlewares) == 0 {
		return invoke
	}
	chain := invoke
	for i := len(middlewares) - 1; i >= 0; i-- {
		chain = middlewares[i].Handle(chain)
	}
	return chain
}

// InvokeWithOptions connects the default primary route on first use. Explicit
// DC, connection-kind, and slot selections must already be connected.
func InvokeWithOptions[T any](ctx context.Context, client *Client, request tl.Request[T], options InvokeOptions) (T, error) {
	if client == nil {
		var zero T
		return zero, ErrNotConnected
	}
	maxAttempts := max(client.config.Retry.MaxAttempts, 1)
	maxFloodWait := client.config.Retry.MaxFloodWait
	method := request.ConstructorID()
	if err := client.floodWait.check(ctx, method, maxFloodWait, defaultFloodWaitStoreMinWait); err != nil {
		var zero T
		return zero, err
	}
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		result, err := invokeWithMigration(ctx, client, request, options)
		if err == nil {
			return result, nil
		}
		rpcError, ok := tgerr.As(err)
		if !ok {
			return result, err
		}
		if wait, ok := rpcError.FloodWaitDuration(); ok {
			if maxFloodWait <= 0 || wait > maxFloodWait || attempt == maxAttempts {
				return result, err
			}
			client.floodWait.record(method, wait, rpcError.IsType(tgerr.ErrSlowModeWait))
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return result, ctx.Err()
			case <-timer.C:
			}
			continue
		}
		if !rpcError.Transient() || attempt == maxAttempts {
			return result, err
		}
	}
	var zero T
	return zero, ErrNotConnected
}

func invokeWithMigration[T any](ctx context.Context, client *Client, request tl.Request[T], options InvokeOptions) (T, error) {
	result, err := invokeRoute(ctx, client, request, options)
	if err == nil {
		return result, nil
	}
	rpcError, ok := tgerr.As(err)
	targetDC, migrates := 0, false
	if ok {
		targetDC, migrates = rpcError.MigrationDC()
	}
	if !migrates || targetDC == options.DCID || targetDC == 0 {
		return result, err
	}
	if options.DCID == 0 && isPrimaryMigration(rpcError) {
		if migrationErr := client.changePrimaryDC(ctx, targetDC); migrationErr != nil {
			return result, migrationErr
		}
		options.DCID = targetDC
		return invokeRoute(ctx, client, request, options)
	}
	if connectErr := client.connectMigrationRoute(ctx, targetDC, options); connectErr != nil {
		return result, connectErr
	}
	options.DCID = targetDC
	result, err = invokeRoute(ctx, client, request, options)
	if !tgerr.IsAuthKeyUnregistered(err) {
		return result, err
	}
	if transferErr := client.ensureAuthorizationTransferred(ctx, targetDC); transferErr != nil {
		return result, transferErr
	}
	return invokeRoute(ctx, client, request, options)
}

func invokeRoute[T any](ctx context.Context, client *Client, request tl.Request[T], options InvokeOptions) (T, error) {
	var zero T
	if client == nil {
		return zero, ErrNotConnected
	}
	connectAttempted := false
selectRoute:
	client.mu.Lock()
	if options.Kind > ConnectionDownload || options.Slot < 0 {
		client.mu.Unlock()
		return zero, ErrUnsupportedRoute
	}
	if client.closed {
		client.mu.Unlock()
		return zero, ErrNotConnected
	}
	var sessionState *mtproto.Session
	var connection net.Conn
	var writeMu *sync.Mutex
	var sendMu *sync.Mutex
	var sender *routeSender
	var ordering *map[string]uint64
	var initConnectionDone *bool
	dcid := options.DCID
	if dcid == 0 {
		dcid = client.config.DCID
	}
	selectedKey := routeKey{dcid: dcid, kind: options.Kind, slot: options.Slot}
	if _, invalid := client.pfsInvalid[selectedKey]; invalid {
		client.mu.Unlock()
		return zero, ErrPFSRebindRequired
	}
	if dcid != client.config.DCID || options.Kind != ConnectionMain || options.Slot != 0 {
		route := client.routes[selectedKey]
		if route == nil {
			client.mu.Unlock()
			return zero, ErrNotConnected
		}
		if route.tempUntil != 0 && route.tempUntil <= client.now().Unix() {
			if route.pfs != nil {
				client.mu.Unlock()
				return zero, ErrPFSRebindRequired
			}
			client.mu.Unlock()
			return zero, ErrAuthKeyExpired
		}
		client.resetRouteIdleTimerLocked(selectedKey, route)
		if route.sender == nil {
			route.sender = client.startRouteSenderLocked(selectedKey, route.session, route.connection, &route.writeMu)
		}
		sessionState, connection, sendMu, writeMu, sender, ordering, initConnectionDone = route.session, route.connection, &route.sendMu, &route.writeMu, route.sender, &route.ordering, &route.initConnectionDone
	} else if options.Kind == ConnectionMain {
		if client.conn == nil || client.session == nil {
			client.mu.Unlock()
			if connectAttempted {
				return zero, ErrNotConnected
			}
			connectAttempted = true
			if err := client.Connect(ctx); err != nil {
				return zero, err
			}
			goto selectRoute
		}
		if client.tempUntil != 0 && client.tempUntil <= client.now().Unix() {
			if client.pfs != nil {
				client.mu.Unlock()
				return zero, ErrPFSRebindRequired
			}
			client.mu.Unlock()
			return zero, ErrAuthKeyExpired
		}
		if client.sender == nil {
			client.sender = client.startRouteSenderLocked(selectedKey, client.session, client.conn, &client.writeMu)
		}
		sessionState, connection, sendMu, writeMu, sender, ordering, initConnectionDone = client.session, client.conn, &client.sendMu, &client.writeMu, client.sender, &client.ordering, &client.initConnectionDone
	} else {
		client.mu.Unlock()
		return zero, ErrNotConnected
	}
	client.mu.Unlock()
	sendMu.Lock()
	wireRequest := request
	wrappedInitConnection := !*initConnectionDone
	if wrappedInitConnection {
		wireRequest = wrapInitConnection(client.config.APIID, client.config.InitConnection, request)
	}
	var object tl.Object = wireRequest
	if options.OrderingKey != "" {
		if *ordering == nil {
			*ordering = make(map[string]uint64)
		}
		if previous := (*ordering)[options.OrderingKey]; previous != 0 {
			object = orderedRequest(wireRequest, previous)
		}
	}
	now := client.now()
	var err error
	sendFailed := false
	if sessionState.NeedsFutureSalts() {
		writeMu.Lock()
		_, _, err = sessionState.SendFutureSaltsRequest(connection, rand.Reader, now)
		writeMu.Unlock()
		sendFailed = err != nil
	}
	var messageID uint64
	var pendingRequest *mtproto.PendingRequest
	if err == nil {
		var message tl.MTPMessage
		message, pendingRequest, err = sessionState.Prepare(now, object)
		messageID = uint64(message.MessageID)
		if err == nil {
			acks := sender.drainAcks()
			messages := [...]tl.MTPMessage{message}
			writeMu.Lock()
			_, err = sessionState.SendPrepared(
				connection, rand.Reader, now, messages[:], acks, false,
			)
			writeMu.Unlock()
			sendFailed = err != nil
			if err != nil {
				sessionState.Cancel(messageID, err)
			}
		}
	}
	if err == nil && options.OrderingKey != "" {
		(*ordering)[options.OrderingKey] = messageID
	}
	sendMu.Unlock()
	if err != nil {
		if sendFailed {
			client.failConnectedRoute(selectedKey, sessionState, connection, err)
		}
		return zero, err
	}
	if options.OrderingKey != "" {
		defer func() {
			sendMu.Lock()
			if (*ordering)[options.OrderingKey] == messageID {
				delete(*ordering, options.OrderingKey)
			}
			sendMu.Unlock()
		}()
	}
	pending, waitErr := sessionState.WaitPrepared(ctx, pendingRequest)
	if waitErr != nil && pending == nil {
		return zero, waitErr
	}
	if waitErr == nil {
		sendMu.Lock()
		if tgerr.IsConnectionNotInited(pending.Result.Err) {
			*initConnectionDone = false
		} else if wrappedInitConnection {
			*initConnectionDone = true
		}
		sendMu.Unlock()
	}
	if pending.Result.Err != nil {
		return zero, pending.Result.Err
	}
	return tl.DecodeResult(request, pending.Result.Body, tl.DefaultDecodeLimits())
}
func wrapInitConnection[T any](apiID int32, init InitConnectionConfig, request tl.Request[T]) tl.Request[T] {
	return &tl.InvokeWithLayerRequest[T]{
		Layer: int32(tl.Layer),
		Query: &tl.InitConnectionRequest[T]{
			APIID:          apiID,
			DeviceModel:    init.DeviceModel,
			SystemVersion:  init.SystemVersion,
			AppVersion:     init.AppVersion,
			SystemLangCode: init.SystemLanguageCode,
			LangPack:       init.LanguagePack,
			LangCode:       init.LanguageCode,
			Proxy:          init.Proxy,
			Params:         init.Parameters,
			Query:          request,
		},
	}
}

func orderedRequest[T any](request tl.Request[T], previous uint64) tl.Object {
	if previous == 0 {
		return request
	}
	return &tl.InvokeAfterMessageRequest[T]{MessageID: int64(previous), Query: request}
}
