package raw

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/tgerr"
	"github.com/mtgo-labs/raw/tl"
)

// RawResult is an undecoded MTProto RPC response. It avoids the allocation
// and CPU cost of full TL deserialization when the caller only needs the
// constructor ID, wants to defer decoding, or only cares about success.
type RawResult struct {
	Constructor uint32
	Payload     []byte
}

// InvokeWithRawResult sends a request and returns the raw undecoded response.
// rpc_result wrapping is transparently unwrapped so the caller sees the
// method's actual result constructor. TL decoding is skipped entirely.
func InvokeWithRawResult(ctx context.Context, client *Client, request tl.Object) (RawResult, error) {
	if client == nil {
		return RawResult{}, ErrNotConnected
	}
	maxAttempts := max(client.config.Retry.MaxAttempts, 1)
	maxFloodWait := client.config.Retry.MaxFloodWait
	method := request.ConstructorID()
	if err := client.floodWait.check(ctx, method, maxFloodWait, defaultFloodWaitStoreMinWait); err != nil {
		return RawResult{}, err
	}
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		result, err := invokeWithRawResult(ctx, client, request, InvokeOptions{})
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
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return result, ctx.Err()
			}
			continue
		}
	}
	return RawResult{}, ErrNotConnected
}

// InvokeRawWithMiddleware is like InvokeWithRawResult but applies
// the configured middleware chain to each RPC invocation. Unlike
// InvokeWithRawResult, it does NOT perform automatic retry — the
// retry loop is left to the caller or to retry middleware in the
// chain. Migration and flood-wait handling are still performed.
//
// When Config.Middlewares is empty, this is equivalent to calling
// InvokeWithRawResult.
func InvokeRawWithMiddleware(ctx context.Context, client *Client, request tl.Object) (RawResult, error) {
	if client == nil {
		return RawResult{}, ErrNotConnected
	}
	rawInvoke := applyMiddleware(client.config.Middlewares, func(ctx context.Context, req tl.Object) ([]byte, error) {
		result, err := invokeWithRawResult(ctx, client, req, InvokeOptions{})
		if err != nil {
			return nil, err
		}
		return append(
			binary.LittleEndian.AppendUint32(nil, result.Constructor),
			result.Payload...,
		), nil
	})
	raw, err := rawInvoke(ctx, request)
	if err != nil {
		return RawResult{}, err
	}
	return rawResult(raw), nil
}

func invokeWithRawResult(ctx context.Context, client *Client, request tl.Object, options InvokeOptions) (RawResult, error) {
	result, err := invokeRouteRawResult(ctx, client, request, options)
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
		if migrateErr := client.changePrimaryDC(ctx, targetDC); migrateErr != nil {
			return result, migrateErr
		}
		return invokeRouteRawResult(ctx, client, request, options)
	}
	if connectErr := client.connectMigrationRoute(ctx, targetDC, options); connectErr != nil {
		return result, connectErr
	}
	options.DCID = targetDC
	result, err = invokeRouteRawResult(ctx, client, request, options)
	if !tgerr.IsAuthKeyUnregistered(err) {
		return result, err
	}
	if transferErr := client.ensureAuthorizationTransferred(ctx, targetDC); transferErr != nil {
		return result, transferErr
	}
	return invokeRouteRawResult(ctx, client, request, options)
}

// rpcResultConstructor is the TL constructor ID for rpc_result#f35c6d01.
const rpcResultConstructor = 0xf35c6d01

func rawResult(body []byte) RawResult {
	if len(body) < 4 {
		return RawResult{}
	}
	ctor := binary.LittleEndian.Uint32(body[:4])
	payload := body[4:]
	// Unwrap rpc_result: skip constructor (4 bytes) + req_msg_id (8 bytes).
	if ctor == rpcResultConstructor && len(payload) >= 8 {
		inner := payload[8:]
		if len(inner) >= 4 {
			ctor = binary.LittleEndian.Uint32(inner[:4])
			payload = inner[4:]
		}
	}
	return RawResult{Constructor: ctor, Payload: payload}
}

func invokeRouteRawResult(ctx context.Context, client *Client, request tl.Object, options InvokeOptions) (RawResult, error) {
	if client == nil {
		return RawResult{}, ErrNotConnected
	}
	connectAttempted := false
	pfsAttempted := false
selectRoute:
	client.mu.Lock()
	if options.Kind > ConnectionDownload || options.Slot < 0 {
		client.mu.Unlock()
		return RawResult{}, ErrUnsupportedRoute
	}
	if client.closed {
		client.mu.Unlock()
		return RawResult{}, ErrNotConnected
	}
	var sessionState *mtproto.Session
	var connection net.Conn
	var writeMu *sync.Mutex
	var sendMu *sync.Mutex
	var sender *routeSender
	var ordering *map[string]uint64
	dcid := options.DCID
	if dcid == 0 {
		dcid = client.config.DCID
	}
	selectedKey := routeKey{dcid: dcid, kind: options.Kind, slot: options.Slot}
	if client.config.PFS.Enabled && client.routeNeedsPFSLocked(selectedKey) {
		client.mu.Unlock()
		if pfsAttempted {
			return RawResult{}, ErrPFSRebindRequired
		}
		pfsAttempted = true
		if err := client.connectPFS(ctx, InvokeOptions{DCID: dcid, Kind: options.Kind, Slot: options.Slot}); err != nil {
			return RawResult{}, err
		}
		goto selectRoute
	}
	if _, invalid := client.pfsInvalid[selectedKey]; invalid {
		client.mu.Unlock()
		return RawResult{}, ErrPFSRebindRequired
	}
	if dcid != client.config.DCID || options.Kind != ConnectionMain || options.Slot != 0 {
		route := client.routes[selectedKey]
		if route == nil {
			client.mu.Unlock()
			return RawResult{}, ErrNotConnected
		}
		if route.tempUntil != 0 && route.tempUntil <= client.now().Unix() {
			if route.pfs != nil {
				client.mu.Unlock()
				return RawResult{}, ErrPFSRebindRequired
			}
			client.mu.Unlock()
			return RawResult{}, ErrAuthKeyExpired
		}
		client.resetRouteIdleTimerLocked(selectedKey, route)
		if route.sender == nil {
			route.sender = client.startRouteSenderLocked(selectedKey, route.session, route.connection, &route.writeMu)
		}
		sessionState, connection, sendMu, writeMu, sender, ordering = route.session, route.connection, &route.sendMu, &route.writeMu, route.sender, &route.ordering
	} else if options.Kind == ConnectionMain {
		if client.conn == nil || client.session == nil {
			client.mu.Unlock()
			if connectAttempted {
				return RawResult{}, ErrNotConnected
			}
			connectAttempted = true
			if err := client.Connect(ctx); err != nil {
				return RawResult{}, err
			}
			goto selectRoute
		}
		if client.tempUntil != 0 && client.tempUntil <= client.now().Unix() {
			if client.pfs != nil {
				client.mu.Unlock()
				return RawResult{}, ErrPFSRebindRequired
			}
			client.mu.Unlock()
			return RawResult{}, ErrAuthKeyExpired
		}
		if client.sender == nil {
			client.sender = client.startRouteSenderLocked(selectedKey, client.session, client.conn, &client.writeMu)
		}
		sessionState, connection, sendMu, writeMu, sender, ordering = client.session, client.conn, &client.sendMu, &client.writeMu, client.sender, &client.ordering
	} else {
		client.mu.Unlock()
		return RawResult{}, ErrNotConnected
	}
	client.mu.Unlock()
	sendMu.Lock()
	var object tl.Object = request
	if options.OrderingKey != "" {
		if *ordering == nil {
			*ordering = make(map[string]uint64)
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
		return RawResult{}, err
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
		return RawResult{}, waitErr
	}
	if pending.Result.Err != nil {
		return RawResult{}, pending.Result.Err
	}
	return rawResult(pending.Result.Body), nil
}
