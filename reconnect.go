package raw

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/tgerr"
	"github.com/mtgo-labs/raw/tl"
)

type clientReconnect struct {
	again   bool
	session *mtproto.Session
	err     error
}

func (client *Client) scheduleReconnect(key routeKey) {
	client.scheduleReconnectSession(key, nil, nil)
}

func (client *Client) scheduleReconnectSession(key routeKey, sessionState *mtproto.Session, cause error) {
	if client == nil || client.config.Reconnect.Disabled {
		if sessionState != nil {
			sessionState.Close(cause)
		}
		return
	}
	client.mu.Lock()
	if client.closed || client.routeUsesPFSLocked(key) {
		client.mu.Unlock()
		if sessionState != nil {
			sessionState.Close(cause)
		}
		return
	}
	if reconnect := client.reconnects[key]; reconnect != nil {
		reconnect.again = true
		if sessionState != nil {
			reconnect.session = sessionState
		}
		if cause != nil {
			reconnect.err = cause
		}
		client.mu.Unlock()
		return
	}
	reconnect := &clientReconnect{session: sessionState, err: cause}
	client.reconnects[key] = reconnect
	client.reconnectWG.Add(1)
	client.mu.Unlock()

	go client.reconnectRoute(key, reconnect)
}

func (client *Client) reconnectRoute(key routeKey, reconnect *clientReconnect) {
	defer client.reconnectWG.Done()
	attempt := 1
	for attempt <= client.config.Reconnect.MaxAttempts {
		delay := client.reconnectDelay(attempt)
		for {
			if !client.waitReconnect(delay) {
				client.finishReconnect(key, reconnect)
				return
			}
			client.mu.Lock()
			sessionState := reconnect.session
			client.mu.Unlock()
			var err error
			if sessionState == nil {
				err = client.connectRoute(client.reconnectCtx, key)
			} else {
				err = client.connectRecoveredRoute(client.reconnectCtx, key, sessionState)
			}
			if err == nil {
				client.mu.Lock()
				if client.reconnects[key] != reconnect {
					client.mu.Unlock()
					return
				}
				if reconnect.again {
					reconnect.again = false
					attempt = 1
					client.mu.Unlock()
					break
				}
				reconnect.session = nil
				delete(client.reconnects, key)
				client.mu.Unlock()
				return
			}
			client.mu.Lock()
			if client.reconnects[key] == reconnect {
				reconnect.err = err
			}
			client.mu.Unlock()
			var flood *ConnectionFloodError
			if errors.As(err, &flood) {
				delay = flood.RetryAfter
				continue
			}
			if terminalReconnectError(err) {
				client.finishReconnect(key, reconnect)
				return
			}
			attempt++
			break
		}
	}
	client.finishReconnect(key, reconnect)
}

func (client *Client) connectRoute(ctx context.Context, key routeKey) error {
	client.mu.Lock()
	primary := key == (routeKey{dcid: client.config.DCID, kind: ConnectionMain, slot: 0})
	client.mu.Unlock()
	if primary {
		return client.Connect(ctx)
	}
	return client.ConnectDCSlot(ctx, key.dcid, key.kind, key.slot)
}

func (client *Client) connectRecoveredRoute(ctx context.Context, key routeKey, sessionState *mtproto.Session) error {
	if ctx == nil {
		return context.Canceled
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return mtproto.ErrSessionClosed
	}
	primary := key == (routeKey{dcid: client.config.DCID, kind: ConnectionMain, slot: 0})
	if primary {
		if client.conn != nil {
			return nil
		}
		if client.session != sessionState {
			return ErrNotConnected
		}
	} else if client.routes[key] != nil {
		return nil
	}
	address := client.config.Address
	if endpoint, ok := client.config.DCAddresses[key.dcid]; ok {
		address = endpoint
	} else if key.dcid != client.config.DCID {
		return ErrUnsupportedRoute
	}
	flood := client.connectionFloodLocked(key)
	poolKey := mtproto.PoolKey{DCID: key.dcid, Kind: mtproto.ConnectionKind(key.kind), Slot: key.slot}
	connection, err := client.pool.Acquire(poolKey, func() (net.Conn, error) {
		if retryAfter := flood.admit(client.now()); retryAfter > 0 {
			return nil, &ConnectionFloodError{RetryAfter: retryAfter}
		}
		return client.dialPacket(ctx, address)
	})
	if err != nil {
		return err
	}
	// The server-side msg_id high-water mark of the dropped session is
	// unknown: messages the server did process advanced it past the ones
	// still unresolved here. Recover under a fresh session id with fresh
	// message ids; re-sending the original ids would draw
	// MSGID_DECREASE_RETRY.
	var sessionID [8]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		_ = client.pool.Discard(poolKey, connection)
		return err
	}
	now := client.now()
	messages := sessionState.ResetAndRecover(sessionID, now)
	route := &clientRoute{connection: connection, session: sessionState}
	writeMu := &route.writeMu
	if primary {
		writeMu = &client.writeMu
		client.sendMu.Lock()
		client.initConnectionDone = false
		client.ordering = nil
		client.sendMu.Unlock()
	}
	// Flush before the route is published: no other writer exists yet, so the
	// recovered ids reach the wire in allocation order and every message
	// sent after reconnect is allocated above them.
	if err := writeRecoveredMessages(sessionState, connection, writeMu, messages, now); err != nil {
		_ = client.pool.Discard(poolKey, connection)
		return err
	}
	route.sender = client.startRouteSenderLocked(key, sessionState, connection, writeMu)
	if primary {
		client.conn = connection
		client.sender = route.sender
		client.err = nil
	} else {
		client.routes[key] = route
		client.resetRouteIdleTimerLocked(key, route)
	}
	client.startRouteLivenessLocked(key, sessionState, connection, writeMu)
	client.startReceiveRouteLocked(key, route)
	return nil
}

// writeRecoveredMessages writes one recovered batch in container-sized
// chunks. Chunks are written in order and each container id is allocated
// after its children, so the ids stay monotonically increasing on the wire.
func writeRecoveredMessages(
	sessionState *mtproto.Session,
	connection net.Conn,
	writeMu *sync.Mutex,
	messages []tl.MTPMessage,
	now time.Time,
) error {
	for start := 0; start < len(messages); {
		end := start
		packetSize := 0
		for end < len(messages) && end-start < mtproto.MaxContainerMessages {
			messageSize := 16 + int(messages[end].Bytes)
			if end != start && packetSize+messageSize > mtproto.MaxContainerPayload {
				break
			}
			packetSize += messageSize
			end++
		}
		writeMu.Lock()
		_, err := sessionState.SendPrepared(connection, rand.Reader, now, messages[start:end], nil, false)
		writeMu.Unlock()
		if err != nil {
			return err
		}
		start = end
	}
	return nil
}

func (client *Client) failConnectedRoute(key routeKey, sessionState *mtproto.Session, connection net.Conn, err error) {
	client.mu.Lock()
	if client.closed {
		client.mu.Unlock()
		return
	}
	primary := key == (routeKey{dcid: client.config.DCID, kind: ConnectionMain, slot: 0})
	var route *clientRoute
	var reconnectable bool
	if primary {
		if client.session != sessionState || client.conn != connection {
			client.mu.Unlock()
			return
		}
		route = &clientRoute{connection: connection, session: sessionState, sender: client.sender}
		reconnectable = client.pfs == nil && !client.config.Reconnect.Disabled
		client.err = err
		_ = client.saveStateLocked()
		client.stopRouteLivenessLocked(key, sessionState)
		client.conn = nil
		client.sender = nil
	} else {
		route = client.routes[key]
		if route == nil || route.session != sessionState || route.connection != connection {
			client.mu.Unlock()
			return
		}
		reconnectable = route.pfs == nil && !client.config.Reconnect.Disabled
		delete(client.routes, key)
		client.stopRouteIdleTimerLocked(route)
		client.stopRouteLivenessLocked(key, route.session)
	}
	preserve := reconnectable && len(sessionState.RecoveryMessages()) != 0
	client.mu.Unlock()

	route.sender.halt()
	if !preserve {
		sessionState.Close(err)
	}
	_ = client.pool.Discard(mtproto.PoolKey{
		DCID: key.dcid, Kind: mtproto.ConnectionKind(key.kind), Slot: key.slot,
	}, route.connection)
	if reconnectable {
		if preserve {
			client.scheduleReconnectSession(key, sessionState, err)
		} else {
			client.scheduleReconnect(key)
		}
	}
}

func (client *Client) finishReconnect(key routeKey, reconnect *clientReconnect) {
	client.mu.Lock()
	var sessionState *mtproto.Session
	var err error
	if client.reconnects[key] == reconnect {
		delete(client.reconnects, key)
		sessionState = reconnect.session
		err = reconnect.err
	}
	client.mu.Unlock()
	if sessionState != nil {
		if err == nil {
			err = ErrNotConnected
		}
		sessionState.Close(err)
	}
}

func (client *Client) waitReconnect(delay time.Duration) bool {
	if delay <= 0 {
		select {
		case <-client.reconnectCtx.Done():
			return false
		default:
			return true
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-client.reconnectCtx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (client *Client) defaultReconnectDelay(attempt int) time.Duration {
	delay := client.config.Reconnect.InitialDelay
	for current := 1; current < attempt && delay < client.config.Reconnect.MaxDelay; current++ {
		if delay > client.config.Reconnect.MaxDelay/2 {
			delay = client.config.Reconnect.MaxDelay
			break
		}
		delay *= 2
	}
	if delay > client.config.Reconnect.MaxDelay {
		delay = client.config.Reconnect.MaxDelay
	}
	if delay <= 0 {
		return 0
	}
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return delay
	}
	return time.Duration(binary.LittleEndian.Uint64(value[:]) % (uint64(delay) + 1))
}

func (client *Client) routeUsesPFSLocked(key routeKey) bool {
	if key == (routeKey{dcid: client.config.DCID, kind: ConnectionMain, slot: 0}) {
		return client.pfs != nil
	}
	route := client.routes[key]
	return route != nil && route.pfs != nil
}

func terminalReconnectError(err error) bool {
	return errors.Is(err, ErrNoAuthKey) ||
		errors.Is(err, ErrAuthKeyExpired) ||
		errors.Is(err, ErrPFSRebindRequired) ||
		errors.Is(err, ErrUnsupportedRoute) ||
		errors.Is(err, ErrInvalidConfig) ||
		errors.Is(err, mtproto.ErrSessionClosed) ||
		errors.Is(err, context.Canceled) ||
		tgerr.IsCode(err, 406)
}
