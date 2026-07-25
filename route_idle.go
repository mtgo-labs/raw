package raw

import (
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
)

type routeIdleTimer struct {
	timer *time.Timer
}

func (client *Client) resetRouteIdleTimerLocked(key routeKey, route *clientRoute) {
	if route == nil {
		return
	}
	if !client.routeIdleEnabledLocked(key) {
		client.stopRouteIdleTimerLocked(route)
		return
	}
	if route.idle != nil && route.idle.timer.Reset(client.config.PoolIdleTimeout) {
		return
	}
	idle := new(routeIdleTimer)
	idle.timer = time.AfterFunc(client.config.PoolIdleTimeout, func() {
		client.closeIdleRoute(key, route, idle)
	})
	route.idle = idle
}

func (client *Client) stopRouteIdleTimerLocked(route *clientRoute) {
	if route == nil || route.idle == nil {
		return
	}
	route.idle.timer.Stop()
	route.idle = nil
}

func (client *Client) routeIdleEnabledLocked(key routeKey) bool {
	return client.config.PoolIdleTimeout > 0 &&
		(key.dcid != client.config.DCID || key.kind != ConnectionMain)
}

func (client *Client) refreshRouteIdleTimersLocked() {
	for key, route := range client.routes {
		client.resetRouteIdleTimerLocked(key, route)
	}
}

func (client *Client) closeIdleRoute(key routeKey, route *clientRoute, idle *routeIdleTimer) {
	client.mu.Lock()
	if client.closed || client.routes[key] != route || route.idle != idle {
		client.mu.Unlock()
		return
	}
	if !client.routeIdleEnabledLocked(key) {
		route.idle = nil
		client.mu.Unlock()
		return
	}
	if route.session.Pending() != 0 {
		idle.timer.Reset(client.config.PoolIdleTimeout)
		client.mu.Unlock()
		return
	}
	delete(client.routes, key)
	route.idle = nil
	client.stopRouteLivenessLocked(key, route.session)
	client.mu.Unlock()

	route.sender.stopAndCancel(mtproto.ErrSessionClosed)
	route.session.Close(mtproto.ErrSessionClosed)
	_ = client.pool.Discard(mtproto.PoolKey{
		DCID: key.dcid, Kind: mtproto.ConnectionKind(key.kind), Slot: key.slot,
	}, route.connection)
}
