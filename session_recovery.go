package raw

import (
	"crypto/rand"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/tl"
)

// applyInboundRecovery re-sends requests selected by the receive path with
// fresh message ids. Recovery writes run inline under the route mutexes
// (client.mu -> sendMu -> writeMu, matching the invoke fast path) so the
// fresh ids are allocated and written atomically with respect to every other
// writer; queueing them for a sender goroutine would let a concurrent invoke
// put a higher id on the wire first.
func (client *Client) applyInboundRecovery(
	key routeKey,
	route *clientRoute,
	result mtproto.InboundResult,
) error {
	if result.ResetSession || len(result.RecoveryTargets) != 0 {
		client.mu.Lock()
		sendMu, writeMu, owned := client.routeMutexesLocked(key, route)
		if !owned {
			// The route was replaced or torn down while this packet was in
			// flight; its recovery events refer to the old route.
			client.mu.Unlock()
			return nil
		}
		now := client.now()
		var sessionID [8]byte
		if result.ResetSession {
			if _, err := rand.Read(sessionID[:]); err != nil {
				client.mu.Unlock()
				return err
			}
		}
		sendMu.Lock()
		writeMu.Lock()
		var messages []tl.MTPMessage
		if result.ResetSession {
			messages = route.session.ResetAndRecover(sessionID, now)
		} else {
			messages = route.session.RecoverTargets(now, result.RecoveryTargets)
		}
		acks := route.sender.drainAcks()
		var err error
		if len(messages) != 0 || len(acks) != 0 {
			_, err = route.session.SendPrepared(
				route.connection, rand.Reader, now, messages, acks, false,
			)
		}
		writeMu.Unlock()
		if result.ResetSession && err == nil {
			// The rotated session has not run initConnection and the old
			// ordering keys reference ids the server no longer knows.
			if key == (routeKey{dcid: client.config.DCID, kind: ConnectionMain, slot: 0}) {
				client.initConnectionDone = false
				client.ordering = nil
			} else {
				route.initConnectionDone = false
				route.ordering = nil
			}
		}
		sendMu.Unlock()
		client.mu.Unlock()
		if err != nil {
			return err
		}
	}
	if len(result.ResendIDs) == 0 {
		return nil
	}
	request, err := mtproto.BuildResendRequest(result.ResendIDs)
	if err != nil {
		return err
	}
	route.writeMu.Lock()
	_, err = route.session.SendControl(
		route.connection,
		rand.Reader,
		client.now(),
		request,
	)
	route.writeMu.Unlock()
	return err
}
