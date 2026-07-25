package raw

import (
	"crypto/rand"

	"github.com/mtgo-labs/raw/internal/mtproto"
)

func (client *Client) applyInboundRecovery(
	key routeKey,
	route *clientRoute,
	result mtproto.InboundResult,
) error {
	if result.ResetSession {
		var sessionID [8]byte
		if _, err := rand.Read(sessionID[:]); err != nil {
			return err
		}
		messages := route.session.ResetAndRecover(sessionID, client.now())
		if err := route.sender.replaceRequests(messages); err != nil {
			return err
		}
		client.mu.Lock()
		if key == (routeKey{dcid: client.config.DCID, kind: ConnectionMain, slot: 0}) &&
			client.session == route.session && client.conn == route.connection {
			client.initConnectionDone = false
			client.ordering = nil
		} else if current := client.routes[key]; current == route {
			current.initConnectionDone = false
			current.ordering = nil
		}
		client.mu.Unlock()
	} else {
		for _, message := range result.RetryMessages {
			if err := route.sender.enqueueRequest(message); err != nil {
				return err
			}
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
