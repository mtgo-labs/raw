package raw

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/tl"
)

var ErrPingTimeout = errors.New("raw: ping timeout")

type routeLiveness struct {
	session    *mtproto.Session
	connection net.Conn
	writeMu    *sync.Mutex
	stop       chan struct{}
	pong       chan struct{}

	mu        sync.Mutex
	pingID    int64
	messageID uint64
	// A fast server can answer before SendPing returns its message ID.
	earlyPongID   uint64
	earlyPongTime time.Time
	sentAt        time.Time
	outstanding   bool
	lastRTT       time.Duration
	hasRTT        bool
}

func (client *Client) startRouteLivenessLocked(
	key routeKey,
	sessionState *mtproto.Session,
	connection net.Conn,
	writeMu *sync.Mutex,
) {
	if client.config.Liveness.Disabled || sessionState == nil || connection == nil || writeMu == nil {
		return
	}
	client.stopRouteLivenessLocked(key, nil)
	liveness := &routeLiveness{
		session:    sessionState,
		connection: connection,
		writeMu:    writeMu,
		stop:       make(chan struct{}),
		pong:       make(chan struct{}, 1),
	}
	client.liveness[key] = liveness
	client.livenessWG.Add(1)
	interval := addDurationSaturated(client.config.Liveness.PingInterval, client.pingJitter())
	go client.runRouteLiveness(key, liveness, interval)
}

// runRouteLiveness alternates one timer between the next ping and the current
// pong deadline. It never observes or schedules individual RPCs.
func (client *Client) runRouteLiveness(key routeKey, liveness *routeLiveness, interval time.Duration) {
	defer client.livenessWG.Done()
	timer := time.NewTimer(interval)
	defer timer.Stop()
	waitingForPong := false

	for {
		select {
		case <-liveness.stop:
			return
		case <-liveness.pong:
			waitingForPong = false
			resetLivenessTimer(timer, interval)
		case <-timer.C:
			if waitingForPong {
				if liveness.pingOutstanding() {
					client.failConnectedRoute(key, liveness.session, liveness.connection, ErrPingTimeout)
					return
				}
				waitingForPong = false
				resetLivenessTimer(timer, interval)
				continue
			}
			select {
			case <-liveness.stop:
				return
			default:
			}
			pingID, err := client.nextPingID()
			if err != nil {
				client.failConnectedRoute(key, liveness.session, liveness.connection, err)
				return
			}
			sentAt := client.now()
			liveness.beginPing(pingID, sentAt)
			liveness.writeMu.Lock()
			messageID, err := liveness.session.SendPing(
				liveness.connection,
				rand.Reader,
				sentAt,
				pingID,
				pingDisconnectDelay(interval, client.config.Liveness.PongTimeout),
			)
			liveness.writeMu.Unlock()
			if err != nil {
				liveness.cancelPing()
				client.failConnectedRoute(key, liveness.session, liveness.connection, err)
				return
			}
			if liveness.finishPingSend(messageID) {
				resetLivenessTimer(timer, interval)
				continue
			}
			waitingForPong = true
			resetLivenessTimer(timer, client.config.Liveness.PongTimeout)
		}
	}
}

func (client *Client) handleRouteLiveness(key routeKey, route *clientRoute, result mtproto.InboundResult) bool {
	if len(result.Pongs) != 0 {
		client.mu.Lock()
		liveness := client.liveness[key]
		if liveness != nil && (liveness.session != route.session || liveness.connection != route.connection) {
			liveness = nil
		}
		client.mu.Unlock()
		if liveness != nil {
			now := client.now()
			for _, pong := range result.Pongs {
				liveness.acceptPong(pong, now)
			}
		}
	}
	if len(result.Pings) == 0 {
		return true
	}

	client.mu.Lock()
	writeMu, owned := client.routeWriteMutexLocked(key, route)
	client.mu.Unlock()
	if !owned {
		return false
	}
	writeMu.Lock()
	var err error
	for _, ping := range result.Pings {
		if ping.MessageID == 0 {
			continue
		}
		_, err = route.session.SendControl(
			route.connection,
			rand.Reader,
			client.now(),
			&tl.MTPPong{MessageID: int64(ping.MessageID), PingID: ping.PingID},
		)
		if err != nil {
			break
		}
	}
	writeMu.Unlock()
	if err != nil {
		client.failConnectedRoute(key, route.session, route.connection, err)
		return false
	}
	return true
}

func (client *Client) routeWriteMutexLocked(key routeKey, route *clientRoute) (*sync.Mutex, bool) {
	if client.closed || route == nil {
		return nil, false
	}
	if key == (routeKey{dcid: client.config.DCID, kind: ConnectionMain, slot: 0}) {
		return &client.writeMu, client.session == route.session && client.conn == route.connection
	}
	current := client.routes[key]
	return &route.writeMu, current == route
}

func (client *Client) stopRouteLivenessLocked(key routeKey, sessionState *mtproto.Session) {
	liveness := client.liveness[key]
	if liveness == nil || sessionState != nil && liveness.session != sessionState {
		return
	}
	delete(client.liveness, key)
	close(liveness.stop)
}

func (client *Client) stopAllRouteLivenessLocked() {
	for key, liveness := range client.liveness {
		delete(client.liveness, key)
		close(liveness.stop)
	}
}

func (client *Client) defaultPingJitter() time.Duration {
	limit := min(5*time.Second, client.config.Liveness.PingInterval/12)
	if limit <= 0 {
		return 0
	}
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return 0
	}
	return time.Duration(binary.LittleEndian.Uint64(value[:]) % (uint64(limit) + 1))
}

func randomPingID() (int64, error) {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint64(value[:])), nil
}

func pingDisconnectDelay(interval, timeout time.Duration) int32 {
	// The margin prevents the server timer from winning a local scheduling race.
	seconds := ceilSeconds(interval) + ceilSeconds(timeout) + 2
	if seconds > int64(1<<31-1) {
		return 1<<31 - 1
	}
	return int32(seconds)
}

func ceilSeconds(duration time.Duration) int64 {
	seconds := int64(duration / time.Second)
	if duration%time.Second != 0 {
		seconds++
	}
	return seconds
}

func addDurationSaturated(left, right time.Duration) time.Duration {
	const maxDuration = time.Duration(1<<63 - 1)
	if right > 0 && left > maxDuration-right {
		return maxDuration
	}
	return left + right
}

func resetLivenessTimer(timer *time.Timer, delay time.Duration) {
	if delay <= 0 {
		delay = time.Nanosecond
	}
	timer.Reset(delay)
}

func (liveness *routeLiveness) beginPing(pingID int64, sentAt time.Time) {
	liveness.mu.Lock()
	liveness.pingID = pingID
	liveness.messageID = 0
	liveness.earlyPongID = 0
	liveness.earlyPongTime = time.Time{}
	liveness.sentAt = sentAt
	liveness.outstanding = true
	liveness.mu.Unlock()
}

func (liveness *routeLiveness) finishPingSend(messageID uint64) bool {
	liveness.mu.Lock()
	liveness.messageID = messageID
	matched := liveness.earlyPongID == messageID
	if matched {
		liveness.completePingLocked(liveness.earlyPongTime)
	}
	liveness.earlyPongID = 0
	liveness.earlyPongTime = time.Time{}
	liveness.mu.Unlock()
	if matched {
		liveness.notifyPong()
	}
	return matched
}

func (liveness *routeLiveness) acceptPong(pong mtproto.InboundPong, now time.Time) bool {
	if pong.MessageID == 0 {
		return false
	}
	liveness.mu.Lock()
	if !liveness.outstanding || pong.PingID != liveness.pingID {
		liveness.mu.Unlock()
		return false
	}
	if liveness.messageID == 0 {
		liveness.earlyPongID = pong.MessageID
		liveness.earlyPongTime = now
		liveness.mu.Unlock()
		return false
	}
	if pong.MessageID != liveness.messageID {
		liveness.mu.Unlock()
		return false
	}
	liveness.completePingLocked(now)
	liveness.mu.Unlock()
	liveness.notifyPong()
	return true
}

func (liveness *routeLiveness) completePingLocked(now time.Time) {
	rtt := max(now.Sub(liveness.sentAt), 0)
	liveness.lastRTT = rtt
	liveness.hasRTT = true
	liveness.outstanding = false
}

func (liveness *routeLiveness) cancelPing() {
	liveness.mu.Lock()
	liveness.outstanding = false
	liveness.mu.Unlock()
}

func (liveness *routeLiveness) pingOutstanding() bool {
	liveness.mu.Lock()
	outstanding := liveness.outstanding
	liveness.mu.Unlock()
	return outstanding
}

func (liveness *routeLiveness) rtt() (time.Duration, bool) {
	liveness.mu.Lock()
	rtt := liveness.lastRTT
	ok := liveness.hasRTT
	liveness.mu.Unlock()
	return rtt, ok
}

func (liveness *routeLiveness) notifyPong() {
	select {
	case liveness.pong <- struct{}{}:
	default:
	}
}
