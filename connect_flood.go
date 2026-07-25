package raw

import "time"

const maxConnectionFloodEvents = 8

var (
	connectionSanityRules = [...]connectionFloodRule{
		{count: 5, window: 10 * time.Second},
	}
	connectionAttemptRules = [...]connectionFloodRule{
		{count: 1, window: time.Second},
		{count: 4, window: 2 * time.Second},
		{count: 8, window: 3 * time.Second},
	}
)

type ConnectionFloodError struct {
	RetryAfter time.Duration
}

func (*ConnectionFloodError) Error() string {
	return ErrConnectionFlood.Error()
}

func (*ConnectionFloodError) Unwrap() error {
	return ErrConnectionFlood
}

type connectionFloodRule struct {
	count  int
	window time.Duration
}

type connectionFloodEvents struct {
	values [maxConnectionFloodEvents]int64
	length int
}

type connectionFloodControl struct {
	attempts      connectionFloodEvents
	mtprotoErrors connectionFloodEvents
}

func (control *connectionFloodControl) admit(now time.Time) time.Duration {
	if control == nil {
		return 0
	}
	nowNanos := now.UnixNano()
	control.attempts.prune(nowNanos, 10*time.Second)
	control.mtprotoErrors.prune(nowNanos, 3*time.Second)
	wakeup := control.attempts.wakeup(nowNanos, connectionSanityRules[:])
	if candidate := control.attempts.wakeup(nowNanos, connectionAttemptRules[:]); candidate > wakeup {
		wakeup = candidate
	}
	if candidate := control.mtprotoErrors.wakeup(nowNanos, connectionAttemptRules[:]); candidate > wakeup {
		wakeup = candidate
	}
	if wakeup > nowNanos {
		return time.Duration(wakeup - nowNanos)
	}
	control.attempts.add(nowNanos)
	return 0
}

func (control *connectionFloodControl) addMTProtoError(now time.Time) {
	if control == nil {
		return
	}
	nowNanos := now.UnixNano()
	control.mtprotoErrors.prune(nowNanos, 3*time.Second)
	control.mtprotoErrors.add(nowNanos)
}

func (events *connectionFloodEvents) wakeup(nowNanos int64, rules []connectionFloodRule) int64 {
	var wakeup int64
	for _, rule := range rules {
		cutoff := nowNanos - int64(rule.window)
		first := events.length
		for first > 0 && events.values[first-1] > cutoff {
			first--
		}
		if events.length-first < rule.count {
			continue
		}
		candidate := events.values[first] + int64(rule.window)
		if candidate > wakeup {
			wakeup = candidate
		}
	}
	return wakeup
}

func (events *connectionFloodEvents) add(nowNanos int64) {
	if events.length == len(events.values) {
		copy(events.values[:], events.values[1:])
		events.length--
	}
	events.values[events.length] = nowNanos
	events.length++
}

func (events *connectionFloodEvents) prune(nowNanos int64, maxWindow time.Duration) {
	cutoff := nowNanos - int64(maxWindow)
	first := 0
	for first < events.length && events.values[first] <= cutoff {
		first++
	}
	if first == 0 {
		return
	}
	copy(events.values[:], events.values[first:events.length])
	events.length -= first
}
