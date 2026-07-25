package raw

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestConnectionFloodControlComposesAttemptRules(t *testing.T) {
	var control connectionFloodControl
	now := time.Unix(1_700_000_000, 0)
	for attempt := range 5 {
		at := now.Add(time.Duration(attempt) * time.Second)
		if retryAfter := control.admit(at); retryAfter != 0 {
			t.Fatalf("attempt %d retry=%v", attempt, retryAfter)
		}
	}
	if retryAfter := control.admit(now.Add(5 * time.Second)); retryAfter != 5*time.Second {
		t.Fatalf("sanity retry=%v", retryAfter)
	}
	if retryAfter := control.admit(now.Add(10 * time.Second)); retryAfter != 0 {
		t.Fatalf("boundary retry=%v", retryAfter)
	}
}

func TestConnectionFloodControlIncludesMTProtoErrors(t *testing.T) {
	var control connectionFloodControl
	now := time.Unix(1_700_000_000, 0)
	control.addMTProtoError(now)
	if retryAfter := control.admit(now); retryAfter != time.Second {
		t.Fatalf("MTProto retry=%v", retryAfter)
	}
	if retryAfter := control.admit(now.Add(time.Second)); retryAfter != 0 {
		t.Fatalf("MTProto boundary retry=%v", retryAfter)
	}
}

func TestConnectionFloodControlIsIndependentPerRoute(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	client.mu.Lock()
	primary := client.connectionFloodLocked(routeKey{dcid: 2, kind: ConnectionMain})
	download := client.connectionFloodLocked(routeKey{dcid: 2, kind: ConnectionDownload})
	client.mu.Unlock()

	if retryAfter := primary.admit(now); retryAfter != 0 {
		t.Fatalf("primary first retry=%v", retryAfter)
	}
	if retryAfter := primary.admit(now); retryAfter != time.Second {
		t.Fatalf("primary second retry=%v", retryAfter)
	}
	if retryAfter := download.admit(now); retryAfter != 0 {
		t.Fatalf("independent route retry=%v", retryAfter)
	}
}

func TestClientRateLimitsRepeatedFailedDials(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(Config{
		APIID: 1, Address: address,
		AuthKey: bytes.Repeat([]byte{1}, 256), AuthKeyID: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	now := time.Unix(1_700_000_000, 0)
	client.now = func() time.Time { return now }

	if err := client.Connect(context.Background()); err == nil || errors.Is(err, ErrConnectionFlood) {
		t.Fatalf("first dial err=%v", err)
	}
	err = client.Connect(context.Background())
	var flood *ConnectionFloodError
	if !errors.As(err, &flood) || flood.RetryAfter != time.Second || !errors.Is(err, ErrConnectionFlood) {
		t.Fatalf("second dial err=%v", err)
	}

	now = now.Add(time.Second)
	if err := client.Connect(context.Background()); err == nil || errors.Is(err, ErrConnectionFlood) {
		t.Fatalf("boundary dial err=%v", err)
	}
}

func BenchmarkConnectionFloodAdmit(b *testing.B) {
	var control connectionFloodControl
	now := time.Unix(1_700_000_000, 0)
	b.ReportAllocs()
	for b.Loop() {
		if retryAfter := control.admit(now); retryAfter != 0 {
			b.Fatal(retryAfter)
		}
		now = now.Add(10 * time.Second)
	}
}
