package raw

// Latency decomposition for the RPC hot path. Each benchmark isolates one
// stage of: invoke → prepare → encode+encrypt+Write → kernel/network →
// receive → resolve → waiter wakeup. The TCP benchmarks use the production
// wiring (PacketConn over TCPConn with TCP_NODELAY, receive goroutine,
// direct-write invokeRoute); the pipe benchmark uses PacketConn over
// net.Pipe so the reserved single-write framing path is the one measured.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/internal/transport"
	"github.com/mtgo-labs/raw/tl"
)

// BenchmarkHotPathPrepare measures invokeRoute's prepare stage:
// EncodedSize + message-ID/sequence allocation + pending-table insert.
func BenchmarkHotPathPrepare(b *testing.B) {
	const window = 1 << 16
	now := time.Unix(1_700_000_000, 0)
	sessionState := mtproto.NewSession(testAuthKey(2), 0, [8]byte{2}, window+8)
	request := &tl.HelpGetConfigRequest{}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; b.Loop(); index++ {
		if index%window == 0 {
			sessionState = mtproto.NewSession(testAuthKey(2), 0, [8]byte{2}, window+8)
		}
		if _, _, err := sessionState.Prepare(now, request); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHotPathEncodeWrite measures the write stage of invokeRoute:
// SendPrepared = pending validation + salt/session lookup + markSent +
// TL encode + MTProto 2.0 encrypt (AES key schedule + IGE) + framed Write,
// through a PacketConn over net.Pipe whose far end is drained by a reader.
// Write returns only after the reader consumes the bytes, so this is
// encode → Write() → return with zero kernel involvement.
func BenchmarkHotPathEncodeWrite(b *testing.B) {
	now := time.Unix(1_700_000_000, 0)
	key := testAuthKey(2)
	clientEnd, serverEnd := net.Pipe()
	defer serverEnd.Close()
	go func() {
		buffer := make([]byte, 1<<16)
		for {
			if _, err := serverEnd.Read(buffer); err != nil {
				return
			}
		}
	}()
	packetConn, err := transport.NewPacketConn(clientEnd, transport.PacketIntermediate)
	if err != nil {
		b.Fatal(err)
	}
	const window = 1 << 16
	sessionState := mtproto.NewSession(key, 0, [8]byte{2}, window+8)
	request := &tl.HelpGetConfigRequest{}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; b.Loop(); index++ {
		if index%window == 0 {
			sessionState = mtproto.NewSession(key, 0, [8]byte{2}, window+8)
		}
		message, _, err := sessionState.Prepare(now, request)
		if err != nil {
			b.Fatal(err)
		}
		messages := [...]tl.MTPMessage{message}
		if _, err := sessionState.SendPrepared(packetConn, rand.Reader, now, messages[:], nil, false); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHotPathCompletionHandoff measures the receive-loop → waiter
// wakeup: PendingTable.Resolve (close under mutex) on one goroutine and
// WaitRequest on another, alternating. Each iteration is one goroutine
// wakeup round trip, i.e. the scheduling cost a response pays after the
// receive loop decrypts and resolves it.
func BenchmarkHotPathCompletionHandoff(b *testing.B) {
	table := mtproto.NewPendingTable(2)
	ready := make(chan *mtproto.PendingRequest)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case request := <-ready:
				table.Resolve(request.MessageID, mtproto.PendingResult{Body: []byte{}})
			case <-quit:
				return
			}
		}
	}()
	b.Cleanup(func() { close(quit) })
	var mu sync.Mutex
	nextID := uint64(1)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		mu.Lock()
		messageID := nextID
		nextID++
		mu.Unlock()
		request, err := table.AddMessage(messageID, tl.MTPMessage{}, false)
		if err != nil {
			b.Fatal(err)
		}
		ready <- request
		if _, err := table.WaitRequest(context.Background(), request); err != nil {
			b.Fatal(err)
		}
	}
}

// goroutine. The server answers every help.getConfig with a fixed Config.
func newLoopbackTCPClient(tb testing.TB) (*Client, chan error) {
	tb.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	key := testAuthKey(2)
	sessionID := [8]byte{2}
	configBody, err := tl.Encode(&tl.Config{})
	if err != nil {
		tb.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		_ = listener.Close()
		header := make([]byte, 4)
		if _, err := io.ReadFull(connection, header); err != nil {
			_ = connection.Close()
			serverDone <- err
			return
		}
		if binary.LittleEndian.Uint32(header) != 0xeeeeeeee {
			_ = connection.Close()
			serverDone <- fmt.Errorf("unexpected transport header %#x", binary.LittleEndian.Uint32(header))
			return
		}
		for {
			messageID, body, err := readClientRequest(connection, key, sessionID)
			if err == nil && len(body) < 4 {
				err = fmt.Errorf("short request body")
			}
			if err == nil {
				err = writeServerResultRaw(connection, key, sessionID, messageID, configBody)
			}
			if err != nil {
				_ = connection.SetDeadline(time.Now())
				_ = connection.Close()
				serverDone <- nil
				return
			}
		}
	}()

	client, err := NewClient(Config{APIID: 1, Address: listener.Addr().String()})
	if err != nil {
		tb.Fatal(err)
	}
	connection, err := transport.DialPacket(context.Background(), listener.Addr().String(), transport.PacketIntermediate)
	if err != nil {
		tb.Fatal(err)
	}
	sessionState := mtproto.NewSession(key, 0, sessionID, 256)
	client.mu.Lock()
	client.conn = connection
	client.session = sessionState
	client.permanent = authState{key: key, sessionID: sessionID}
	client.startReceiveRouteLocked(
		routeKey{dcid: client.config.DCID, kind: ConnectionMain},
		&clientRoute{connection: connection, session: sessionState},
	)
	client.mu.Unlock()
	client.initConnectionDone = true
	tb.Cleanup(func() {
		_ = client.Close()
		_ = connection.Close()
	})
	return client, serverDone
}

// BenchmarkHotPathInvokeLoopbackTCP measures the complete sequential RPC
// round trip over real TCP loopback with production wiring: flood-wait
// check, route selection, prepare, direct Write under sendMu/writeMu,
// kernel TCP in both directions, receive goroutine decrypt+resolve, waiter
// wakeup, raw result slice.
func BenchmarkHotPathInvokeLoopbackTCP(b *testing.B) {
	client, serverDone := newLoopbackTCPClient(b)
	request := &tl.HelpGetConfigRequest{}
	samples := make([]time.Duration, 0, 1<<16)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		start := time.Now()
		result, err := invokeRouteRawResult(context.Background(), client, request, InvokeOptions{})
		if err != nil {
			b.Fatal(err)
		}
		if result.Constructor != tl.ConfigConstructorID {
			b.Fatalf("constructor=%#x", result.Constructor)
		}
		samples = append(samples, time.Since(start))
	}
	b.StopTimer()
	_ = client.Close()
	if err := <-serverDone; err != nil {
		b.Fatal(err)
	}
	reportPercentiles(b, samples)
}

// BenchmarkHotPathInvokeTCPParallel runs concurrent invokes on one route to
// expose the cost of the correctness-required serialization points
// (client.mu route lookup, sendMu prepare+write, writeMu, pending.mu).
func BenchmarkHotPathInvokeTCPParallel(b *testing.B) {
	client, serverDone := newLoopbackTCPClient(b)
	request := &tl.HelpGetConfigRequest{}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(parallel *testing.PB) {
		for parallel.Next() {
			result, err := invokeRouteRawResult(context.Background(), client, request, InvokeOptions{})
			if err != nil {
				b.Error(err)
				return
			}
			if result.Constructor != tl.ConfigConstructorID {
				b.Errorf("constructor=%#x", result.Constructor)
				return
			}
		}
	})
	b.StopTimer()
	_ = client.Close()
	if err := <-serverDone; err != nil {
		b.Fatal(err)
	}
}

func reportPercentiles(b *testing.B, samples []time.Duration) {
	if len(samples) == 0 {
		return
	}
	sorted := make([]time.Duration, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	pick := func(fraction float64) time.Duration {
		return sorted[int(fraction*float64(len(sorted)-1))]
	}
	b.ReportMetric(float64(pick(0.50))/1e3, "p50_µs")
	b.ReportMetric(float64(pick(0.95))/1e3, "p95_µs")
	b.ReportMetric(float64(pick(0.99))/1e3, "p99_µs")
}
