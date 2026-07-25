package raw

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/tl"
)

// BenchmarkRawResult measures the zero-copy slicing overhead.
func BenchmarkRawResult(b *testing.B) {
	// Simulate a decrypted body: 12-byte MTProto header + rpc_result(4) + req_msg_id(8) + inner_ctor(4) + payload
	payload := make([]byte, 12+4+8+4+1024)
	binary.LittleEndian.PutUint32(payload[12:16], rpcResultConstructor) // rpc_result#f35c6d01
	binary.LittleEndian.PutUint64(payload[16:24], 1)                    // req_msg_id
	binary.LittleEndian.PutUint32(payload[24:28], 0x12345678)           // inner constructor
	// The rawResult function receives body[12:] (the slice past the MTProto header)
	rawBody := payload[12:]
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		result := rawResult(rawBody)
		if result.Constructor != 0x12345678 {
			b.Fatalf("constructor=%#x", result.Constructor)
		}
	}
}

// BenchmarkResolveRPCResultRaw measures the pending-table resolve with rawBody.
func BenchmarkResolveRPCResultRaw(b *testing.B) {
	table := mtproto.NewPendingTable(b.N + 1)
	rawBody := make([]byte, 4+8+4+256)
	binary.LittleEndian.PutUint32(rawBody, tl.MTPRPCResultConstructorID)
	binary.LittleEndian.PutUint64(rawBody[4:], 1)
	binary.LittleEndian.PutUint32(rawBody[12:], tl.HelpGetConfigRequestConstructorID)

	b.ReportAllocs()
	b.ResetTimer()
	for index := range b.N {
		messageID := uint64(index + 1)
		if _, err := table.Add(messageID); err != nil {
			b.Fatal(err)
		}
		result := &tl.MTPRPCResult{ReqMessageID: int64(messageID), Result: &tl.Config{}}
		resolved, err := table.ResolveRPCResult(result, rawBody)
		if err != nil || !resolved {
			b.Fatalf("resolved=%v err=%v", resolved, err)
		}
	}
}

// BenchmarkResolveRPCResultReEncode measures the OLD path (when rawBody is nil).
func BenchmarkResolveRPCResultReEncode(b *testing.B) {
	table := mtproto.NewPendingTable(b.N + 1)

	b.ReportAllocs()
	b.ResetTimer()
	for index := range b.N {
		messageID := uint64(index + 1)
		if _, err := table.Add(messageID); err != nil {
			b.Fatal(err)
		}
		result := &tl.MTPRPCResult{ReqMessageID: int64(messageID), Result: &tl.Config{}}
		resolved, err := table.ResolveRPCResult(result, nil)
		if err != nil || !resolved {
			b.Fatalf("resolved=%v err=%v", resolved, err)
		}
	}
}

// BenchmarkInvokeRouteRawResult is the end-to-end raw-path benchmark.
func BenchmarkInvokeRouteRawResult(b *testing.B) {
	client, server, key, sessionID := newInitConnectionTranscriptClient(b, Config{
		APIID: 1, Address: "127.0.0.1:1",
	})
	client.initConnectionDone = true
	request := &tl.HelpGetConfigRequest{}

	// Pre-encoded Config response: constructor + flags + zero fields
	// Config is a large struct, so encode it once and reuse.
	configBody, err := tl.Encode(&tl.Config{})
	if err != nil {
		b.Fatal(err)
	}

	serverDone := make(chan error, 1)
	go func() {
		var err error
		for range b.N {
			var messageID uint64
			var body []byte
			messageID, body, err = readClientRequest(server, key, sessionID)
			if err == nil && binary.LittleEndian.Uint32(body) != tl.HelpGetConfigRequestConstructorID {
				err = fmt.Errorf("steady-state constructor=%#x", binary.LittleEndian.Uint32(body))
			}
			if err != nil {
				_ = server.SetDeadline(time.Now())
				break
			}
			if err = writeServerResultRaw(server, key, sessionID, messageID, configBody); err != nil {
				_ = server.SetDeadline(time.Now())
				break
			}
		}
		serverDone <- err
	}()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		result, err := invokeRouteRawResult(context.Background(), client, request, InvokeOptions{})
		if err != nil {
			b.Fatal(err)
		}
		if result.Constructor != tl.ConfigConstructorID {
			b.Fatalf("constructor=%#x", result.Constructor)
		}
	}
	b.StopTimer()
	if err := <-serverDone; err != nil {
		b.Fatal(err)
	}
}

// BenchmarkInvokeRouteTyped is the typed-path benchmark for comparison.
func BenchmarkInvokeRouteTyped(b *testing.B) {
	client, server, key, sessionID := newInitConnectionTranscriptClient(b, Config{
		APIID: 1, Address: "127.0.0.1:1",
	})
	client.initConnectionDone = true
	request := &tl.HelpGetConfigRequest{}

	serverDone := make(chan error, 1)
	go func() {
		var err error
		for range b.N {
			var messageID uint64
			var body []byte
			messageID, body, err = readClientRequest(server, key, sessionID)
			if err == nil && binary.LittleEndian.Uint32(body) != tl.HelpGetConfigRequestConstructorID {
				err = fmt.Errorf("steady-state constructor=%#x", binary.LittleEndian.Uint32(body))
			}
			if err != nil {
				_ = server.SetDeadline(time.Now())
				break
			}
			if err = writeServerResult(server, key, sessionID, messageID, &tl.Config{}); err != nil {
				_ = server.SetDeadline(time.Now())
				break
			}
		}
		serverDone <- err
	}()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := invokeRoute(context.Background(), client, request, InvokeOptions{}); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if err := <-serverDone; err != nil {
		b.Fatal(err)
	}
}
