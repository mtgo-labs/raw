package raw

import (
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/mtgo-labs/raw/internal/mtproto"
	"github.com/mtgo-labs/raw/tl"
)

// TestRawResultZeroCopy verifies that RawResult.Payload shares the backing
// array with the decrypted body buffer — no hidden copies or allocations.
func TestRawResultZeroCopy(t *testing.T) {
	// Simulate what decryptMessageEnvelope returns:
	// MTProto header (12 bytes) + rpc_result ctor (4) + req_msg_id (8) + inner ctor (4) + payload
	innerPayload := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	// body layout: [0:12]=mtproto header, [12:16]=rpc_result ctor, [16:24]=req_msg_id, [24:28]=inner ctor, [28:]=inner payload
	body := make([]byte, 12+4+8+4+len(innerPayload))
	binary.LittleEndian.PutUint32(body[12:16], rpcResultConstructor) // rpc_result ctor
	binary.LittleEndian.PutUint64(body[16:24], 1)                    // req_msg_id
	binary.LittleEndian.PutUint32(body[24:28], 0xDEADBEEF)           // inner ctor
	copy(body[28:], innerPayload)                                    // inner payload

	// Extract rawBody as receiveSessionPayloadAt does
	rawBody := body[12:]

	// Pass through ResolveRPCResult
	result := &tl.MTPRPCResult{ReqMessageID: 1, Result: &tl.Config{}}
	table := mtproto.NewPendingTable(2)
	if _, err := table.Add(1); err != nil {
		t.Fatal(err)
	}
	resolved, err := table.ResolveRPCResult(result, rawBody)
	if err != nil || !resolved {
		t.Fatalf("resolved=%v err=%v", resolved, err)
	}

	pending, err := table.Wait(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}

	// Extract RawResult
	rr := rawResult(pending.Result.Body)
	if rr.Constructor != 0xDEADBEEF {
		t.Fatalf("constructor=%#x", rr.Constructor)
	}

	// Verify same backing array: RawResult.Payload should be backed by body
	bodyPtr := uintptr(unsafe.Pointer(unsafe.SliceData(body)))
	payloadPtr := uintptr(unsafe.Pointer(unsafe.SliceData(rr.Payload)))

	// Payload starts at body[28:] (12 header + 4 rpc_result ctor + 8 req_msg_id + 4 inner ctor)
	expectedOffset := bodyPtr + 28
	if payloadPtr != expectedOffset {
		t.Fatalf("payload pointer mismatch: body=%#x payload=%#x expected=%#x (diff=%d, body[28:]=%#x)",
			bodyPtr, payloadPtr, expectedOffset, int(payloadPtr)-int(bodyPtr), bodyPtr+28)
	}
	t.Logf("Zero-copy confirmed: body=%#x payload=%#x offset=%d", bodyPtr, payloadPtr, int(payloadPtr)-int(bodyPtr))

	// Verify payload content
	if len(rr.Payload) != len(innerPayload) {
		t.Fatalf("payload length=%d expected=%d", len(rr.Payload), len(innerPayload))
	}
	for i, v := range innerPayload {
		if rr.Payload[i] != v {
			t.Fatalf("payload[%d]=%#x expected=%#x", i, rr.Payload[i], v)
		}
	}

	// Verify no hidden copy by confirming they're exactly the same slice position
	expectedSlice := body[28:]
	if uintptr(unsafe.Pointer(unsafe.SliceData(expectedSlice))) != payloadPtr {
		t.Fatal("hidden copy detected: expected slice and payload have different backing arrays")
	}
	t.Log("No hidden copy: payload IS body[28:]")
}

// TestRawResultLifetime verifies that RawResult data remains valid after
// the pending request is removed (ownership is with the caller).
func TestRawResultLifetime(t *testing.T) {
	innerPayload := []byte("test-payload-data")
	body := make([]byte, 12+4+8+4+len(innerPayload))
	binary.LittleEndian.PutUint32(body[12:16], rpcResultConstructor)
	binary.LittleEndian.PutUint64(body[16:24], 1)
	binary.LittleEndian.PutUint32(body[24:28], 0x12345678)
	copy(body[28:], innerPayload)

	rawBody := body[12:]
	table := mtproto.NewPendingTable(2)
	if _, err := table.Add(1); err != nil {
		t.Fatal(err)
	}
	result := &tl.MTPRPCResult{ReqMessageID: 1, Result: &tl.Config{}}
	_, err := table.ResolveRPCResult(result, rawBody)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := table.Wait(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}

	rr := rawResult(pending.Result.Body)

	// Wait already deletes the entry. RawResult should still be valid because
	// its Payload slice points into the body buffer, not the pending table.
	if rr.Constructor != 0x12345678 {
		t.Fatalf("constructor changed after wait: %#x", rr.Constructor)
	}
	if string(rr.Payload) != string(innerPayload) {
		t.Fatalf("payload changed after wait: %q", rr.Payload)
	}
	t.Log("Lifetime verified: RawResult payload survives Wait-based table removal")
}
