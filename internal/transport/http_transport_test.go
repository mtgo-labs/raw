package transport

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHTTPConnNewInvalid(t *testing.T) {
	if _, err := NewHTTPConn(nil, "http://localhost"); err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestHTTPConnURLConstruction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	// host:port without scheme should get http:// prepended
	conn, err := NewHTTPConn(server.Client(), strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	if !strings.HasPrefix(conn.url, "http://") {
		t.Fatalf("expected http:// prefix, got %q", conn.url)
	}
}

func TestHTTPConnWritePacketRoundTrip(t *testing.T) {
	echo := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	}
	server := httptest.NewServer(http.HandlerFunc(echo))
	defer server.Close()

	conn, err := NewHTTPConn(server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	payload := []byte{0x01, 0x02, 0x03, 0x04}
	if err := conn.WritePacket(payload); err != nil {
		t.Fatal(err)
	}

	response, err := conn.ReadPacket(4096)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(response, payload) {
		t.Fatalf("expected %v, got %v", payload, response)
	}
}

func TestHTTPConnWritePacketReserved(t *testing.T) {
	echo := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	}
	server := httptest.NewServer(http.HandlerFunc(echo))
	defer server.Close()

	conn, err := NewHTTPConn(server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Simulate intermediate-framed packet: 4-byte length prefix + payload
	payload := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	packet := make([]byte, 4+len(payload))
	packet[0] = byte(len(payload))
	copy(packet[4:], payload)

	if err := conn.WritePacketReserved(packet, 4); err != nil {
		t.Fatal(err)
	}

	response, err := conn.ReadPacket(4096)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(response, payload) {
		t.Fatalf("expected %v, got %v", payload, response)
	}
}

func TestHTTPConnWritePacketReservedInvalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	conn, err := NewHTTPConn(server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := conn.WritePacketReserved([]byte{1}, -1); err == nil {
		t.Fatal("expected error for negative offset")
	}
	if err := conn.WritePacketReserved([]byte{1}, 1); err == nil {
		t.Fatal("expected error for offset equal to length")
	}
	if err := conn.WritePacketReserved([]byte{1}, 2); err == nil {
		t.Fatal("expected error for offset beyond length")
	}
}

func TestHTTPConnReadWrite(t *testing.T) {
	echo := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	}
	server := httptest.NewServer(http.HandlerFunc(echo))
	defer server.Close()

	conn, err := NewHTTPConn(server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Write via standard Write (simulates transport.WriteIntermediate which calls writeFull)
	payload := []byte("hello world")
	n, err := conn.Write(payload)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Fatalf("wrote %d, expected %d", n, len(payload))
	}

	// Read back
	buf := make([]byte, 128)
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello world" {
		t.Fatalf("expected 'hello world', got %q", string(buf[:n]))
	}
}

func TestHTTPConnClose(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	conn, err := NewHTTPConn(server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	// Double close should be safe
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	// Write after close should fail
	if _, err := conn.Write([]byte{1}); err == nil {
		t.Fatal("expected error writing to closed conn")
	}

	// Read after close should fail
	buf := make([]byte, 128)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected error reading from closed conn")
	}
}

func TestHTTPConnConcurrent(t *testing.T) {
	echo := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	}
	server := httptest.NewServer(http.HandlerFunc(echo))
	defer server.Close()

	conn, err := NewHTTPConn(server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var wg sync.WaitGroup
	errCh := make(chan error, 20)

	// Writer: write sequentially (simulates writeMu serialization)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			if err := conn.WritePacket([]byte{byte(i)}); err != nil {
				errCh <- err
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	// Reader: read sequentially (simulates receive goroutine)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			data, err := conn.ReadPacket(4096)
			if err != nil {
				errCh <- err
				return
			}
			if len(data) != 1 {
				errCh <- err
				return
			}
		}
	}()

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

func TestHTTPConnLocalAddr(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	conn, err := NewHTTPConn(server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	addr := conn.LocalAddr()
	if addr == nil {
		t.Fatal("LocalAddr returned nil")
	}
	if addr.Network() != "http" {
		t.Fatalf("expected network 'http', got %q", addr.Network())
	}
}

func TestHTTPConnRemoteAddr(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	conn, err := NewHTTPConn(server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if addr := conn.RemoteAddr(); addr == nil {
		t.Fatal("RemoteAddr returned nil")
	}
}

func TestHTTPConnDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	conn, err := NewHTTPConn(server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPConnInterfaceCheck(t *testing.T) {
	// Verify httpConn implements net.Conn
	var _ net.Conn = (*httpConn)(nil)
}

func TestHTTPConnServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	conn, err := NewHTTPConn(server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := conn.WritePacket([]byte{1}); err != nil {
		t.Fatal(err)
	}

	if _, err := conn.ReadPacket(4096); err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestHTTPConnEmptyRead(t *testing.T) {
	// Read should block until Write provides data or Close is called.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("response"))
	}))
	defer server.Close()

	conn, err := NewHTTPConn(server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}

	// Write then close, read should get data then EOF
	if err := conn.WritePacket([]byte{1}); err != nil {
		t.Fatal(err)
	}

	// First read gets the response
	data, err := conn.ReadPacket(4096)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "response" {
		t.Fatalf("expected 'response', got %q", string(data))
	}

	// Second read blocks - close to unblock
	done := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Millisecond)
		conn.Close()
		close(done)
	}()

	_, err = conn.ReadPacket(4096)
	if err == nil {
		t.Fatal("expected error after close")
	}

	<-done
}

func TestHTTPConnLargePayload(t *testing.T) {
	echo := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	}
	server := httptest.NewServer(http.HandlerFunc(echo))
	defer server.Close()

	conn, err := NewHTTPConn(server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// 1MB payload
	payload := bytes.Repeat([]byte{0x42}, 1024*1024)

	if err := conn.WritePacket(payload); err != nil {
		t.Fatal(err)
	}

	response, err := conn.ReadPacket(2 * 1024 * 1024)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(response, payload) {
		t.Fatalf("large payload mismatch: got %d bytes, expected %d", len(response), len(payload))
	}
}

func TestHTTPConnMultipleWritesBeforeRead(t *testing.T) {
	// Simulates WriteIntermediate (header + payload as separate Write calls).
	echo := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	}
	server := httptest.NewServer(http.HandlerFunc(echo))
	defer server.Close()

	conn, err := NewHTTPConn(server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Two separate writes (simulating intermediate framing header + payload)
	header := []byte{0x04, 0x00, 0x00, 0x00} // length=4 in little-endian
	payload := []byte{0xde, 0xad, 0xbe, 0xef}

	conn.Write(header)
	conn.Write(payload)

	// Read should send both as one HTTP request
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	expected := append(header, payload...)
	if !bytes.Equal(buf[:n], expected) {
		t.Fatalf("expected %v, got %v", expected, buf[:n])
	}
}
