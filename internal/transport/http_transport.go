package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// httpConn implements net.Conn over HTTP transport. Each Write buffers
// data; the next Read sends an HTTP POST with the accumulated write buffer
// and returns the response body. This matches MTProto's request-response
// pattern where every client write expects a server reply.
//
// httpConn is safe for concurrent use by one writer and one reader, which
// is the natural MTProto split (writeMu serializes all writes on a route,
// and receiveRoute is the sole reader).
type httpConn struct {
	client *http.Client
	url    string

	mu       sync.Mutex
	writeBuf bytes.Buffer
	readBuf  bytes.Buffer
	cond     *sync.Cond // broadcast when writeBuf has data or conn closes

	closed   bool
	closeErr error

	readDeadline  time.Time
	writeDeadline time.Time
}

// NewHTTPConn creates a connection that tunnels MTProto over HTTP POST.
// address is a host:port or full http(s) URL. The provided http.Client is
// shared across all routes for connection reuse.
func NewHTTPConn(client *http.Client, address string) (*httpConn, error) {
	if client == nil {
		return nil, errors.New("transport: nil HTTP client")
	}
	url := address
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}
	c := &httpConn{
		client: client,
		url:    url,
	}
	c.cond = sync.NewCond(&c.mu)
	return c, nil
}

// Write buffers p for the next HTTP round-trip. It never blocks for
// network I/O.
func (c *httpConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, c.closeErr
	}
	n, _ := c.writeBuf.Write(p)
	c.cond.Signal()
	return n, nil
}

// readHTTPLocked sends an HTTP POST with the accumulated write buffer and
// stores the response in the read buffer. Must be called with c.mu held.
// On return the caller still holds c.mu.
func (c *httpConn) readHTTPLocked(maxPayload int) error {
	if c.writeBuf.Len() == 0 {
		return nil
	}
	body := make([]byte, c.writeBuf.Len())
	copy(body, c.writeBuf.Bytes())
	c.writeBuf.Reset()

	ctx := context.Background()
	if !c.readDeadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, c.readDeadline)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Connection", "keep-alive")
	req.Close = false

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("transport: HTTP %d", resp.StatusCode)
	}

	limit := maxPayload
	if limit <= 0 {
		limit = DefaultMaxIntermediatePayload
	}
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)))
	if err != nil {
		return err
	}
	c.readBuf.Write(responseBody)
	return nil
}

// Read returns buffered response data, or triggers an HTTP round-trip if
// there is pending write data and no response data.
func (c *httpConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for {
		if c.closed {
			return 0, c.closeErr
		}
		if c.readBuf.Len() > 0 {
			return c.readBuf.Read(p)
		}
		if err := c.readHTTPLocked(DefaultMaxIntermediatePayload); err != nil {
			return 0, err
		}
		if c.readBuf.Len() > 0 {
			return c.readBuf.Read(p)
		}
		if c.writeBuf.Len() == 0 {
			c.cond.Wait()
		}
	}
}

// WritePacket sends a raw payload over HTTP. The payload is buffered and
// sent as the HTTP request body on the next ReadPacket or Read call.
func (c *httpConn) WritePacket(payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return c.closeErr
	}
	c.writeBuf.Write(payload)
	c.cond.Signal()
	return nil
}

// WritePacketReserved extracts the payload from an intermediate-framed
// packet and buffers it for HTTP transport. payloadOffset must point past
// the 4-byte intermediate length prefix.
func (c *httpConn) WritePacketReserved(packet []byte, payloadOffset int) error {
	if payloadOffset < 0 || payloadOffset >= len(packet) {
		return errors.New("transport: invalid reserved packet")
	}
	return c.WritePacket(packet[payloadOffset:])
}

// ReadPacket waits for buffered write data, sends it as an HTTP POST,
// and returns the response body.
func (c *httpConn) ReadPacket(maxPayload int) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for {
		if c.closed {
			return nil, c.closeErr
		}
		if err := c.readHTTPLocked(maxPayload); err != nil {
			return nil, err
		}
		if c.readBuf.Len() > 0 {
			data := make([]byte, c.readBuf.Len())
			n, _ := c.readBuf.Read(data)
			return data[:n], nil
		}
		if c.writeBuf.Len() == 0 {
			c.cond.Wait()
		}
	}
}

// Close marks the connection as closed and wakes any blocked reader.
func (c *httpConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.closeErr = net.ErrClosed
	c.cond.Broadcast()
	c.client.CloseIdleConnections()
	return nil
}

// LocalAddr returns a synthetic address for compatibility.
func (c *httpConn) LocalAddr() net.Addr { return httpAddr("local") }

// RemoteAddr returns a synthetic address for compatibility.
func (c *httpConn) RemoteAddr() net.Addr { return httpAddr(c.url) }

// SetDeadline sets both read and write deadlines.
func (c *httpConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

// SetReadDeadline sets the deadline for Read operations.
func (c *httpConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return nil
}

// SetWriteDeadline sets the deadline for Write operations. HTTP writes
// are buffered in memory and never block, so this is a no-op.
func (c *httpConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return nil
}

// httpAddr is a synthetic net.Addr for HTTP connections.
type httpAddr string

func (a httpAddr) Network() string { return "http" }
func (a httpAddr) String() string  { return string(a) }
