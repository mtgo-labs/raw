package transport

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestObfuscatedConnWritesHandshake(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	nonce := bytes.Repeat([]byte{1}, 64)
	created := make(chan net.Conn, 1)
	go func() {
		connection, err := NewObfuscatedConnWithNonce(left, 0xef, nonce)
		if err != nil {
			created <- nil
			return
		}
		created <- connection
	}()
	wire := make([]byte, 64)
	if _, err := io.ReadFull(right, wire); err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString(
		"0101010101010101010101010101010101010101010101010101010101010101" +
			"0101010101010101010101010101010101010101010101017b87360dacf54caa",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, want) {
		t.Fatalf("got %x, want %x", wire, want)
	}
	if connection := <-created; connection == nil {
		t.Fatal("failed to create obfuscated connection")
	}
}

func TestObfuscatedNonceRejectsForbiddenHeader(t *testing.T) {
	nonce := bytes.Repeat([]byte{1}, 64)
	nonce[0] = 0xef
	if _, err := NewObfuscatedConnWithNonce(nil, 0xef, nonce); err == nil {
		t.Fatal("forbidden nonce accepted")
	}
}

func TestObfuscatedConnConcurrentWrite(t *testing.T) {
	connection, err := newObfuscatedConn(discardNetConn{}, 0xdd, bytes.Repeat([]byte{1}, 64), false)
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	wait.Add(2)
	for range 2 {
		go func() {
			defer wait.Done()
			for range 100 {
				if _, err := connection.Write(make([]byte, 1024)); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wait.Wait()
}

type discardNetConn struct{}

func (discardNetConn) Read([]byte) (int, error)          { return 0, io.EOF }
func (discardNetConn) Write(payload []byte) (int, error) { return len(payload), nil }
func (discardNetConn) Close() error                      { return nil }
func (discardNetConn) LocalAddr() net.Addr               { return nil }
func (discardNetConn) RemoteAddr() net.Addr              { return nil }
func (discardNetConn) SetDeadline(time.Time) error       { return nil }
func (discardNetConn) SetReadDeadline(time.Time) error   { return nil }
func (discardNetConn) SetWriteDeadline(time.Time) error  { return nil }

func BenchmarkObfuscatedWrite16K(b *testing.B) {
	connection, err := newObfuscatedConn(discardNetConn{}, 0xdd, bytes.Repeat([]byte{1}, 64), false)
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 16<<10)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := connection.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}
