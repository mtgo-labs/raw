package transport

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDialHTTPConnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		line, err := reader.ReadString('\n')
		if err == nil && !strings.Contains(line, "CONNECT telegram.test:443") {
			err = fmt.Errorf("request=%q", line)
		}
		for err == nil {
			var header string
			header, err = reader.ReadString('\n')
			if header == "\r\n" {
				break
			}
		}
		if err == nil {
			_, err = io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\n\r\nready")
		}
		serverDone <- err
	}()
	connection, err := DialHTTPConnect(context.Background(), HTTPProxy{Address: listener.Addr().String()}, "telegram.test:443")
	if err != nil {
		t.Fatal(err)
	}
	var tunneled [5]byte
	if _, err := io.ReadFull(connection, tunneled[:]); err != nil {
		t.Fatal(err)
	}
	if string(tunneled[:]) != "ready" {
		t.Fatalf("tunneled bytes=%q", tunneled)
	}
	_ = connection.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestDialHTTPConnectCancellationClosesHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverReady := make(chan struct{})
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		close(serverReady)
		var input [1]byte
		_, _ = connection.Read(input[:])
	}()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := DialHTTPConnect(ctx, HTTPProxy{Address: listener.Addr().String()}, "telegram.test:443")
		result <- err
	}()
	<-serverReady
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP CONNECT handshake remained blocked after cancellation")
	}
}

func TestDialHTTPConnectRejectsOversizedResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_ = writeFull(connection, bytes.Repeat([]byte{'x'}, maxHTTPProxyHeader+1))
	}()
	_, err = DialHTTPConnect(context.Background(), HTTPProxy{Address: listener.Addr().String()}, "telegram.test:443")
	if !errors.Is(err, ErrProxyHandshake) {
		t.Fatalf("err=%v", err)
	}
}
