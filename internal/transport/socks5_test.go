package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestDialSOCKS5Vectors(t *testing.T) {
	tests := []struct {
		name       string
		proxy      SOCKS5Proxy
		greeting   []byte
		selection  []byte
		credential []byte
	}{
		{
			name:      "no authentication",
			greeting:  []byte{5, 1, 0},
			selection: []byte{5, 0},
		},
		{
			name: "username and password",
			proxy: SOCKS5Proxy{
				Username: "user",
				Password: "pass",
			},
			greeting:   []byte{5, 2, 0, 2},
			selection:  []byte{5, 2},
			credential: []byte{1, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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
				if err := expectSOCKS5Bytes(connection, test.greeting); err != nil {
					serverDone <- err
					return
				}
				if err := writeFull(connection, test.selection); err != nil {
					serverDone <- err
					return
				}
				if len(test.credential) != 0 {
					if err := expectSOCKS5Bytes(connection, test.credential); err != nil {
						serverDone <- err
						return
					}
					if err := writeFull(connection, []byte{1, 0}); err != nil {
						serverDone <- err
						return
					}
				}
				request := []byte{
					5, 1, 0, 3, 13,
					't', 'e', 'l', 'e', 'g', 'r', 'a', 'm', '.', 't', 'e', 's', 't',
					1, 187,
				}
				if err := expectSOCKS5Bytes(connection, request); err != nil {
					serverDone <- err
					return
				}
				serverDone <- writeFull(connection, []byte{5, 0, 0, 1, 127, 0, 0, 1, 31, 144})
			}()
			test.proxy.Address = listener.Addr().String()
			connection, err := DialSOCKS5(context.Background(), test.proxy, "telegram.test:443")
			if err != nil {
				t.Fatal(err)
			}
			_ = connection.Close()
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDialSOCKS5RejectsUnofferedAuthentication(t *testing.T) {
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
		var greeting [3]byte
		_, _ = io.ReadFull(connection, greeting[:])
		_ = writeFull(connection, []byte{5, 2})
	}()
	_, err = DialSOCKS5(context.Background(), SOCKS5Proxy{Address: listener.Addr().String()}, "telegram.test:443")
	if !errors.Is(err, ErrSOCKS5Handshake) {
		t.Fatalf("err=%v", err)
	}
}

func TestDialSOCKS5CancellationClosesHandshake(t *testing.T) {
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
		var greeting [3]byte
		_, _ = io.ReadFull(connection, greeting[:])
		close(serverReady)
		var input [1]byte
		_, _ = connection.Read(input[:])
	}()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := DialSOCKS5(ctx, SOCKS5Proxy{Address: listener.Addr().String()}, "telegram.test:443")
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
		t.Fatal("SOCKS5 handshake remained blocked after cancellation")
	}
}

func expectSOCKS5Bytes(reader io.Reader, want []byte) error {
	got := make([]byte, len(want))
	if _, err := io.ReadFull(reader, got); err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("got %x, want %x", got, want)
	}
	return nil
}
