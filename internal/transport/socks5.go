package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
)

var ErrSOCKS5Handshake = errors.New("transport: SOCKS5 handshake failed")

type SOCKS5Proxy struct {
	Address  string
	Username string
	Password string
}

func DialSOCKS5(ctx context.Context, proxy SOCKS5Proxy, target string) (net.Conn, error) {
	if ctx == nil || proxy.Address == "" || target == "" ||
		len(proxy.Username) > 255 || len(proxy.Password) > 255 ||
		proxy.Username == "" && proxy.Password != "" {
		return nil, ErrSOCKS5Handshake
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxy.Address)
	if err != nil {
		return nil, err
	}
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = connection.Close()
	})
	defer stopCancellation()
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = connection.Close()
		}
	}()
	methods := []byte{5, 1, 0}
	if proxy.Username != "" {
		methods = []byte{5, 2, 0, 2}
	}
	if err := writeFull(connection, methods); err != nil {
		return nil, socks5IOError(ctx, "methods", err)
	}
	var selected [2]byte
	if _, err := io.ReadFull(connection, selected[:]); err != nil {
		return nil, socks5IOError(ctx, "method selection", err)
	}
	if selected[0] != 5 {
		return nil, ErrSOCKS5Handshake
	}
	if selected[1] == 2 {
		if proxy.Username == "" {
			return nil, ErrSOCKS5Handshake
		}
		auth := append([]byte{1, byte(len(proxy.Username))}, []byte(proxy.Username)...)
		auth = append(auth, byte(len(proxy.Password)))
		auth = append(auth, []byte(proxy.Password)...)
		if err := writeFull(connection, auth); err != nil {
			return nil, socks5IOError(ctx, "authentication", err)
		}
		var result [2]byte
		if _, err := io.ReadFull(connection, result[:]); err != nil {
			return nil, socks5IOError(ctx, "authentication result", err)
		}
		if result[0] != 1 || result[1] != 0 {
			return nil, ErrSOCKS5Handshake
		}
	} else if selected[1] != 0 {
		return nil, ErrSOCKS5Handshake
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, ErrSOCKS5Handshake
	}
	portNumber, err := net.LookupPort("tcp", port)
	if err != nil {
		return nil, ErrSOCKS5Handshake
	}
	request := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			request = append(request, 1)
			request = append(request, ipv4...)
		} else {
			request = append(request, 4)
			request = append(request, ip.To16()...)
		}
	} else if len(host) > 0 && len(host) <= 255 {
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	} else {
		return nil, ErrSOCKS5Handshake
	}
	request = append(request, byte(portNumber>>8), byte(portNumber))
	if err := writeFull(connection, request); err != nil {
		return nil, socks5IOError(ctx, "connect request", err)
	}
	var response [4]byte
	if _, err := io.ReadFull(connection, response[:]); err != nil {
		return nil, socks5IOError(ctx, "connect response", err)
	}
	if response[0] != 5 || response[1] != 0 || response[2] != 0 {
		return nil, ErrSOCKS5Handshake
	}
	length := 0
	switch response[3] {
	case 1:
		length = 4
	case 4:
		length = 16
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(connection, size[:]); err != nil {
			return nil, socks5IOError(ctx, "bound address length", err)
		}
		if size[0] == 0 {
			return nil, ErrSOCKS5Handshake
		}
		length = int(size[0])
	default:
		return nil, ErrSOCKS5Handshake
	}
	if _, err := io.CopyN(io.Discard, connection, int64(length+2)); err != nil {
		return nil, socks5IOError(ctx, "bound address", err)
	}
	if !stopCancellation() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, ErrSOCKS5Handshake
	}
	closeOnError = false
	return connection, nil
}

func socks5IOError(ctx context.Context, stage string, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return fmt.Errorf("%w: %s: %w", ErrSOCKS5Handshake, stage, err)
}
