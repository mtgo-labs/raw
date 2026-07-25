package transport

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

const maxHTTPProxyHeader = 16 << 10

var ErrProxyHandshake = errors.New("transport: HTTP proxy handshake failed")

type HTTPProxy struct {
	Address  string
	Username string
	Password string
}

func DialHTTPConnect(ctx context.Context, proxy HTTPProxy, target string) (net.Conn, error) {
	if ctx == nil || proxy.Address == "" || target == "" {
		return nil, ErrProxyHandshake
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return nil, ErrProxyHandshake
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber <= 0 || portNumber > 65535 {
		return nil, ErrProxyHandshake
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
	request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if proxy.Username != "" {
		token := base64.StdEncoding.EncodeToString([]byte(proxy.Username + ":" + proxy.Password))
		request += "Proxy-Authorization: Basic " + token + "\r\n"
	}
	request += "\r\n"
	if err := writeHTTPProxyRequest(connection, request); err != nil {
		return nil, httpProxyIOError(ctx, "write", err)
	}
	if err := readHTTPProxyResponse(ctx, connection); err != nil {
		return nil, err
	}
	if !stopCancellation() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, ErrProxyHandshake
	}
	closeOnError = false
	return connection, nil
}

func writeHTTPProxyRequest(writer io.Writer, request string) error {
	for len(request) != 0 {
		written, err := io.WriteString(writer, request)
		if written > 0 {
			request = request[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func readHTTPProxyResponse(ctx context.Context, reader io.Reader) error {
	var response [maxHTTPProxyHeader]byte
	length := 0
	for length < len(response) {
		if _, err := io.ReadFull(reader, response[length:length+1]); err != nil {
			return httpProxyIOError(ctx, "response", err)
		}
		length++
		if length >= 4 && bytes.Equal(response[length-4:length], []byte("\r\n\r\n")) ||
			length >= 2 && bytes.Equal(response[length-2:length], []byte("\n\n")) {
			lineEnd := bytes.IndexByte(response[:length], '\n')
			if lineEnd < 0 {
				return ErrProxyHandshake
			}
			parts := strings.Fields(string(response[:lineEnd]))
			if len(parts) < 2 || parts[0] != "HTTP/1.1" && parts[0] != "HTTP/1.0" || parts[1] != "200" {
				return ErrProxyHandshake
			}
			return nil
		}
	}
	return ErrProxyHandshake
}

func httpProxyIOError(ctx context.Context, stage string, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return fmt.Errorf("%w: %s: %w", ErrProxyHandshake, stage, err)
}
