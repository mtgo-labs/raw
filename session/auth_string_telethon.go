package session

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
)

func decodeTelethonSessionString(encoded string) (SessionString, error) {
	if !strings.HasPrefix(encoded, "1") {
		return SessionString{}, ErrInvalidSessionString
	}
	payload, err := decodeAuthBase64(encoded[1:])
	if err != nil || len(payload) != 263 && len(payload) != 275 {
		return SessionString{}, ErrInvalidSessionString
	}
	defer clear(payload)
	dcid := int(payload[0])
	if dcid <= 0 || dcid > 5 {
		return SessionString{}, ErrInvalidSessionString
	}
	ipLength := len(payload) - 1 - 2 - 256
	host := net.IP(payload[1 : 1+ipLength]).String()
	if host == "<nil>" {
		return SessionString{}, ErrInvalidSessionString
	}
	portOffset := 1 + ipLength
	port := binary.BigEndian.Uint16(payload[portOffset : portOffset+2])
	if port == 0 {
		return SessionString{}, ErrInvalidSessionString
	}
	authKey := payload[portOffset+2:]
	main := SessionStringDC{
		ID:      dcid,
		Address: net.JoinHostPort(host, strconv.Itoa(int(port))),
		IPv6:    ipLength == net.IPv6len,
	}
	return SessionString{
		Format:        SessionStringFormatTelethon,
		Main:          main,
		Media:         main,
		AuthKey:       append([]byte(nil), authKey...),
		AddressKnown:  true,
		TestModeKnown: false,
	}, nil
}
