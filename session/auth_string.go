package session

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"unicode/utf8"
)

const (
	// MtcuteSessionStringVersion is the mtcute string-session version supported by raw.
	MtcuteSessionStringVersion = 3
	maxSessionStringBytes      = 1024
	maxInt53                   = 1<<53 - 1
)

var (
	// ErrInvalidSessionString reports malformed, unauthenticated, or unsupported
	// authorization-string data.
	ErrInvalidSessionString = errors.New("session: invalid session string")
)

// SessionStringFormat identifies an automatically detected authorization string.
type SessionStringFormat string

const (
	SessionStringFormatRaw      SessionStringFormat = "mtgo-raw"
	SessionStringFormatMtcute   SessionStringFormat = "mtcute"
	SessionStringFormatPyrogram SessionStringFormat = "pyrogram"
	SessionStringFormatTelethon SessionStringFormat = "telethon"
)

// SessionStringDC is one mtcute string-session data-center endpoint.
type SessionStringDC struct {
	ID        int
	Address   string
	IPv6      bool
	MediaOnly bool
	TestMode  bool
}

// SessionStringUser is optional identity metadata carried by an mtcute session string.
// Raw does not use this metadata for authorization.
type SessionStringUser struct {
	ID  int64
	Bot bool
}

// SessionString is the common authorization state decoded from a supported
// session-string format. AuthKey is copied at API ownership boundaries.
type SessionString struct {
	Format        SessionStringFormat
	Version       int
	APIID         int32
	Main          SessionStringDC
	Media         SessionStringDC
	User          *SessionStringUser
	AuthKey       []byte
	AddressKnown  bool
	TestModeKnown bool
}

// DecodeMtcuteSessionString decodes and validates an mtcute v3 string session.
func DecodeMtcuteSessionString(encoded string) (SessionString, error) {
	if encoded == "" || len(encoded) > base64.RawURLEncoding.EncodedLen(maxSessionStringBytes) {
		return SessionString{}, ErrInvalidSessionString
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(data) == 0 || len(data) > maxSessionStringBytes {
		return SessionString{}, ErrInvalidSessionString
	}
	defer clear(data)
	decoder := authStringDecoder{data: data}
	version, ok := decoder.byte()
	if !ok || version != MtcuteSessionStringVersion {
		return SessionString{}, fmt.Errorf("%w: unsupported version %d", ErrInvalidSessionString, version)
	}
	flags, ok := decoder.uint32()
	if !ok || flags&^uint32(7) != 0 {
		return SessionString{}, ErrInvalidSessionString
	}
	mainData, ok := decoder.tlBytes()
	if !ok {
		return SessionString{}, ErrInvalidSessionString
	}
	main, err := parseSessionStringDC(mainData)
	if err != nil {
		return SessionString{}, err
	}
	media := main
	if flags&4 != 0 {
		mediaData, ok := decoder.tlBytes()
		if !ok {
			return SessionString{}, ErrInvalidSessionString
		}
		media, err = parseSessionStringDC(mediaData)
		if err != nil {
			return SessionString{}, err
		}
	}
	if flags&2 != 0 {
		main.TestMode = true
		media.TestMode = true
	} else if main.TestMode != media.TestMode {
		return SessionString{}, fmt.Errorf("%w: mixed production and test endpoints", ErrInvalidSessionString)
	}
	var user *SessionStringUser
	if flags&1 != 0 {
		id, ok := decoder.int64()
		if !ok || id <= 0 || id > maxInt53 {
			return SessionString{}, ErrInvalidSessionString
		}
		constructor, ok := decoder.uint32()
		if !ok {
			return SessionString{}, ErrInvalidSessionString
		}
		var bot bool
		switch constructor {
		case 0x997275b5:
			bot = true
		case 0xbc799737:
		default:
			return SessionString{}, ErrInvalidSessionString
		}
		user = &SessionStringUser{ID: id, Bot: bot}
	}
	authKey, ok := decoder.tlBytes()
	if !ok || len(authKey) != 256 || decoder.offset != len(data) {
		return SessionString{}, ErrInvalidSessionString
	}
	return SessionString{
		Format:        SessionStringFormatMtcute,
		Version:       MtcuteSessionStringVersion,
		Main:          main,
		Media:         media,
		User:          user,
		AuthKey:       append([]byte(nil), authKey...),
		AddressKnown:  true,
		TestModeKnown: true,
	}, nil
}

// EncodeMtcuteSessionString encodes an mtcute-compatible v3 string session.
func EncodeMtcuteSessionString(value SessionString) (string, error) {
	if value.Version != MtcuteSessionStringVersion || len(value.AuthKey) != 256 {
		return "", ErrInvalidSessionString
	}
	main, err := encodeSessionStringDC(value.Main)
	if err != nil {
		return "", err
	}
	mediaValue := value.Media
	if mediaValue.ID == 0 {
		mediaValue = value.Main
	}
	if value.Main.TestMode != mediaValue.TestMode {
		return "", fmt.Errorf("%w: mixed production and test endpoints", ErrInvalidSessionString)
	}
	media, err := encodeSessionStringDC(mediaValue)
	if err != nil {
		return "", err
	}
	flags := uint32(0)
	if value.User != nil {
		if value.User.ID <= 0 || value.User.ID > maxInt53 {
			return "", ErrInvalidSessionString
		}
		flags |= 1
	}
	if value.Main != mediaValue {
		flags |= 4
	}
	data := make([]byte, 0, 512)
	defer func() {
		clear(data)
	}()
	data = append(data, MtcuteSessionStringVersion)
	data = binary.LittleEndian.AppendUint32(data, flags)
	data, err = appendTLBytes(data, main)
	if err != nil {
		return "", err
	}
	if flags&4 != 0 {
		data, err = appendTLBytes(data, media)
		if err != nil {
			return "", err
		}
	}
	if value.User != nil {
		data = binary.LittleEndian.AppendUint64(data, uint64(value.User.ID))
		constructor := uint32(0xbc799737)
		if value.User.Bot {
			constructor = 0x997275b5
		}
		data = binary.LittleEndian.AppendUint32(data, constructor)
	}
	data, err = appendTLBytes(data, value.AuthKey)
	if err != nil || len(data) > maxSessionStringBytes {
		return "", ErrInvalidSessionString
	}
	encoded := base64.RawURLEncoding.EncodeToString(data)
	return encoded, nil
}

func parseSessionStringDC(data []byte) (SessionStringDC, error) {
	if len(data) < 7 {
		return SessionStringDC{}, ErrInvalidSessionString
	}
	version, id, flags := data[0], data[1], data[2]
	if (version != 1 && version != 2) || id == 0 || flags&^byte(7) != 0 || version == 1 && flags&4 != 0 {
		return SessionStringDC{}, ErrInvalidSessionString
	}
	decoder := authStringDecoder{data: data, offset: 3}
	hostData, ok := decoder.tlBytes()
	if !ok || !utf8.Valid(hostData) {
		return SessionStringDC{}, ErrInvalidSessionString
	}
	host := string(hostData)
	ip := net.ParseIP(host)
	port, ok := decoder.uint32()
	if !ok || decoder.offset != len(data) || ip == nil || port == 0 || port > 65535 {
		return SessionStringDC{}, ErrInvalidSessionString
	}
	ipv6 := flags&1 != 0
	if ipv6 == (ip.To4() != nil) {
		return SessionStringDC{}, ErrInvalidSessionString
	}
	return SessionStringDC{
		ID:        int(id),
		Address:   net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)),
		IPv6:      ipv6,
		MediaOnly: flags&2 != 0,
		TestMode:  version == 2 && flags&4 != 0,
	}, nil
}

func encodeSessionStringDC(value SessionStringDC) ([]byte, error) {
	if value.ID <= 0 || value.ID > 255 {
		return nil, ErrInvalidSessionString
	}
	host, portText, err := net.SplitHostPort(value.Address)
	if err != nil || host == "" {
		return nil, ErrInvalidSessionString
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, ErrInvalidSessionString
	}
	ip := net.ParseIP(host)
	if ip == nil || value.IPv6 == (ip.To4() != nil) {
		return nil, ErrInvalidSessionString
	}
	flags := byte(0)
	if value.IPv6 {
		flags |= 1
	}
	if value.MediaOnly {
		flags |= 2
	}
	if value.TestMode {
		flags |= 4
	}
	data := []byte{2, byte(value.ID), flags}
	data, err = appendTLBytes(data, []byte(host))
	if err != nil {
		return nil, err
	}
	data = binary.LittleEndian.AppendUint32(data, uint32(port))
	return data, nil
}

func appendTLBytes(output, value []byte) ([]byte, error) {
	length := len(value)
	headerLength := 1
	switch {
	case length < 254:
		output = append(output, byte(length))
	case length <= 0xffffff:
		headerLength = 4
		output = append(output, 254, byte(length), byte(length>>8), byte(length>>16))
	default:
		return nil, ErrInvalidSessionString
	}
	output = append(output, value...)
	for range -(headerLength + length) & 3 {
		output = append(output, 0)
	}
	return output, nil
}

type authStringDecoder struct {
	data   []byte
	offset int
}

func (decoder *authStringDecoder) byte() (byte, bool) {
	if decoder.offset >= len(decoder.data) {
		return 0, false
	}
	value := decoder.data[decoder.offset]
	decoder.offset++
	return value, true
}

func (decoder *authStringDecoder) uint32() (uint32, bool) {
	if len(decoder.data)-decoder.offset < 4 {
		return 0, false
	}
	value := binary.LittleEndian.Uint32(decoder.data[decoder.offset:])
	decoder.offset += 4
	return value, true
}

func (decoder *authStringDecoder) int64() (int64, bool) {
	if len(decoder.data)-decoder.offset < 8 {
		return 0, false
	}
	value := int64(binary.LittleEndian.Uint64(decoder.data[decoder.offset:]))
	decoder.offset += 8
	return value, true
}

func (decoder *authStringDecoder) tlBytes() ([]byte, bool) {
	first, ok := decoder.byte()
	if !ok || first == 255 {
		return nil, false
	}
	headerLength := 1
	length := int(first)
	if first == 254 {
		if len(decoder.data)-decoder.offset < 3 {
			return nil, false
		}
		length = int(decoder.data[decoder.offset]) |
			int(decoder.data[decoder.offset+1])<<8 |
			int(decoder.data[decoder.offset+2])<<16
		decoder.offset += 3
		headerLength = 4
	}
	padding := -(headerLength + length) & 3
	if length < 0 || length > maxSessionStringBytes || len(decoder.data)-decoder.offset < length+padding {
		return nil, false
	}
	value := decoder.data[decoder.offset : decoder.offset+length]
	decoder.offset += length
	for range padding {
		if decoder.data[decoder.offset] != 0 {
			return nil, false
		}
		decoder.offset++
	}
	return value, true
}
