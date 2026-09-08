package session

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Native mtgo authorization strings ("MTGO1.<base64url payload>"). The wire
// layout is byte-compatible with the session-converter package.
//
// Version 1 payload:
//
//	version  u8     = 1
//	flags    u8     bit0 = test mode, bit1 = is bot; other bits must be 0
//	user_id  varint (> 0)
//	phone    varint byte length + UTF-8 bytes (0..64)
//	auth_key 256 bytes
//	api_id   varint (> 0)
//	api_hash varint byte length + 16 raw bytes (32 hex chars on the API)
//	dc_id    varint (1..5)
//
// Unknown flag bits and unknown versions fail closed.
const (
	mtgoStringPrefix      = "MTGO"
	mtgoStringVersion     = 1
	mtgoStringFlagTest    = 1 << 0
	mtgoStringFlagBot     = 1 << 1
	mtgoStringKnownFlags  = mtgoStringFlagTest | mtgoStringFlagBot
	mtgoStringMaxPhone    = 64
	mtgoStringMaxPayload  = 1024
	mtgoStringHashBytes   = 16
	mtgoStringHashHexSize = 32
)

// DecodeMTGOSessionString decodes a native mtgo MTGO1 authorization string.
// The MTGO prefix and version are validated; unsupported versions fail closed.
func DecodeMTGOSessionString(encoded string) (SessionString, error) {
	version, payload, ok := splitMTGOStringPrefix(encoded)
	if !ok {
		return SessionString{}, fmt.Errorf("%w: missing %s<version>. prefix", ErrInvalidSessionString, mtgoStringPrefix)
	}
	if version != mtgoStringVersion {
		return SessionString{}, fmt.Errorf("%w: unsupported version %s%d", ErrInvalidSessionString, mtgoStringPrefix, version)
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(payload)
	if err != nil || len(data) == 0 || len(data) > mtgoStringMaxPayload {
		return SessionString{}, ErrInvalidSessionString
	}
	defer clear(data)
	decoder := authStringDecoder{data: data}
	versionByte, ok := decoder.byte()
	if !ok || versionByte != mtgoStringVersion {
		return SessionString{}, ErrInvalidSessionString
	}
	flags, ok := decoder.byte()
	if !ok || flags&^mtgoStringKnownFlags != 0 {
		return SessionString{}, ErrInvalidSessionString
	}
	userID, ok := decoder.uvarint()
	if !ok || userID == 0 || userID > maxInt53 {
		return SessionString{}, ErrInvalidSessionString
	}
	phone, ok := decoder.varintBytes()
	if !ok || len(phone) > mtgoStringMaxPhone || !utf8.Valid(phone) {
		return SessionString{}, ErrInvalidSessionString
	}
	authKey, ok := decoder.take(256)
	if !ok {
		return SessionString{}, ErrInvalidSessionString
	}
	apiID, ok := decoder.uvarint()
	if !ok || apiID == 0 || apiID > math.MaxInt32 {
		return SessionString{}, ErrInvalidSessionString
	}
	apiHash, ok := decoder.varintBytes()
	if !ok || len(apiHash) != mtgoStringHashBytes {
		return SessionString{}, ErrInvalidSessionString
	}
	dcid, ok := decoder.uvarint()
	if !ok || dcid == 0 || dcid > 5 || decoder.offset != len(data) {
		return SessionString{}, ErrInvalidSessionString
	}
	testMode := flags&mtgoStringFlagTest != 0
	address, ok := sessionStringDefaultAddress(int(dcid), testMode)
	if !ok {
		return SessionString{}, ErrInvalidSessionString
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return SessionString{}, ErrInvalidSessionString
	}
	main := SessionStringDC{
		ID:       int(dcid),
		Address:  address,
		IPv6:     net.ParseIP(host).To4() == nil,
		TestMode: testMode,
	}
	return SessionString{
		Format:        SessionStringFormatMTGO,
		Version:       mtgoStringVersion,
		APIID:         int32(apiID),
		Main:          main,
		Media:         main,
		User:          &SessionStringUser{ID: int64(userID), Bot: flags&mtgoStringFlagBot != 0},
		AuthKey:       append([]byte(nil), authKey...),
		APIHash:       hex.EncodeToString(apiHash),
		PhoneNumber:   string(phone),
		AddressKnown:  false,
		TestModeKnown: true,
	}, nil
}

// EncodeMTGOSessionString encodes authorization state into a native mtgo MTGO1
// authorization string. APIHash must be the 32-hex-char API hash from
// my.telegram.org, and User is required (the format carries the user ID).
func EncodeMTGOSessionString(value SessionString) (string, error) {
	if len(value.AuthKey) != 256 || value.APIID <= 0 || value.Main.ID <= 0 || value.Main.ID > 5 ||
		value.Main.MediaOnly || value.User == nil || value.User.ID <= 0 || value.User.ID > maxInt53 {
		return "", ErrInvalidSessionString
	}
	if len(value.APIHash) != mtgoStringHashHexSize {
		return "", ErrInvalidSessionString
	}
	apiHash, err := hex.DecodeString(value.APIHash)
	if err != nil || len(apiHash) != mtgoStringHashBytes {
		return "", ErrInvalidSessionString
	}
	if len(value.PhoneNumber) > mtgoStringMaxPhone || !utf8.ValidString(value.PhoneNumber) {
		return "", ErrInvalidSessionString
	}
	mediaValue := value.Media
	if mediaValue.ID == 0 {
		mediaValue = value.Main
	}
	if value.Main != mediaValue {
		return "", ErrInvalidSessionString
	}
	flags := byte(0)
	if value.Main.TestMode {
		flags |= mtgoStringFlagTest
	}
	if value.User.Bot {
		flags |= mtgoStringFlagBot
	}
	data := make([]byte, 0, mtgoStringMaxPayload)
	defer func() {
		clear(data)
	}()
	data = append(data, mtgoStringVersion, flags)
	data = binary.AppendUvarint(data, uint64(value.User.ID))
	data = binary.AppendUvarint(data, uint64(len(value.PhoneNumber)))
	data = append(data, value.PhoneNumber...)
	data = append(data, value.AuthKey...)
	data = binary.AppendUvarint(data, uint64(value.APIID))
	data = binary.AppendUvarint(data, uint64(len(apiHash)))
	data = append(data, apiHash...)
	data = binary.AppendUvarint(data, uint64(value.Main.ID))
	if len(data) > mtgoStringMaxPayload {
		return "", ErrInvalidSessionString
	}
	return mtgoStringPrefix + strconv.Itoa(mtgoStringVersion) + "." + base64.RawURLEncoding.EncodeToString(data), nil
}

// splitMTGOStringPrefix parses the "MTGO<digits>." header. It requires a
// canonical (no leading zeros) decimal version number.
func splitMTGOStringPrefix(s string) (version int, payload string, ok bool) {
	if !strings.HasPrefix(s, mtgoStringPrefix) {
		return 0, "", false
	}
	rest := s[len(mtgoStringPrefix):]
	dot := strings.IndexByte(rest, '.')
	if dot <= 0 {
		return 0, "", false
	}
	digits := rest[:dot]
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, "", false
		}
	}
	version, err := strconv.Atoi(digits)
	if err != nil || strconv.Itoa(version) != digits {
		return 0, "", false
	}
	return version, rest[dot+1:], true
}

func (decoder *authStringDecoder) uvarint() (uint64, bool) {
	value, n := binary.Uvarint(decoder.data[decoder.offset:])
	if n <= 0 {
		return 0, false
	}
	decoder.offset += n
	return value, true
}

func (decoder *authStringDecoder) take(n int) ([]byte, bool) {
	if n < 0 || len(decoder.data)-decoder.offset < n {
		return nil, false
	}
	value := decoder.data[decoder.offset : decoder.offset+n]
	decoder.offset += n
	return value, true
}

func (decoder *authStringDecoder) varintBytes() ([]byte, bool) {
	length, ok := decoder.uvarint()
	if !ok || length > mtgoStringMaxPayload {
		return nil, false
	}
	return decoder.take(int(length))
}
