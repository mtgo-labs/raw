package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
)

const (
	rawSessionStringPrefix  = "raw1:"
	rawSessionStringVersion = 1
	rawSessionStringAAD     = "mtgo-raw/auth-string/v1"
)

// DecodeSessionString automatically decodes mtgo-raw, mtcute v3, Pyrogram, or
// Telethon authorization strings. encryptionKey is required only for raw1
// strings and must contain exactly 32 bytes.
func DecodeSessionString(encoded string, encryptionKey []byte) (SessionString, error) {
	if strings.HasPrefix(encoded, rawSessionStringPrefix) {
		return decodeRawSessionString(encoded, encryptionKey)
	}
	payload, _ := decodeAuthBase64(encoded)
	defer clear(payload)
	switch len(payload) {
	case 263, 267, 271:
		return decodePyrogramSessionString(payload)
	}
	if len(payload) >= 5 && payload[0] == MtcuteSessionStringVersion {
		return DecodeMtcuteSessionString(encoded)
	}
	if strings.HasPrefix(encoded, "1") {
		return decodeTelethonSessionString(encoded)
	}
	return SessionString{}, ErrInvalidSessionString
}

// EncodeSessionString encrypts authorization state into the mtgo-raw raw1
// envelope with AES-256-GCM and a fresh random nonce. encryptionKey must be a
// caller-owned 32-byte random key and is not embedded in the result.
func EncodeSessionString(value SessionString, encryptionKey []byte) (string, error) {
	return encodeRawSessionString(value, encryptionKey, rand.Reader)
}

func encodeRawSessionString(value SessionString, encryptionKey []byte, random io.Reader) (string, error) {
	if len(encryptionKey) != 32 || random == nil || len(value.AuthKey) != 256 ||
		value.APIID <= 0 || value.Main.ID <= 0 || value.Main.ID > 255 ||
		value.Main.MediaOnly || value.Media.ID != 0 && value.Media != value.Main {
		return "", ErrInvalidSessionString
	}
	host, portText, err := net.SplitHostPort(value.Main.Address)
	if err != nil || host == "" || len(host) > 255 {
		return "", ErrInvalidSessionString
	}
	ip := net.ParseIP(host)
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 || ip == nil || value.Main.IPv6 == (ip.To4() != nil) {
		return "", ErrInvalidSessionString
	}
	flags := byte(0)
	if value.Main.TestMode {
		flags |= 1
	}
	if value.Main.IPv6 {
		flags |= 2
	}
	if value.User != nil {
		if value.User.ID <= 0 || value.User.ID > maxInt53 {
			return "", ErrInvalidSessionString
		}
		flags |= 4
		if value.User.Bot {
			flags |= 8
		}
	}
	plaintext := make([]byte, 0, 10+len(host)+8+len(value.AuthKey))
	defer func() {
		clear(plaintext)
	}()
	plaintext = append(plaintext, rawSessionStringVersion, flags, byte(value.Main.ID))
	plaintext = binary.BigEndian.AppendUint32(plaintext, uint32(value.APIID))
	plaintext = binary.BigEndian.AppendUint16(plaintext, uint16(port))
	plaintext = append(plaintext, byte(len(host)))
	plaintext = append(plaintext, host...)
	if value.User != nil {
		plaintext = binary.BigEndian.AppendUint64(plaintext, uint64(value.User.ID))
	}
	plaintext = append(plaintext, value.AuthKey...)

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", ErrInvalidSessionString
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", ErrInvalidSessionString
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(random, nonce); err != nil {
		return "", err
	}
	envelope := gcm.Seal(nonce, nonce, plaintext, []byte(rawSessionStringAAD))
	clear(plaintext)
	return rawSessionStringPrefix + base64.RawURLEncoding.EncodeToString(envelope), nil
}
func decodeRawSessionString(encoded string, encryptionKey []byte) (SessionString, error) {
	if len(encryptionKey) != 32 {
		return SessionString{}, ErrInvalidSessionString
	}
	envelope, err := decodeAuthBase64(strings.TrimPrefix(encoded, rawSessionStringPrefix))
	if err != nil {
		return SessionString{}, ErrInvalidSessionString
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return SessionString{}, ErrInvalidSessionString
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(envelope) < gcm.NonceSize()+gcm.Overhead() {
		return SessionString{}, ErrInvalidSessionString
	}
	nonce := envelope[:gcm.NonceSize()]
	plaintext, err := gcm.Open(nil, nonce, envelope[gcm.NonceSize():], []byte(rawSessionStringAAD))
	if err != nil {
		return SessionString{}, ErrInvalidSessionString
	}
	defer clear(plaintext)
	if len(plaintext) < 10+256 || plaintext[0] != rawSessionStringVersion || plaintext[1]&^byte(15) != 0 {
		return SessionString{}, ErrInvalidSessionString
	}
	flags := plaintext[1]
	dcid := int(plaintext[2])
	apiID := int32(binary.BigEndian.Uint32(plaintext[3:7]))
	port := binary.BigEndian.Uint16(plaintext[7:9])
	hostLength := int(plaintext[9])
	offset := 10
	userLength := 0
	if flags&4 != 0 {
		userLength = 8
	} else if flags&8 != 0 {
		return SessionString{}, ErrInvalidSessionString
	}
	if dcid == 0 || apiID <= 0 || port == 0 || hostLength == 0 ||
		len(plaintext) != offset+hostLength+userLength+256 {
		return SessionString{}, ErrInvalidSessionString
	}
	host := string(plaintext[offset : offset+hostLength])
	offset += hostLength
	ip := net.ParseIP(host)
	ipv6 := flags&2 != 0
	if ip == nil || ipv6 == (ip.To4() != nil) {
		return SessionString{}, ErrInvalidSessionString
	}
	var user *SessionStringUser
	if flags&4 != 0 {
		userID := int64(binary.BigEndian.Uint64(plaintext[offset : offset+8]))
		offset += 8
		if userID <= 0 || userID > maxInt53 {
			return SessionString{}, ErrInvalidSessionString
		}
		user = &SessionStringUser{ID: userID, Bot: flags&8 != 0}
	}
	main := SessionStringDC{
		ID:       dcid,
		Address:  net.JoinHostPort(host, strconv.Itoa(int(port))),
		IPv6:     ipv6,
		TestMode: flags&1 != 0,
	}
	return SessionString{
		Format:        SessionStringFormatRaw,
		Version:       rawSessionStringVersion,
		APIID:         apiID,
		Main:          main,
		Media:         main,
		User:          user,
		AuthKey:       append([]byte(nil), plaintext[offset:]...),
		AddressKnown:  true,
		TestModeKnown: true,
	}, nil
}

func decodeAuthBase64(encoded string) ([]byte, error) {
	if encoded == "" || len(encoded) > base64.RawURLEncoding.EncodedLen(maxSessionStringBytes) {
		return nil, ErrInvalidSessionString
	}
	if strings.Contains(encoded, "=") {
		data, err := base64.URLEncoding.Strict().DecodeString(encoded)
		if err != nil || len(data) > maxSessionStringBytes {
			return nil, ErrInvalidSessionString
		}
		return data, nil
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(data) > maxSessionStringBytes {
		return nil, ErrInvalidSessionString
	}
	return data, nil
}

func sessionStringDefaultAddress(dcid int, testMode bool) (string, bool) {
	production := [...]string{"", "149.154.175.50", "149.154.167.51", "149.154.175.100", "149.154.167.91", "91.108.56.165"}
	test := [...]string{"", "149.154.175.10", "149.154.167.40", "149.154.175.117"}
	var host string
	if testMode {
		if dcid > 0 && dcid < len(test) {
			host = test[dcid]
		}
	} else if dcid > 0 && dcid < len(production) {
		host = production[dcid]
	}
	if host == "" {
		return "", false
	}
	return net.JoinHostPort(host, "443"), true
}
