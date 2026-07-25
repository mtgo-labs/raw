package session

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestDecodeSessionStringAutomaticallyDetectsMtcute(t *testing.T) {
	value, err := DecodeSessionString(sessionStringGolden, nil)
	if err != nil {
		t.Fatal(err)
	}
	if value.Format != SessionStringFormatMtcute || value.Main.ID != 2 || len(value.AuthKey) != 256 {
		t.Fatalf("value=%+v", value)
	}
}

func TestDecodeSessionStringAutomaticallyDetectsPyrogram(t *testing.T) {
	authKey := bytes.Repeat([]byte{0x31}, 256)
	current := make([]byte, 271)
	current[0] = 4
	binary.BigEndian.PutUint32(current[1:5], 22333936)
	current[5] = 0
	copy(current[6:262], authKey)
	binary.BigEndian.PutUint64(current[262:270], 12345)
	current[270] = 1
	encoded := base64.RawURLEncoding.EncodeToString(current)
	value, err := DecodeSessionString(encoded, nil)
	if err != nil {
		t.Fatal(err)
	}
	if value.Format != SessionStringFormatPyrogram || value.APIID != 22333936 || value.Main.ID != 4 ||
		value.Main.Address != "149.154.167.91:443" || value.AddressKnown || !value.TestModeKnown ||
		value.User == nil || value.User.ID != 12345 || !value.User.Bot || !bytes.Equal(value.AuthKey, authKey) {
		t.Fatalf("value=%+v", value)
	}

	for _, size := range []int{263, 267} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			legacy := make([]byte, size)
			legacy[0] = 2
			copy(legacy[2:258], authKey)
			if size == 263 {
				binary.BigEndian.PutUint32(legacy[258:262], 12345)
			} else {
				binary.BigEndian.PutUint64(legacy[258:266], 12345)
			}
			decoded, err := DecodeSessionString(base64.RawURLEncoding.EncodeToString(legacy), nil)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Format != SessionStringFormatPyrogram || decoded.APIID != 0 || decoded.User == nil || decoded.User.ID != 12345 {
				t.Fatalf("decoded=%+v", decoded)
			}
		})
	}
}

func TestDecodeSessionStringAutomaticallyDetectsTelethon(t *testing.T) {
	authKey := bytes.Repeat([]byte{0x41}, 256)
	for name, ip := range map[string]net.IP{
		"ipv4": net.ParseIP("149.154.167.91").To4(),
		"ipv6": net.ParseIP("2001:67c:4e8:f004::a").To16(),
	} {
		t.Run(name, func(t *testing.T) {
			payload := []byte{4}
			payload = append(payload, ip...)
			payload = binary.BigEndian.AppendUint16(payload, 443)
			payload = append(payload, authKey...)
			encoded := "1" + base64.URLEncoding.EncodeToString(payload)
			value, err := DecodeSessionString(encoded, nil)
			if err != nil {
				t.Fatal(err)
			}
			if value.Format != SessionStringFormatTelethon || value.Main.ID != 4 || !value.AddressKnown || value.TestModeKnown ||
				value.Main.IPv6 != (name == "ipv6") || !bytes.Equal(value.AuthKey, authKey) {
				t.Fatalf("value=%+v", value)
			}
		})
	}
}

func TestRawSessionStringGolden(t *testing.T) {
	authKey := make([]byte, 256)
	for index := range authKey {
		authKey[index] = byte(index)
	}
	got, err := encodeRawSessionString(SessionString{
		APIID: 22333936,
		Main: SessionStringDC{
			ID:      2,
			Address: "149.154.167.50:443",
		},
		AuthKey: authKey,
	}, bytes.Repeat([]byte{0xa5}, 32), bytes.NewReader([]byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	}))
	if err != nil {
		t.Fatal(err)
	}
	const want = "raw1:AAECAwQFBgcICQoLh8XvhNwtqyz2k81pKngZwWJY00PLxvd_uDKQAlJmdTm__tzStlhPyDhCVaHmCL9YCpkQdjw9kWOw16sxUbIt6BXZ7lXAsjTtETRTIGMkhdFkoWnym5IltIhO2dA2NFSlzptYUlySX5wvHuHq-JSlQMzt7iwsQ9-UAp5OhMgKJioVYpbwCmLOdIV2f_-ex7LP6U6H1410i8yTnT8iS1ZktMEo4FUQtRB4hN9A6z6i0kFrWGihzq67edRa5NwrH962FMAAIPlA98IvZZ9D7U_KsDCU4o3ukcCeGQcDP7wbIJkpGoNms-QNpxwY_fDqws6inYGmfjgBf1LEfLyUxRl2RsZqXemiR12_eObRQAIS8eXuW6__mGqQ-IW3jP-RZdr7uR09aPI2NYA"
	if got != want {
		t.Fatalf("encoded=%q", got)
	}
}

func TestRawSessionStringEncryptsAndAuthenticates(t *testing.T) {
	encryptionKey := bytes.Repeat([]byte{0xa5}, 32)
	authKey := make([]byte, 256)
	for index := range authKey {
		authKey[index] = byte(index)
	}
	input := SessionString{
		APIID: 22333936,
		Main: SessionStringDC{
			ID:       2,
			Address:  "149.154.167.50:443",
			TestMode: false,
		},
		User:    &SessionStringUser{ID: 12345, Bot: true},
		AuthKey: authKey,
	}
	first, err := EncodeSessionString(input, encryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EncodeSessionString(input, encryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !strings.HasPrefix(first, rawSessionStringPrefix) {
		t.Fatalf("non-random encrypted outputs: %q %q", first, second)
	}
	for _, encoded := range []string{first, second} {
		decoded, err := DecodeSessionString(encoded, encryptionKey)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Format != SessionStringFormatRaw || decoded.APIID != input.APIID || decoded.Main != input.Main ||
			decoded.User == nil || *decoded.User != *input.User || !bytes.Equal(decoded.AuthKey, authKey) {
			t.Fatalf("decoded=%+v", decoded)
		}
	}
	envelope, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(first, rawSessionStringPrefix))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(envelope, authKey) {
		t.Fatal("encrypted envelope contains plaintext authorization key")
	}
	tampered := append([]byte(nil), envelope...)
	tampered[len(tampered)-1] ^= 1
	for name, test := range map[string]struct {
		encoded string
		key     []byte
	}{
		"wrong key": {first, bytes.Repeat([]byte{0xa6}, 32)},
		"no key":    {first, nil},
		"tampered":  {rawSessionStringPrefix + base64.RawURLEncoding.EncodeToString(tampered), encryptionKey},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeSessionString(test.encoded, test.key); !errors.Is(err, ErrInvalidSessionString) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	input.Media = SessionStringDC{ID: 2, Address: "149.154.167.51:443"}
	if _, err := EncodeSessionString(input, encryptionKey); !errors.Is(err, ErrInvalidSessionString) {
		t.Fatalf("distinct media DC err=%v", err)
	}
	input.Media = SessionStringDC{}
	if _, err := EncodeSessionString(input, encryptionKey[:31]); !errors.Is(err, ErrInvalidSessionString) {
		t.Fatalf("short key err=%v", err)
	}
}

func TestDecodeSessionStringRejectsMalformedForeignFormats(t *testing.T) {
	pyrogram := make([]byte, 271)
	pyrogram[0] = 2
	pyrogram[5] = 2
	copy(pyrogram[6:262], bytes.Repeat([]byte{1}, 256))
	telethon := "1" + base64.URLEncoding.EncodeToString(make([]byte, 263))
	for name, encoded := range map[string]string{
		"unknown":          "not-a-session",
		"pyrogram boolean": base64.RawURLEncoding.EncodeToString(pyrogram),
		"telethon fields":  telethon,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeSessionString(encoded, nil); !errors.Is(err, ErrInvalidSessionString) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
