package session

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

const sessionStringGolden = "AwUAAAAXAgIADjE0OS4xNTQuMTY3LjUwALsBAAAXAgICDzE0OS4xNTQuMTY3LjIyMrsBAAA5MAAAAAAAALV1cpn-AAEAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq-wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy8_T19vf4-fr7_P3-_w"

func TestSessionStringMtcuteV3Fixture(t *testing.T) {
	authKey := make([]byte, 256)
	for index := range authKey {
		authKey[index] = byte(index)
	}
	value := SessionString{
		Version: MtcuteSessionStringVersion,
		Main: SessionStringDC{
			ID:      2,
			Address: "149.154.167.50:443",
		},
		Media: SessionStringDC{
			ID:        2,
			Address:   "149.154.167.222:443",
			MediaOnly: true,
		},
		User:    &SessionStringUser{ID: 12345, Bot: true},
		AuthKey: authKey,
	}
	encoded, err := EncodeMtcuteSessionString(value)
	if err != nil {
		t.Fatal(err)
	}
	if encoded != sessionStringGolden {
		t.Fatalf("encoded auth string differs from mtcute fixture\n got: %s\nwant: %s", encoded, sessionStringGolden)
	}
	decoded, err := DecodeMtcuteSessionString(sessionStringGolden)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Version != MtcuteSessionStringVersion || decoded.Main != value.Main || decoded.Media != value.Media ||
		decoded.User == nil || *decoded.User != *value.User || !bytes.Equal(decoded.AuthKey, authKey) {
		t.Fatalf("decoded=%+v", decoded)
	}
	decoded.AuthKey[0] ^= 0xff
	again, err := DecodeMtcuteSessionString(sessionStringGolden)
	if err != nil {
		t.Fatal(err)
	}
	if again.AuthKey[0] != 0 {
		t.Fatal("parsed auth key aliases prior result")
	}
}

func TestParseSessionStringLegacyTestModeFlag(t *testing.T) {
	encoded, err := EncodeMtcuteSessionString(SessionString{
		Version: MtcuteSessionStringVersion,
		Main: SessionStringDC{
			ID:       2,
			Address:  "149.154.167.40:443",
			TestMode: true,
		},
		AuthKey: bytes.Repeat([]byte{0x42}, 256),
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	data[1] = 2 // Legacy session-level test-mode flag.
	data[6] = 1 // Basic DC option v1 did not carry test mode.
	data[8] = 0
	value, err := DecodeMtcuteSessionString(base64.RawURLEncoding.EncodeToString(data))
	if err != nil {
		t.Fatal(err)
	}
	if !value.Main.TestMode || !value.Media.TestMode || value.Main.Address != "149.154.167.40:443" || value.Media != value.Main {
		t.Fatalf("value=%+v", value)
	}
}

func TestParseSessionStringRejectsMalformedInput(t *testing.T) {
	valid, err := base64.RawURLEncoding.DecodeString(sessionStringGolden)
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(change func([]byte) []byte) string {
		data := append([]byte(nil), valid...)
		return base64.RawURLEncoding.EncodeToString(change(data))
	}
	cases := map[string]string{
		"empty":          "",
		"invalid base64": "%%%",
		"version": mutate(func(data []byte) []byte {
			data[0] = 4
			return data
		}),
		"unknown flags": mutate(func(data []byte) []byte {
			data[1] = 8
			return data
		}),
		"mixed backends": mutate(func(data []byte) []byte {
			data[8] = 4
			return data
		}),
		"invalid boolean": mutate(func(data []byte) []byte {
			data[61] = 0
			return data
		}),
		"truncated": mutate(func(data []byte) []byte {
			return data[:len(data)-1]
		}),
		"trailing": mutate(func(data []byte) []byte {
			return append(data, 0)
		}),
		"oversized":          base64.RawURLEncoding.EncodeToString(make([]byte, maxSessionStringBytes+1)),
		"short upstream key": "AwQAAAAXAgIADjE0OS4xNTQuMTY3LjUwALsBAAAXAgICDzE0OS4xNTQuMTY3LjIyMrsBAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeMtcuteSessionString(encoded); !errors.Is(err, ErrInvalidSessionString) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestEncodeSessionStringRejectsInvalidValues(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 256)
	valid := SessionString{
		Version: MtcuteSessionStringVersion,
		Main:    SessionStringDC{ID: 2, Address: "149.154.167.50:443"},
		AuthKey: key,
	}
	cases := map[string]SessionString{
		"version": func() SessionString {
			value := valid
			value.Version = 2
			return value
		}(),
		"key": func() SessionString {
			value := valid
			value.AuthKey = key[:255]
			return value
		}(),
		"dc": func() SessionString {
			value := valid
			value.Main.ID = 0
			return value
		}(),
		"address": func() SessionString {
			value := valid
			value.Main.Address = "not-an-address"
			return value
		}(),
		"ipv6 mismatch": func() SessionString {
			value := valid
			value.Main.IPv6 = true
			return value
		}(),
		"user": func() SessionString {
			value := valid
			value.User = &SessionStringUser{}
			return value
		}(),
		"mixed backends": func() SessionString {
			value := valid
			value.Media = value.Main
			value.Media.TestMode = true
			return value
		}(),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := EncodeMtcuteSessionString(value); !errors.Is(err, ErrInvalidSessionString) {
				t.Fatalf("err=%v", err)
			}
		})
	}

	encoded, err := EncodeMtcuteSessionString(valid)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded, "=") {
		t.Fatalf("auth string uses base64 padding: %q", encoded)
	}
}
