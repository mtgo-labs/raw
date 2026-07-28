package raw

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/mtgo-labs/raw/session"
)

func TestNewClientImportsMtcuteSessionString(t *testing.T) {
	authKey := bytes.Repeat([]byte{0x42}, 256)
	encoded := testSessionString(t, session.SessionString{
		Version: session.MtcuteSessionStringVersion,
		Main:    session.SessionStringDC{ID: 4, Address: "149.154.167.91:443"},
		Media:   session.SessionStringDC{ID: 4, Address: "149.154.167.92:443", MediaOnly: true},
		User:    &session.SessionStringUser{ID: 12345, Bot: true},
		AuthKey: authKey,
	})
	client, err := NewClient(Config{APIID: 1, SessionString: encoded})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	digest := sha1.Sum(authKey)
	wantID := binary.LittleEndian.Uint64(digest[12:20])
	if client.config.DCID != 4 || client.config.Address != "149.154.167.91:443" ||
		client.config.AuthKeyID != wantID || !bytes.Equal(client.config.AuthKey, authKey) {
		t.Fatalf("config=%+v", client.config)
	}
	if client.config.SessionString != "" {
		t.Fatal("client retained encoded session string")
	}
	authKey[0] ^= 0xff
	if client.config.AuthKey[0] != 0x42 {
		t.Fatal("client auth key aliases caller input")
	}
}

func TestNewClientAutomaticallyImportsPyrogramTelethonAndRaw(t *testing.T) {
	authKey := bytes.Repeat([]byte{0x35}, 256)
	pyrogram := make([]byte, 271)
	pyrogram[0] = 4
	binary.BigEndian.PutUint32(pyrogram[1:5], 22333936)
	copy(pyrogram[6:262], authKey)
	binary.BigEndian.PutUint64(pyrogram[262:270], 12345)

	telethon := []byte{4, 149, 154, 167, 91}
	telethon = binary.BigEndian.AppendUint16(telethon, 443)
	telethon = append(telethon, authKey...)

	encryptionKey := bytes.Repeat([]byte{0x91}, 32)
	rawString, err := session.EncodeSessionString(session.SessionString{
		APIID: 22333936,
		Main: session.SessionStringDC{
			ID:      4,
			Address: "149.154.167.91:443",
		},
		AuthKey: authKey,
	}, encryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]Config{
		"pyrogram": {
			SessionString: base64.RawURLEncoding.EncodeToString(pyrogram),
		},
		"telethon": {
			APIID:         22333936,
			SessionString: "1" + base64.URLEncoding.EncodeToString(telethon),
		},
		"mtgo-raw": {
			SessionString:    rawString,
			SessionStringKey: encryptionKey,
		},
	}
	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			client, err := NewClient(config)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if client.config.APIID != 22333936 || client.config.DCID != 4 ||
				client.config.Address != "149.154.167.91:443" ||
				!bytes.Equal(client.config.AuthKey, authKey) ||
				client.config.SessionString != "" || len(client.config.SessionStringKey) != 0 {
				t.Fatalf("config=%+v", client.config)
			}
		})
	}
	client, err := NewClient(Config{
		APIID:         1,
		SessionString: base64.RawURLEncoding.EncodeToString(pyrogram),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.config.APIID != 1 {
		t.Fatalf("config APIID should be 1, got %d", client.config.APIID)
	}
	if !bytes.Equal(encryptionKey, bytes.Repeat([]byte{0x91}, 32)) {
		t.Fatal("NewClient modified the caller-owned encryption key")
	}
}

func TestNewClientSessionStringValidatesConflictsAndBackend(t *testing.T) {
	production := testSessionString(t, session.SessionString{
		Version: session.MtcuteSessionStringVersion,
		Main:    session.SessionStringDC{ID: 2, Address: "149.154.167.50:443"},
		AuthKey: bytes.Repeat([]byte{1}, 256),
	})
	testBackend := testSessionString(t, session.SessionString{
		Version: session.MtcuteSessionStringVersion,
		Main:    session.SessionStringDC{ID: 2, Address: "149.154.167.40:443", TestMode: true},
		AuthKey: bytes.Repeat([]byte{2}, 256),
	})
	cases := map[string]Config{
		"malformed":    {APIID: 1, SessionString: "not-base64"},
		"explicit key": {APIID: 1, SessionString: production, AuthKey: bytes.Repeat([]byte{3}, 256), AuthKeyID: 3},
		"dc":           {APIID: 1, DCID: 4, SessionString: production},
		"address":      {APIID: 1, Address: "127.0.0.1:443", SessionString: production},
		"endpoint":     {APIID: 1, SessionString: production, DCAddresses: map[int]string{2: "127.0.0.1:443"}},
		"prod as test": {APIID: 1, SessionString: production, TestMode: true},
		"key without string": {
			APIID:            1,
			Address:          "149.154.167.50:443",
			SessionStringKey: bytes.Repeat([]byte{4}, 32),
		},
		"short string key": {
			APIID:            1,
			SessionString:    production,
			SessionStringKey: bytes.Repeat([]byte{4}, 31),
		},
		"key on mtcute": {
			APIID:            1,
			SessionString:    production,
			SessionStringKey: bytes.Repeat([]byte{4}, 32),
		},
	}
	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewClient(config); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	client, err := NewClient(Config{APIID: 1, SessionString: testBackend})
	if err != nil {
		t.Fatal(err)
	}
	if !client.config.TestMode {
		t.Fatal("test backend flag was lost")
	}
	_ = client.Close()
}

func TestClientExportsEncryptedRawSessionString(t *testing.T) {
	authKey := bytes.Repeat([]byte{0x5a}, 256)
	encryptionKey := bytes.Repeat([]byte{0x7c}, 32)
	encoded := testSessionString(t, session.SessionString{
		Version: session.MtcuteSessionStringVersion,
		Main:    session.SessionStringDC{ID: 2, Address: "149.154.167.50:443"},
		AuthKey: authKey,
	})
	client, err := NewClient(Config{APIID: 1, SessionString: encoded})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	exported, err := client.ExportSessionString(context.Background(), encryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	value, err := session.DecodeSessionString(exported, encryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	if value.Format != session.SessionStringFormatRaw || value.APIID != 1 ||
		value.Main.ID != 2 || value.Main.Address != "149.154.167.50:443" || value.Media != value.Main ||
		value.User != nil || !bytes.Equal(value.AuthKey, authKey) {
		t.Fatalf("value=%+v", value)
	}
}

func TestClientExportsStoredPrimarySessionString(t *testing.T) {
	authKey := bytes.Repeat([]byte{0x6b}, 256)
	encryptionKey := bytes.Repeat([]byte{0x7d}, 32)
	digest := sha1.Sum(authKey)
	store := session.NewMemoryStore()
	data, err := session.Encode(session.Snapshot{
		APIID:     1,
		PrimaryDC: 4,
		AuthKeys: []session.AuthKey{{
			DCID: 4,
			Kind: "main",
			Key:  authKey,
			ID:   binary.LittleEndian.Uint64(digest[12:20]),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), data); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(Config{
		APIID:       1,
		Address:     "149.154.167.50:443",
		DCAddresses: map[int]string{4: "149.154.167.91:443"},
		Store:       store,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	exported, err := client.ExportSessionString(context.Background(), encryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	value, err := session.DecodeSessionString(exported, encryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	if value.Main.ID != 4 || value.Main.Address != "149.154.167.91:443" || !bytes.Equal(value.AuthKey, authKey) {
		t.Fatalf("value=%+v", value)
	}
}

func TestClientExportSessionStringRejectsMissingOrCorruptState(t *testing.T) {
	client, err := NewClient(Config{APIID: 1, Address: "149.154.167.50:443"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ExportSessionString(context.Background(), bytes.Repeat([]byte{1}, 32)); !errors.Is(err, ErrNoAuthKey) {
		t.Fatalf("missing key err=%v", err)
	}
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.ExportSessionString(canceledCtx, bytes.Repeat([]byte{1}, 32)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context err=%v", err)
	}
	_ = client.Close()

	store := session.NewMemoryStore()
	if err := store.Save(context.Background(), []byte("corrupt")); err != nil {
		t.Fatal(err)
	}
	client, err = NewClient(Config{APIID: 1, Address: "149.154.167.50:443", Store: store})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.ExportSessionString(context.Background(), bytes.Repeat([]byte{1}, 32)); !errors.Is(err, session.ErrInvalidSnapshot) {
		t.Fatalf("corrupt state err=%v", err)
	}
}

func testSessionString(t *testing.T, value session.SessionString) string {
	t.Helper()
	encoded, err := session.EncodeMtcuteSessionString(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
