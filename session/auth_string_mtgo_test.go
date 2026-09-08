package session

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func testMTGOValue() SessionString {
	authKey := bytes.Repeat([]byte{0x6d}, 256)
	return SessionString{
		Version:     mtgoStringVersion,
		APIID:       22333936,
		Main:        SessionStringDC{ID: 4},
		User:        &SessionStringUser{ID: 123456789, Bot: true},
		AuthKey:     authKey,
		APIHash:     "89abcdef0123456789abcdef01234567",
		PhoneNumber: "+9996621234",
	}
}

func TestMTGOSessionStringRoundTrip(t *testing.T) {
	value := testMTGOValue()
	encoded, err := EncodeMTGOSessionString(value)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "MTGO1.") {
		t.Fatalf("missing MTGO1 prefix: %q", encoded)
	}
	decoded, err := DecodeMTGOSessionString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Format != SessionStringFormatMTGO || decoded.Version != mtgoStringVersion ||
		decoded.APIID != value.APIID || decoded.Main.ID != 4 ||
		decoded.User == nil || decoded.User.ID != 123456789 || !decoded.User.Bot ||
		decoded.APIHash != value.APIHash || decoded.PhoneNumber != value.PhoneNumber ||
		decoded.AddressKnown || !decoded.TestModeKnown || decoded.Main.TestMode ||
		decoded.Main.Address != "149.154.167.91:443" ||
		!bytes.Equal(decoded.AuthKey, value.AuthKey) {
		t.Fatalf("decoded=%+v", decoded)
	}
	reencoded, err := EncodeMTGOSessionString(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if reencoded != encoded {
		t.Fatalf("non-canonical round trip:\n first: %s\n again: %s", encoded, reencoded)
	}
}

func TestMTGOSessionStringRoundTripUser(t *testing.T) {
	value := testMTGOValue()
	value.Main = SessionStringDC{ID: 2, TestMode: true}
	value.User = &SessionStringUser{ID: 1}
	value.PhoneNumber = ""
	value.APIHash = "0123456789abcdef0123456789abcdef"
	encoded, err := EncodeMTGOSessionString(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeMTGOSessionString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Main.ID != 2 || !decoded.Main.TestMode || decoded.Main.Address != "149.154.167.40:443" ||
		decoded.User == nil || decoded.User.Bot || decoded.User.ID != 1 || decoded.PhoneNumber != "" {
		t.Fatalf("decoded=%+v", decoded)
	}
}

func TestDecodeSessionStringAutomaticallyDetectsMTGO(t *testing.T) {
	value := testMTGOValue()
	encoded, err := EncodeMTGOSessionString(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSessionString(encoded, nil)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Format != SessionStringFormatMTGO || decoded.APIHash != value.APIHash ||
		decoded.PhoneNumber != value.PhoneNumber {
		t.Fatalf("decoded=%+v", decoded)
	}
}

func TestMTGOSessionStringRejectsMalformedInput(t *testing.T) {
	value := testMTGOValue()
	valid, err := EncodeMTGOSessionString(value)
	if err != nil {
		t.Fatal(err)
	}
	payload := valid[strings.IndexByte(valid, '.')+1:]
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := func(mutate func([]byte) []byte) string {
		dup := append([]byte(nil), data...)
		return "MTGO1." + base64.RawURLEncoding.EncodeToString(mutate(dup))
	}

	tests := []struct {
		name string
		str  string
	}{
		{"empty", ""},
		{"missing prefix", payload},
		{"unsupported version", "MTGO2." + payload},
		{"leading zero version", "MTGO01." + payload},
		{"missing dot", "MTGO1" + payload},
		{"invalid base64", "MTGO1.!!!"},
		{"trailing bytes", valid + "AA"},
		{"unknown flags", corrupt(func(d []byte) []byte { d[1] |= 1 << 7; return d })},
		{"zero user id", corrupt(func(d []byte) []byte { d[2] = 0; return d })},
		{"invalid phone utf8", corrupt(func(d []byte) []byte {
			d[6] = 1    // phone length = 1 (was 11)
			d[7] = 0xff // invalid UTF-8 byte
			return d
		})},
		{"bad api hash length", corrupt(func(d []byte) []byte { d[len(d)-18] = 15; return d })},
		{"unknown dc", corrupt(func(d []byte) []byte { d[len(d)-1] = 6; return d })},
		{"truncated", corrupt(func(d []byte) []byte { return d[:len(d)-1] })},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecodeSessionString(tt.str, nil); err == nil {
				t.Fatalf("decoded invalid session %q", tt.str)
			}
		})
	}
}

func TestEncodeMTGOSessionStringRejectsInvalidValues(t *testing.T) {
	value := testMTGOValue()
	tests := []struct {
		name   string
		mutate func(*SessionString)
	}{
		{"short auth key", func(v *SessionString) { v.AuthKey = v.AuthKey[:255] }},
		{"zero api id", func(v *SessionString) { v.APIID = 0 }},
		{"zero dc", func(v *SessionString) { v.Main.ID = 0 }},
		{"large dc", func(v *SessionString) { v.Main.ID = 6 }},
		{"media dc", func(v *SessionString) { v.Main.MediaOnly = true }},
		{"no user", func(v *SessionString) { v.User = nil }},
		{"zero user", func(v *SessionString) { v.User = &SessionStringUser{ID: 0} }},
		{"empty api hash", func(v *SessionString) { v.APIHash = "" }},
		{"non-hex api hash", func(v *SessionString) { v.APIHash = strings.Repeat("g", 32) }},
		{"oversize phone", func(v *SessionString) { v.PhoneNumber = strings.Repeat("x", mtgoStringMaxPhone+1) }},
		{"distinct media", func(v *SessionString) { v.Media = SessionStringDC{ID: 5} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dup := value
			dup.AuthKey = append([]byte(nil), value.AuthKey...)
			if dup.User != nil {
				dup.User = &SessionStringUser{ID: value.User.ID, Bot: value.User.Bot}
			}
			tt.mutate(&dup)
			if _, err := EncodeMTGOSessionString(dup); err == nil {
				t.Fatal("encoded invalid value")
			}
		})
	}
}
