package tl

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestEncodeGeneratedMTPPing(t *testing.T) {
	t.Parallel()

	encoded, err := Encode(&MTPPing{PingID: 0x0102030405060708})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want, err := hex.DecodeString("ec77be7a0807060504030201")
	if err != nil {
		t.Fatalf("decode expected bytes: %v", err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded bytes = %x, want %x", encoded, want)
	}
}

func TestEncodeGeneratedMessageContainerWireVector(t *testing.T) {
	t.Parallel()

	value := &MTPMessageContainer{Messages: []MTPMessage{{
		MessageID: 0x0102030405060708,
		Seqno:     1,
		Bytes:     12,
		Body:      &MTPPing{PingID: 0x1112131415161718},
	}}}
	encoded, err := Encode(value)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want, err := hex.DecodeString(
		"dcf8f173" +
			"01000000" +
			"0807060504030201" +
			"01000000" +
			"0c000000" +
			"ec77be7a" +
			"1817161514131211",
	)
	if err != nil {
		t.Fatalf("decode expected bytes: %v", err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded bytes = %x, want %x", encoded, want)
	}
}

func TestEncodeGeneratedMessageContainerRejectsBodyLengthMismatch(t *testing.T) {
	t.Parallel()

	_, err := Encode(&MTPMessageContainer{Messages: []MTPMessage{{
		Bytes: 4,
		Body:  &MTPPing{},
	}}})
	if !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("Encode error = %v, want ErrInvalidLength", err)
	}
}

func TestEncodeGeneratedBareObjectVector(t *testing.T) {
	t.Parallel()

	value := &MTPFutureSalts{
		ReqMessageID: 1,
		Now:          2,
		Salts: []MTPFutureSalt{{
			ValidSince: 3,
			ValidUntil: 4,
			Salt:       5,
		}},
	}
	encoded, err := Encode(value)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want, err := hex.DecodeString(
		"950850ae" +
			"0100000000000000" +
			"02000000" +
			"01000000" +
			"03000000" +
			"04000000" +
			"0500000000000000",
	)
	if err != nil {
		t.Fatalf("decode expected bytes: %v", err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded bytes = %x, want %x", encoded, want)
	}
}

func TestEncodeGeneratedFlags(t *testing.T) {
	t.Parallel()

	rank := "admin"
	encoded, err := Encode(&ChatParticipantAdmin{
		UserID:    1,
		InviterID: 2,
		Date:      3,
		Rank:      &rank,
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want, err := hex.DecodeString(
		"d2d56003" +
			"01000000" +
			"0100000000000000" +
			"0200000000000000" +
			"03000000" +
			"0561646d696e0000",
	)
	if err != nil {
		t.Fatalf("decode expected bytes: %v", err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded bytes = %x, want %x", encoded, want)
	}
}

func TestEncodeGeneratedGenericQuery(t *testing.T) {
	t.Parallel()

	value := &InvokeAfterMessageRequest[*NearestDC]{
		MessageID: 1,
		Query:     &HelpGetNearestDCRequest{},
	}
	encoded, err := Encode(value)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want, err := hex.DecodeString(
		"2d379fcb" +
			"0100000000000000" +
			"2630b31f",
	)
	if err != nil {
		t.Fatalf("decode expected bytes: %v", err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded bytes = %x, want %x", encoded, want)
	}
}

func TestEncodeRejectsInconsistentSharedPredicate(t *testing.T) {
	t.Parallel()

	maxTipAmount := int64(100)
	_, err := Encode(&Invoice{MaxTipAmount: &maxTipAmount})
	if !errors.Is(err, ErrInconsistentFlags) {
		t.Fatalf("Encode error = %v, want ErrInconsistentFlags", err)
	}
	var encodeError *EncodeError
	if !errors.As(err, &encodeError) {
		t.Fatalf("Encode error type = %T, want *EncodeError", err)
	}
	if encodeError.Type != "invoice" || encodeError.Field != "flags.8" {
		t.Fatalf("Encode error location = %s.%s", encodeError.Type, encodeError.Field)
	}
}

func TestEncodeRejectsNilObjects(t *testing.T) {
	t.Parallel()

	var nilPing *MTPPing
	if _, err := Encode(nilPing); !errors.Is(err, ErrNilObject) {
		t.Fatalf("typed nil error = %v, want ErrNilObject", err)
	}
	if _, err := Encode(&InputStickeredMediaDocument{}); !errors.Is(
		err,
		ErrNilObject,
	) {
		t.Fatalf("required nil field error = %v, want ErrNilObject", err)
	}
}

func TestAppendGeneratedReusesCapacity(t *testing.T) {
	t.Parallel()

	dst := make([]byte, 3, 32)
	copy(dst, "raw")
	encoded, err := Append(dst, &MTPPing{PingID: 1})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if string(encoded[:3]) != "raw" {
		t.Fatalf("prefix = %q, want raw", encoded[:3])
	}
	if &encoded[0] != &dst[0] {
		t.Fatal("Append allocated despite sufficient destination capacity")
	}
}
