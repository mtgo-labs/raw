package tl

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
)

func TestDecodeGeneratedObjects(t *testing.T) {
	t.Parallel()

	rank := "admin"
	tests := []Object{
		&MTPPing{PingID: 0x0102030405060708},
		&MTPFutureSalts{
			ReqMessageID: 1,
			Now:          2,
			Salts: []MTPFutureSalt{{
				ValidSince: 3,
				ValidUntil: 4,
				Salt:       5,
			}},
		},
		&ChatParticipantAdmin{
			UserID:    1,
			InviterID: 2,
			Date:      3,
			Rank:      &rank,
		},
	}
	limits := DefaultDecodeLimits()
	for _, want := range tests {
		want := want
		t.Run(reflect.TypeOf(want).String(), func(t *testing.T) {
			t.Parallel()

			input, err := Encode(want)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			got, err := Decode(input, limits)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("Decode() = %#v, want %#v", got, want)
			}
		})
	}
}

func TestDecodeGeneratedMessageContainerBodyBoundary(t *testing.T) {
	t.Parallel()

	input, err := Encode(&MTPMessageContainer{Messages: []MTPMessage{{
		MessageID: 1,
		Seqno:     1,
		Bytes:     12,
		Body:      &MTPPing{PingID: 2},
	}}})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	for _, test := range []struct {
		name string
		size uint32
		want error
	}{
		{name: "zero", size: 0, want: ErrInvalidLength},
		{name: "unaligned", size: 10, want: ErrInvalidLength},
		{name: "short", size: 8, want: ErrUnexpectedEOF},
		{name: "long", size: 16, want: ErrUnexpectedEOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			malformed := append([]byte(nil), input...)
			binary.LittleEndian.PutUint32(malformed[20:24], test.size)
			if _, err := Decode(malformed, DefaultDecodeLimits()); !errors.Is(err, test.want) {
				t.Fatalf("Decode error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestDecodeGeneratedMessageContainerGzipBody(t *testing.T) {
	t.Parallel()

	plain, err := Encode(&MTPPing{PingID: 2})
	if err != nil {
		t.Fatalf("Encode ping: %v", err)
	}
	body := packGzipForTest(t, plain)
	output := newEncoder(nil)
	output.putUint32(MTPMessageContainerConstructorID)
	if err := output.putBareVectorHeader(1); err != nil {
		t.Fatalf("put bare vector header: %v", err)
	}
	output.putInt64(1)
	output.putInt32(1)
	output.putInt32(int32(len(body)))
	output.buffer = append(output.buffer, body...)

	decoded, err := Decode(output.data(), DefaultDecodeLimits())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	container, ok := decoded.(*MTPMessageContainer)
	if !ok || len(container.Messages) != 1 {
		t.Fatalf("decoded container = %#v", decoded)
	}
	ping, ok := container.Messages[0].Body.(*MTPPing)
	if !ok || ping.PingID != 2 {
		t.Fatalf("decoded body = %#v", container.Messages[0].Body)
	}
}

func TestDecodeGeneratedMessageContainerRPCResultPayloads(t *testing.T) {
	t.Parallel()

	vector := newEncoder(nil)
	if err := vector.putVectorHeader(0); err != nil {
		t.Fatalf("put vector header: %v", err)
	}
	ping, err := Encode(&MTPPing{PingID: 2})
	if err != nil {
		t.Fatalf("Encode ping: %v", err)
	}
	rpcError, err := Encode(&MTPRPCError{ErrorCode: 400, ErrorMessage: "BAD_REQUEST"})
	if err != nil {
		t.Fatalf("Encode RPC error: %v", err)
	}
	tests := []struct {
		name   string
		result []byte
		want   []byte
		check  func([]byte) error
	}{
		{
			name:   "vector",
			result: vector.data(),
			want:   vector.data(),
			check: func(input []byte) error {
				users, err := DecodeResult(&UsersGetUsersRequest{}, input, DefaultDecodeLimits())
				if err == nil && len(users) != 0 {
					t.Fatalf("decoded users = %#v", users)
				}
				return err
			},
		},
		{
			name:   "gzip",
			result: packGzipForTest(t, ping),
			want:   ping,
			check: func(input []byte) error {
				value, err := Decode(input, DefaultDecodeLimits())
				if err == nil {
					decoded, ok := value.(*MTPPing)
					if !ok || decoded.PingID != 2 {
						t.Fatalf("decoded gzip result = %#v", value)
					}
				}
				return err
			},
		},
		{
			name:   "gzip RPC error",
			result: packGzipForTest(t, rpcError),
			want:   rpcError,
			check: func(input []byte) error {
				value, err := Decode(input, DefaultDecodeLimits())
				if err == nil {
					decoded, ok := value.(*MTPRPCError)
					if !ok || decoded.ErrorCode != 400 || decoded.ErrorMessage != "BAD_REQUEST" {
						t.Fatalf("decoded gzip RPC error = %#v", value)
					}
				}
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := newEncoder(nil)
			body.putUint32(MTPRPCResultConstructorID)
			body.putInt64(7)
			body.buffer = append(body.buffer, test.result...)
			output := newEncoder(nil)
			output.putUint32(MTPMessageContainerConstructorID)
			if err := output.putBareVectorHeader(1); err != nil {
				t.Fatalf("put bare vector header: %v", err)
			}
			output.putInt64(1)
			output.putInt32(1)
			output.putInt32(int32(len(body.data())))
			output.buffer = append(output.buffer, body.data()...)

			decoded, err := Decode(output.data(), DefaultDecodeLimits())
			if err != nil {
				t.Fatalf("Decode container: %v", err)
			}
			container, ok := decoded.(*MTPMessageContainer)
			if !ok || len(container.Messages) != 1 {
				t.Fatalf("decoded container = %#v", decoded)
			}
			result, ok := container.Messages[0].Body.(*MTPRPCResult)
			if !ok {
				t.Fatalf("decoded body = %#v", container.Messages[0].Body)
			}
			encoded, err := Encode(result.Result)
			if err != nil {
				t.Fatalf("Encode result: %v", err)
			}
			if !bytes.Equal(encoded, test.want) {
				t.Fatalf("result bytes = %x, want %x", encoded, test.want)
			}
			if err := test.check(encoded); err != nil {
				t.Fatalf("decode typed result: %v", err)
			}
		})
	}
}

func TestDecodeGeneratedResultShapes(t *testing.T) {
	t.Parallel()

	limits := DefaultDecodeLimits()
	nearest := &NearestDC{Country: "IQ", ThisDC: 2, NearestDC: 4}
	nearestInput, err := Encode(nearest)
	if err != nil {
		t.Fatalf("Encode nearest DC: %v", err)
	}
	gotNearest, err := DecodeResult(
		&HelpGetNearestDCRequest{},
		nearestInput,
		limits,
	)
	if err != nil {
		t.Fatalf("DecodeResult concrete: %v", err)
	}
	if !reflect.DeepEqual(gotNearest, nearest) {
		t.Fatalf("concrete result = %#v, want %#v", gotNearest, nearest)
	}

	wrapper := &InvokeAfterMessageRequest[*NearestDC]{
		Query: &HelpGetNearestDCRequest{},
	}
	gotWrapped, err := DecodeResult(wrapper, nearestInput, limits)
	if err != nil {
		t.Fatalf("DecodeResult generic: %v", err)
	}
	if !reflect.DeepEqual(gotWrapped, nearest) {
		t.Fatalf("generic result = %#v, want %#v", gotWrapped, nearest)
	}

	boolEncoder := newEncoder(nil)
	boolEncoder.putBool(true)
	gotBool, err := DecodeResult(
		&ContactsDeleteByPhonesRequest{},
		boolEncoder.data(),
		limits,
	)
	if err != nil {
		t.Fatalf("DecodeResult bool: %v", err)
	}
	if !gotBool {
		t.Fatal("bool result = false, want true")
	}

	statuses := []ContactStatus{{
		UserID: 7,
		Status: &UserStatusEmpty{},
	}}
	vectorEncoder := newEncoder(nil)
	if err := vectorEncoder.putVectorHeader(len(statuses)); err != nil {
		t.Fatalf("putVectorHeader: %v", err)
	}
	for index := range statuses {
		var err error
		vectorEncoder, err = statuses[index].encode(vectorEncoder)
		if err != nil {
			t.Fatalf("encode status: %v", err)
		}
	}
	gotStatuses, err := DecodeResult(
		&ContactsGetStatusesRequest{},
		vectorEncoder.data(),
		limits,
	)
	if err != nil {
		t.Fatalf("DecodeResult vector: %v", err)
	}
	if !reflect.DeepEqual(gotStatuses, statuses) {
		t.Fatalf("vector result = %#v, want %#v", gotStatuses, statuses)
	}
}

func TestDecodeRejectsMalformedGeneratedInput(t *testing.T) {
	t.Parallel()

	limits := DefaultDecodeLimits()
	value := &MTPFutureSalts{
		ReqMessageID: 1,
		Now:          2,
		Salts: []MTPFutureSalt{{
			ValidSince: 3,
			ValidUntil: 4,
			Salt:       5,
		}},
	}
	input, err := Encode(value)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	for end := range len(input) {
		if _, err := Decode(input[:end], limits); !errors.Is(
			err,
			ErrUnexpectedEOF,
		) {
			t.Fatalf(
				"Decode %d/%d bytes error = %v, want ErrUnexpectedEOF",
				end,
				len(input),
				err,
			)
		}
	}

	trailing := append(append([]byte(nil), input...), 0)
	if _, err := Decode(trailing, limits); !errors.Is(err, ErrTrailingData) {
		t.Fatalf("trailing data error = %v, want ErrTrailingData", err)
	}

	unknown := newEncoder(nil)
	unknown.putUint32(0xffffffff)
	if _, err := Decode(unknown.data(), limits); !errors.Is(
		err,
		ErrUnexpectedConstructor,
	) {
		t.Fatalf("unknown constructor error = %v", err)
	}

	wrong, err := Encode(&MTPPing{})
	if err != nil {
		t.Fatalf("Encode wrong result: %v", err)
	}
	if _, err := DecodeResult(
		&HelpGetNearestDCRequest{},
		wrong,
		limits,
	); !errors.Is(err, ErrUnexpectedConstructor) {
		t.Fatalf("wrong result error = %v", err)
	}
}

func TestDecodeGeneratedLimits(t *testing.T) {
	t.Parallel()

	input, err := Encode(&MTPPing{PingID: 1})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := Decode(input, DecodeLimits{}); !errors.Is(
		err,
		ErrInvalidDecodeLimits,
	) {
		t.Fatalf("zero limits error = %v", err)
	}

	limits := DefaultDecodeLimits()
	limits.MaxAllocation = 7
	if _, err := Decode(input, limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("allocation limit error = %v", err)
	}

	status := &ContactStatus{UserID: 1, Status: &UserStatusEmpty{}}
	statusInput, err := Encode(status)
	if err != nil {
		t.Fatalf("Encode nested value: %v", err)
	}
	limits = DefaultDecodeLimits()
	limits.MaxDepth = 1
	if _, err := Decode(statusInput, limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("depth limit error = %v", err)
	}
}

func TestDecodeResultRejectsTypedNilRequest(t *testing.T) {
	t.Parallel()

	var request *HelpGetNearestDCRequest
	_, err := DecodeResult(request, nil, DefaultDecodeLimits())
	if !errors.Is(err, ErrNilObject) {
		t.Fatalf("typed nil request error = %v, want ErrNilObject", err)
	}
}

func TestDecodedStringOwnsInput(t *testing.T) {
	t.Parallel()

	input, err := Encode(&NearestDC{
		Country:   "IQ",
		ThisDC:    2,
		NearestDC: 4,
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	value, err := DecodeResult(
		&HelpGetNearestDCRequest{},
		input,
		DefaultDecodeLimits(),
	)
	if err != nil {
		t.Fatalf("DecodeResult: %v", err)
	}
	for index := range input {
		input[index] = 0
	}
	if value.Country != "IQ" {
		t.Fatalf("decoded country changed with input: %q", value.Country)
	}
}

func FuzzDecodeGenerated(f *testing.F) {
	seeds := []Object{
		&MTPPing{PingID: 1},
		&NearestDC{Country: "IQ", ThisDC: 2, NearestDC: 4},
		&ContactStatus{UserID: 1, Status: &UserStatusEmpty{}},
	}
	for _, seed := range seeds {
		input, err := Encode(seed)
		if err != nil {
			f.Fatalf("Encode seed: %v", err)
		}
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		limits := DecodeLimits{
			MaxBytes:             4096,
			MaxVectorElements:    128,
			MaxDepth:             16,
			MaxAllocation:        16 << 10,
			MaxDecompressedBytes: 4096,
		}
		_, _ = Decode(input, limits)
	})
}

func FuzzDecodeGeneratedResult(f *testing.F) {
	seed, err := Encode(&NearestDC{
		Country:   "IQ",
		ThisDC:    2,
		NearestDC: 4,
	})
	if err != nil {
		f.Fatalf("Encode seed: %v", err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, input []byte) {
		limits := DecodeLimits{
			MaxBytes:             4096,
			MaxVectorElements:    128,
			MaxDepth:             16,
			MaxAllocation:        16 << 10,
			MaxDecompressedBytes: 4096,
		}
		_, _ = DecodeResult(&HelpGetNearestDCRequest{}, input, limits)
	})
}
