package cryptoutil

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"testing"
)

var mtcuteAuthKeyChunk = decodeHexString(
	"98cb29c6ffa89e79da695a54f572e6cb101e81c688b63a4bf73c3622dec230e0",
)

func TestComputeMessageKey(t *testing.T) {
	t.Parallel()

	// Expected hashes were computed independently with OpenSSL from CoreFork's
	// MTProto 2.0 auth-key offsets.
	authKey := repeatedBytes(mtcuteAuthKeyChunk, 8)
	plaintext := sequentialBytes(32, 0)
	tests := []struct {
		name      string
		direction MessageDirection
		want      string
	}{
		{
			name:      "client to server",
			direction: ClientToServer,
			want:      "894b894875ebce6603ffafd3f41b19d6",
		},
		{
			name:      "server to client",
			direction: ServerToClient,
			want:      "dd1fe9862a6907d65c65fe63fd80bf29",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := ComputeMessageKey(authKey, plaintext, test.direction)
			if err != nil {
				t.Fatalf("ComputeMessageKey: %v", err)
			}
			want := decodeHex(t, test.want)
			if !bytes.Equal(got[:], want) {
				t.Fatalf("message key = %x, want %x", got, want)
			}
		})
	}
}

func TestDeriveMessageAESKeyIV(t *testing.T) {
	t.Parallel()

	authKey := repeatedBytes(mtcuteAuthKeyChunk, 8)
	messageKey := array16(decodeHex(t, "25d701f2a29205526757825a99eb2d32"))
	tests := []struct {
		name       string
		direction  MessageDirection
		wantAES256 string
		wantIV     string
	}{
		{
			name:      "client to server",
			direction: ClientToServer,
			wantAES256: "af3f8e1ffa75f4c981eec33a3e5bbaa2" +
				"ea48f9bb93e91597627eb1f67960a0c9",
			wantIV: "9874d77f95155b35221bff94b7df4594" +
				"c6996e2a62e44fcb7d93c8c4e41b79ee",
		},
		{
			name:      "server to client",
			direction: ServerToClient,
			wantAES256: "d4b378e1e0525f10ff9d4c42807ccce5" +
				"b30a033a8088c0b922b5259421751648",
			wantIV: "4d7194f42f0135d2fd83050b403265b4" +
				"c40ee3e9e9fba56f0f4d8ea6bcb121f5",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			key, iv, err := deriveMessageAESKeyIV(
				authKey,
				messageKey,
				test.direction,
			)
			if err != nil {
				t.Fatalf("deriveMessageAESKeyIV: %v", err)
			}
			if want := decodeHex(t, test.wantAES256); !bytes.Equal(key[:], want) {
				t.Fatalf("AES key = %x, want %x", key, want)
			}
			if want := decodeHex(t, test.wantIV); !bytes.Equal(iv[:], want) {
				t.Fatalf("AES IV = %x, want %x", iv, want)
			}

			block, blockIV, err := NewMessageAES256(
				authKey,
				messageKey,
				test.direction,
			)
			if err != nil {
				t.Fatalf("NewMessageAES256: %v", err)
			}
			if block.block == nil {
				t.Fatal("NewMessageAES256 returned an uninitialized block")
			}
			if blockIV != iv {
				t.Fatalf("expanded-key IV = %x, want %x", blockIV, iv)
			}
			expectedBlock := newAES256(t, key[:])
			plaintext := make([]byte, 32)
			gotCiphertext := make([]byte, len(plaintext))
			if err := EncryptIGE(
				gotCiphertext,
				plaintext,
				block,
				iv[:],
			); err != nil {
				t.Fatalf("EncryptIGE derived block: %v", err)
			}
			wantCiphertext := make([]byte, len(plaintext))
			if err := EncryptIGE(
				wantCiphertext,
				plaintext,
				expectedBlock,
				iv[:],
			); err != nil {
				t.Fatalf("EncryptIGE expected block: %v", err)
			}
			if !bytes.Equal(gotCiphertext, wantCiphertext) {
				t.Fatal("NewMessageAES256 expanded the wrong key")
			}
		})
	}
}

func TestDeriveNonceAESKeyIV(t *testing.T) {
	t.Parallel()

	// CoreFork specifies a 256-bit new_nonce. The pinned mtcute fixture only
	// supplies 128 bits, so this vector extends it to the protocol width and
	// records independently computed OpenSSL SHA-1 results.
	serverNonce := array16(
		decodeHex(t, "8af24c551836e5ed7002f5857e6e71b2"),
	)
	newNonce := array32(
		decodeHex(t,
			"3bf48b2d3152f383d82d1f2b32ac7fb5"+
				"00000000000000000000000000000000",
		),
	)
	key, iv := DeriveNonceAESKeyIV(serverNonce, newNonce)
	wantKey := decodeHex(t,
		"8a50a44636837cd17a9f681697c08cca"+
			"cd1d5f0f25b3cef7095f614678381f25",
	)
	wantIV := decodeHex(t,
		"5af98b4fd46f6680af6de4dd42991ea7"+
			"75d7ae04dc70c94ddff32c1c3bf48b2d",
	)
	if !bytes.Equal(key[:], wantKey) {
		t.Fatalf("AES key = %x, want %x", key, wantKey)
	}
	if !bytes.Equal(iv[:], wantIV) {
		t.Fatalf("AES IV = %x, want %x", iv, wantIV)
	}
}

func TestMessageDerivationRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	validAuthKey := make([]byte, authKeySize)
	validPlaintext := make([]byte, 32)
	validMessageKey := [16]byte{}

	for _, size := range []int{0, authKeySize - 1, authKeySize + 1} {
		authKey := make([]byte, size)
		if _, err := ComputeMessageKey(
			authKey,
			validPlaintext,
			ClientToServer,
		); !errors.Is(err, ErrInvalidAuthKeySize) {
			t.Fatalf("ComputeMessageKey auth size %d error = %v", size, err)
		}
		if _, _, err := NewMessageAES256(
			authKey,
			validMessageKey,
			ClientToServer,
		); !errors.Is(err, ErrInvalidAuthKeySize) {
			t.Fatalf("NewMessageAES256 auth size %d error = %v", size, err)
		}
	}

	if _, err := ComputeMessageKey(
		validAuthKey,
		make([]byte, 31),
		ClientToServer,
	); !errors.Is(err, ErrInvalidAESDataSize) {
		t.Fatalf("unaligned plaintext error = %v", err)
	}

	for _, direction := range []MessageDirection{0, 3, 255} {
		if _, err := ComputeMessageKey(
			validAuthKey,
			validPlaintext,
			direction,
		); !errors.Is(err, ErrInvalidMessageDirection) {
			t.Fatalf("ComputeMessageKey direction %d error = %v", direction, err)
		}
		if _, _, err := NewMessageAES256(
			validAuthKey,
			validMessageKey,
			direction,
		); !errors.Is(err, ErrInvalidMessageDirection) {
			t.Fatalf("NewMessageAES256 direction %d error = %v", direction, err)
		}
	}
}

func TestMessageDerivationDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	authKey := repeatedBytes(mtcuteAuthKeyChunk, 8)
	plaintext := sequentialBytes(32, 0x20)
	authKeyBefore := bytes.Clone(authKey)
	plaintextBefore := bytes.Clone(plaintext)
	messageKey, err := ComputeMessageKey(
		authKey,
		plaintext,
		ClientToServer,
	)
	if err != nil {
		t.Fatalf("ComputeMessageKey: %v", err)
	}
	if _, _, err := NewMessageAES256(
		authKey,
		messageKey,
		ClientToServer,
	); err != nil {
		t.Fatalf("NewMessageAES256: %v", err)
	}
	if !bytes.Equal(authKey, authKeyBefore) {
		t.Fatal("authorization key changed")
	}
	if !bytes.Equal(plaintext, plaintextBefore) {
		t.Fatal("plaintext changed")
	}
}

func TestMessageDerivationAllocations(t *testing.T) {
	authKey := repeatedBytes(mtcuteAuthKeyChunk, 8)
	plaintext := sequentialBytes(1024, 0x20)
	messageKey := [16]byte{}

	if allocations := testing.AllocsPerRun(1000, func() {
		_, _, _ = deriveMessageAESKeyIV(
			authKey,
			messageKey,
			ClientToServer,
		)
	}); allocations != 0 {
		t.Fatalf("deriveMessageAESKeyIV allocations = %v, want 0", allocations)
	}

	serverNonce := [16]byte{}
	newNonce := [32]byte{}
	if allocations := testing.AllocsPerRun(1000, func() {
		_, _ = DeriveNonceAESKeyIV(serverNonce, newNonce)
	}); allocations != 0 {
		t.Fatalf("DeriveNonceAESKeyIV allocations = %v, want 0", allocations)
	}

	var operationError error
	allocations := testing.AllocsPerRun(1000, func() {
		_, operationError = ComputeMessageKey(
			authKey,
			plaintext,
			ClientToServer,
		)
	})
	if operationError != nil {
		t.Fatalf("ComputeMessageKey: %v", operationError)
	}
	if allocations != 0 {
		t.Fatalf("ComputeMessageKey allocations = %v, want 0", allocations)
	}

	allocations = testing.AllocsPerRun(1000, func() {
		_, _, operationError = NewMessageAES256(
			authKey,
			messageKey,
			ClientToServer,
		)
	})
	if operationError != nil {
		t.Fatalf("NewMessageAES256: %v", operationError)
	}
	if allocations > 1 {
		t.Fatalf("NewMessageAES256 allocations = %v, want at most 1", allocations)
	}
}

func FuzzMessageDerivation(f *testing.F) {
	f.Add([]byte("mtproto"), false)
	f.Add(sequentialBytes(1024, 0x20), true)
	f.Fuzz(func(t *testing.T, input []byte, incoming bool) {
		if len(input) > 4096 {
			t.Skip()
		}
		authKey := fuzzAuthKey(input)
		plaintext := input[:len(input)-len(input)%16]
		direction := ClientToServer
		if incoming {
			direction = ServerToClient
		}

		messageKey, err := ComputeMessageKey(
			authKey[:],
			plaintext,
			direction,
		)
		if err != nil {
			t.Fatalf("ComputeMessageKey: %v", err)
		}
		if want := referenceMessageKey(
			authKey[:],
			plaintext,
			direction,
		); messageKey != want {
			t.Fatalf("message key = %x, want %x", messageKey, want)
		}

		key, iv, err := deriveMessageAESKeyIV(
			authKey[:],
			messageKey,
			direction,
		)
		if err != nil {
			t.Fatalf("deriveMessageAESKeyIV: %v", err)
		}
		wantKey, wantIV := referenceMessageAESKeyIV(
			authKey[:],
			messageKey,
			direction,
		)
		if key != wantKey || iv != wantIV {
			t.Fatalf(
				"AES key/IV = %x/%x, want %x/%x",
				key,
				iv,
				wantKey,
				wantIV,
			)
		}

		var serverNonce [16]byte
		var newNonce [32]byte
		copy(serverNonce[:], authKey[:16])
		copy(newNonce[:], authKey[16:48])
		nonceKey, nonceIV := DeriveNonceAESKeyIV(serverNonce, newNonce)
		wantNonceKey, wantNonceIV := referenceNonceAESKeyIV(
			serverNonce,
			newNonce,
		)
		if nonceKey != wantNonceKey || nonceIV != wantNonceIV {
			t.Fatalf(
				"nonce key/IV = %x/%x, want %x/%x",
				nonceKey,
				nonceIV,
				wantNonceKey,
				wantNonceIV,
			)
		}
	})
}

func referenceMessageKey(
	authKey, plaintext []byte,
	direction MessageDirection,
) [16]byte {
	offset := referenceDirectionOffset(direction)
	input := make([]byte, 0, 32+len(plaintext))
	input = append(input, authKey[88+offset:120+offset]...)
	input = append(input, plaintext...)
	fullHash := sha256.Sum256(input)
	return array16(fullHash[8:24])
}

func referenceMessageAESKeyIV(
	authKey []byte,
	messageKey [16]byte,
	direction MessageDirection,
) ([32]byte, [32]byte) {
	offset := referenceDirectionOffset(direction)
	inputA := append(bytes.Clone(messageKey[:]), authKey[offset:offset+36]...)
	hashA := sha256.Sum256(inputA)
	inputB := append(
		bytes.Clone(authKey[40+offset:76+offset]),
		messageKey[:]...,
	)
	hashB := sha256.Sum256(inputB)

	keyBytes := make([]byte, 0, 32)
	keyBytes = append(keyBytes, hashA[:8]...)
	keyBytes = append(keyBytes, hashB[8:24]...)
	keyBytes = append(keyBytes, hashA[24:]...)

	ivBytes := make([]byte, 0, 32)
	ivBytes = append(ivBytes, hashB[:8]...)
	ivBytes = append(ivBytes, hashA[8:24]...)
	ivBytes = append(ivBytes, hashB[24:]...)
	return array32(keyBytes), array32(ivBytes)
}

func referenceNonceAESKeyIV(
	serverNonce [16]byte,
	newNonce [32]byte,
) ([32]byte, [32]byte) {
	hash1Input := append(bytes.Clone(newNonce[:]), serverNonce[:]...)
	hash1 := sha1.Sum(hash1Input)
	hash2Input := append(bytes.Clone(serverNonce[:]), newNonce[:]...)
	hash2 := sha1.Sum(hash2Input)
	hash3Input := append(bytes.Clone(newNonce[:]), newNonce[:]...)
	hash3 := sha1.Sum(hash3Input)

	keyBytes := append(bytes.Clone(hash1[:]), hash2[:12]...)
	ivBytes := append(bytes.Clone(hash2[12:]), hash3[:]...)
	ivBytes = append(ivBytes, newNonce[:4]...)
	return array32(keyBytes), array32(ivBytes)
}

func referenceDirectionOffset(direction MessageDirection) int {
	if direction == ServerToClient {
		return 8
	}
	return 0
}

func fuzzAuthKey(input []byte) [authKeySize]byte {
	var authKey [authKeySize]byte
	if len(input) == 0 {
		for index := range authKey {
			authKey[index] = byte(index)
		}
		return authKey
	}
	for index := range authKey {
		authKey[index] = input[index%len(input)] ^ byte(index)
	}
	return authKey
}

func repeatedBytes(value []byte, count int) []byte {
	output := make([]byte, 0, len(value)*count)
	for range count {
		output = append(output, value...)
	}
	return output
}

func array16(value []byte) [16]byte {
	var output [16]byte
	copy(output[:], value)
	return output
}

func array32(value []byte) [32]byte {
	var output [32]byte
	copy(output[:], value)
	return output
}

func decodeHexString(value string) []byte {
	output := make([]byte, len(value)/2)
	for index := range output {
		high := fromHex(value[index*2])
		low := fromHex(value[index*2+1])
		output[index] = high<<4 | low
	}
	return output
}

func fromHex(value byte) byte {
	switch {
	case value >= '0' && value <= '9':
		return value - '0'
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10
	default:
		panic("invalid hex fixture")
	}
}
