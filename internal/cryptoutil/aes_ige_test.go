package cryptoutil

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestAESIGEVector(t *testing.T) {
	t.Parallel()

	// Pinned mtcute AES-256-IGE vector. Its IGE recurrence matches OpenSSL's
	// independent AES_ige_encrypt reference implementation.
	key := decodeHex(t,
		"5468697320697320616e20696d706c65"+
			"5468697320697320616e20696d706c65",
	)
	iv := decodeHex(t,
		"6d656e746174696f6e206f6620494745"+
			"206d6f646520666f72204f70656e5353",
	)
	plaintext := decodeHex(t,
		"99706487a1cde613bc6de0b6f24b1c7a"+
			"a448c8b9c3403e3467a8cad89340f53b",
	)
	ciphertext := decodeHex(t,
		"792ea8ae577b1a66cb3bd92679b8030c"+
			"a54ee631976bd3a04547fdcb4639fa69",
	)
	keyBefore := bytes.Clone(key)
	ivBefore := bytes.Clone(iv)
	plaintextBefore := bytes.Clone(plaintext)
	ciphertextBefore := bytes.Clone(ciphertext)
	block := newAES256(t, key)

	encrypted := make([]byte, len(plaintext))
	if err := EncryptIGE(encrypted, plaintext, block, iv); err != nil {
		t.Fatalf("EncryptIGE: %v", err)
	}
	if !bytes.Equal(encrypted, ciphertext) {
		t.Fatalf("ciphertext = %x, want %x", encrypted, ciphertext)
	}

	decrypted := make([]byte, len(ciphertext))
	if err := DecryptIGE(decrypted, ciphertext, block, iv); err != nil {
		t.Fatalf("DecryptIGE: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext = %x, want %x", decrypted, plaintext)
	}
	for name, value := range map[string]struct {
		got  []byte
		want []byte
	}{
		"key":        {key, keyBefore},
		"IV":         {iv, ivBefore},
		"plaintext":  {plaintext, plaintextBefore},
		"ciphertext": {ciphertext, ciphertextBefore},
	} {
		if !bytes.Equal(value.got, value.want) {
			t.Fatalf("%s input changed", name)
		}
	}
}

func TestAESIGEInPlace(t *testing.T) {
	t.Parallel()

	key := sequentialBytes(32, 0x20)
	iv := sequentialBytes(32, 0x40)
	plaintext := sequentialBytes(4*16, 0x60)
	data := bytes.Clone(plaintext)
	block := newAES256(t, key)

	if err := EncryptIGE(data, data, block, iv); err != nil {
		t.Fatalf("EncryptIGE: %v", err)
	}
	if bytes.Equal(data, plaintext) {
		t.Fatal("EncryptIGE did not change plaintext")
	}
	if err := DecryptIGE(data, data, block, iv); err != nil {
		t.Fatalf("DecryptIGE: %v", err)
	}
	if !bytes.Equal(data, plaintext) {
		t.Fatalf("round trip = %x, want %x", data, plaintext)
	}
}

func TestAESIGERejectsInvalidSizes(t *testing.T) {
	t.Parallel()

	validKey := make([]byte, 32)
	validBlock := newAES256(t, validKey)
	validIV := make([]byte, 32)
	validData := make([]byte, 32)
	tests := []struct {
		name  string
		dst   []byte
		src   []byte
		block AES256
		iv    []byte
		want  error
	}{
		{
			name:  "uninitialized AES-256",
			dst:   make([]byte, 32),
			src:   validData,
			block: AES256{},
			iv:    validIV,
			want:  ErrUninitializedAES256,
		},
		{
			name:  "short IV",
			dst:   make([]byte, 32),
			src:   validData,
			block: validBlock,
			iv:    make([]byte, 31),
			want:  ErrInvalidAESIVSize,
		},
		{
			name:  "long IV",
			dst:   make([]byte, 32),
			src:   validData,
			block: validBlock,
			iv:    make([]byte, 33),
			want:  ErrInvalidAESIVSize,
		},
		{
			name:  "partial block",
			dst:   make([]byte, 31),
			src:   make([]byte, 31),
			block: validBlock,
			iv:    validIV,
			want:  ErrInvalidAESDataSize,
		},
		{
			name:  "short destination",
			dst:   make([]byte, 16),
			src:   validData,
			block: validBlock,
			iv:    validIV,
			want:  ErrInvalidAESDestinationSize,
		},
		{
			name:  "long destination",
			dst:   make([]byte, 48),
			src:   validData,
			block: validBlock,
			iv:    validIV,
			want:  ErrInvalidAESDestinationSize,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			before := bytes.Clone(test.dst)
			if err := EncryptIGE(
				test.dst,
				test.src,
				test.block,
				test.iv,
			); !errors.Is(err, test.want) {
				t.Fatalf("EncryptIGE error = %v, want %v", err, test.want)
			}
			if !bytes.Equal(test.dst, before) {
				t.Fatal("EncryptIGE changed destination on validation failure")
			}
			if err := DecryptIGE(
				test.dst,
				test.src,
				test.block,
				test.iv,
			); !errors.Is(err, test.want) {
				t.Fatalf("DecryptIGE error = %v, want %v", err, test.want)
			}
			if !bytes.Equal(test.dst, before) {
				t.Fatal("DecryptIGE changed destination on validation failure")
			}
		})
	}
}

func TestNewAES256RejectsInvalidKeySizes(t *testing.T) {
	t.Parallel()

	for _, size := range []int{0, 16, 24, 31, 33} {
		if _, err := NewAES256(make([]byte, size)); !errors.Is(
			err,
			ErrInvalidAESKeySize,
		) {
			t.Fatalf("NewAES256 key size %d error = %v", size, err)
		}
	}
}

func TestAESIGEEmptyInput(t *testing.T) {
	t.Parallel()

	block := newAES256(t, make([]byte, 32))
	if err := EncryptIGE(nil, nil, block, make([]byte, 32)); err != nil {
		t.Fatalf("EncryptIGE: %v", err)
	}
	if err := DecryptIGE(nil, nil, block, make([]byte, 32)); err != nil {
		t.Fatalf("DecryptIGE: %v", err)
	}
}

func TestAESIGEModeAllocations(t *testing.T) {
	key := sequentialBytes(32, 0x20)
	iv := sequentialBytes(32, 0x40)
	src := sequentialBytes(1024, 0x60)
	dst := make([]byte, len(src))
	block := newAES256(t, key)

	var operationError error
	encryptAllocations := testing.AllocsPerRun(1000, func() {
		operationError = EncryptIGE(dst, src, block, iv)
	})
	if operationError != nil {
		t.Fatalf("EncryptIGE: %v", operationError)
	}
	if encryptAllocations != 0 {
		t.Fatalf("EncryptIGE allocations = %v, want 0", encryptAllocations)
	}

	decryptAllocations := testing.AllocsPerRun(1000, func() {
		operationError = DecryptIGE(dst, src, block, iv)
	})
	if operationError != nil {
		t.Fatalf("DecryptIGE: %v", operationError)
	}
	if decryptAllocations != 0 {
		t.Fatalf("DecryptIGE allocations = %v, want 0", decryptAllocations)
	}
}

func FuzzAESIGERoundTrip(f *testing.F) {
	f.Add(sequentialBytes(64, 0x60), false)
	f.Add(sequentialBytes(64, 0x60), true)
	f.Fuzz(func(t *testing.T, input []byte, inPlace bool) {
		if len(input) > 4096 {
			t.Skip()
		}
		plaintext := input[:len(input)-len(input)%16]
		key := sequentialBytes(32, 0x20)
		iv := sequentialBytes(32, 0x40)
		block, err := NewAES256(key)
		if err != nil {
			t.Fatalf("NewAES256: %v", err)
		}

		decrypted := make([]byte, len(plaintext))
		if inPlace {
			copy(decrypted, plaintext)
			if err := EncryptIGE(decrypted, decrypted, block, iv); err != nil {
				t.Fatalf("EncryptIGE: %v", err)
			}
			if err := DecryptIGE(decrypted, decrypted, block, iv); err != nil {
				t.Fatalf("DecryptIGE: %v", err)
			}
		} else {
			ciphertext := make([]byte, len(plaintext))
			if err := EncryptIGE(ciphertext, plaintext, block, iv); err != nil {
				t.Fatalf("EncryptIGE: %v", err)
			}
			if err := DecryptIGE(decrypted, ciphertext, block, iv); err != nil {
				t.Fatalf("DecryptIGE: %v", err)
			}
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("round trip = %x, want %x", decrypted, plaintext)
		}
	})
}

func newAES256(t *testing.T, key []byte) AES256 {
	t.Helper()
	block, err := NewAES256(key)
	if err != nil {
		t.Fatalf("NewAES256: %v", err)
	}
	return block
}

func decodeHex(t *testing.T, input string) []byte {
	t.Helper()
	output, err := hex.DecodeString(input)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	return output
}

func sequentialBytes(size int, start byte) []byte {
	output := make([]byte, size)
	for index := range output {
		output[index] = start + byte(index)
	}
	return output
}
