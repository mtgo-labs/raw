package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

const igeIVSize = 2 * aes.BlockSize

var (
	ErrInvalidAESKeySize = errors.New(
		"cryptoutil: AES-IGE key must be 32 bytes",
	)
	ErrUninitializedAES256 = errors.New(
		"cryptoutil: AES-256 key is not initialized",
	)
	ErrInvalidAESIVSize = errors.New(
		"cryptoutil: AES-IGE IV must be 32 bytes",
	)
	ErrInvalidAESDataSize = errors.New(
		"cryptoutil: AES-IGE data length must be a multiple of 16 bytes",
	)
	ErrInvalidAESDestinationSize = errors.New(
		"cryptoutil: AES-IGE destination and source lengths must match",
	)
)

// AES256 owns an expanded AES-256 key.
type AES256 struct {
	block cipher.Block
}

// NewAES256 expands an AES-256 key for IGE operations.
func NewAES256(key []byte) (AES256, error) {
	if len(key) != 32 {
		return AES256{}, ErrInvalidAESKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return AES256{}, err
	}
	return AES256{block: block}, nil
}

// EncryptIGE encrypts src with AES-IGE into caller-owned dst.
// dst and src may be the same slice; otherwise they must not overlap.
func EncryptIGE(dst, src []byte, block AES256, iv []byte) error {
	if err := validateIGE(dst, src, block, iv); err != nil {
		return err
	}

	var previousCiphertext [aes.BlockSize]byte
	var previousPlaintext [aes.BlockSize]byte
	copy(previousCiphertext[:], iv[:aes.BlockSize])
	copy(previousPlaintext[:], iv[aes.BlockSize:])

	var plaintext [aes.BlockSize]byte
	for offset := 0; offset < len(src); offset += aes.BlockSize {
		copy(plaintext[:], src[offset:offset+aes.BlockSize])
		output := dst[offset : offset+aes.BlockSize]
		for index := range output {
			output[index] = plaintext[index] ^ previousCiphertext[index]
		}
		block.block.Encrypt(output, output)
		for index := range output {
			output[index] ^= previousPlaintext[index]
		}
		copy(previousCiphertext[:], output)
		previousPlaintext = plaintext
	}
	return nil
}

// DecryptIGE decrypts src with AES-IGE into caller-owned dst.
// dst and src may be the same slice; otherwise they must not overlap.
func DecryptIGE(dst, src []byte, block AES256, iv []byte) error {
	if err := validateIGE(dst, src, block, iv); err != nil {
		return err
	}

	var previousPlaintext [aes.BlockSize]byte
	var previousCiphertext [aes.BlockSize]byte
	copy(previousPlaintext[:], iv[aes.BlockSize:])
	copy(previousCiphertext[:], iv[:aes.BlockSize])

	var ciphertext [aes.BlockSize]byte
	for offset := 0; offset < len(src); offset += aes.BlockSize {
		copy(ciphertext[:], src[offset:offset+aes.BlockSize])
		output := dst[offset : offset+aes.BlockSize]
		for index := range output {
			output[index] = ciphertext[index] ^ previousPlaintext[index]
		}
		block.block.Decrypt(output, output)
		for index := range output {
			output[index] ^= previousCiphertext[index]
		}
		copy(previousPlaintext[:], output)
		previousCiphertext = ciphertext
	}
	return nil
}

func validateIGE(dst, src []byte, block AES256, iv []byte) error {
	switch {
	case block.block == nil:
		return ErrUninitializedAES256
	case len(iv) != igeIVSize:
		return ErrInvalidAESIVSize
	case len(src)%aes.BlockSize != 0:
		return ErrInvalidAESDataSize
	case len(dst) != len(src):
		return ErrInvalidAESDestinationSize
	default:
		return nil
	}
}
