package cryptoutil

import (
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
)

const (
	rsaPaddedDataSize = 192
	rsaOutputSize     = 256
	rsaMaxDataSize    = 144
	rsaPadMaxAttempts = 64
)

var (
	ErrInvalidRSAPublicKey = errors.New(
		"cryptoutil: RSA public key must have an odd 2048-bit modulus and exponent",
	)
	ErrRSADataTooLarge = errors.New(
		"cryptoutil: RSA_PAD data exceeds 144 bytes",
	)
	ErrNilRandomSource = errors.New(
		"cryptoutil: random source is nil",
	)
	ErrRSAPaddingAttempts = errors.New(
		"cryptoutil: RSA_PAD candidate retry limit exceeded",
	)
)

// EncryptRSAPadded applies Telegram's current RSA_PAD construction and raw RSA
// encryption. It returns one fixed-width 2048-bit ciphertext.
func EncryptRSAPadded(
	random io.Reader,
	publicKey *rsa.PublicKey,
	data []byte,
) ([rsaOutputSize]byte, error) {
	var output [rsaOutputSize]byte
	if err := validateRSAPublicKey(publicKey); err != nil {
		return output, err
	}
	if len(data) > rsaMaxDataSize {
		return output, ErrRSADataTooLarge
	}
	if random == nil {
		return output, ErrNilRandomSource
	}

	var paddedData [rsaPaddedDataSize]byte
	copy(paddedData[:], data)
	if _, err := io.ReadFull(random, paddedData[len(data):]); err != nil {
		return output, fmt.Errorf(
			"cryptoutil: read RSA_PAD data padding: %w",
			err,
		)
	}

	var hashInput [32 + rsaPaddedDataSize]byte
	copy(hashInput[32:], paddedData[:])
	var dataWithHash [rsaPaddedDataSize + sha256.Size]byte
	for index := range paddedData {
		dataWithHash[index] = paddedData[len(paddedData)-1-index]
	}
	var encryptedData [rsaPaddedDataSize + sha256.Size]byte
	var candidate [rsaOutputSize]byte
	var temporaryKey [32]byte
	var zeroIV [32]byte
	candidateInteger := new(big.Int)
	exponent := big.NewInt(int64(publicKey.E))
	encryptedInteger := new(big.Int)

	defer func() {
		clear(paddedData[:])
		clear(hashInput[:])
		clear(dataWithHash[:])
		clear(encryptedData[:])
		clear(candidate[:])
		clear(temporaryKey[:])
	}()

	for range rsaPadMaxAttempts {
		if _, err := io.ReadFull(random, temporaryKey[:]); err != nil {
			return output, fmt.Errorf(
				"cryptoutil: read RSA_PAD temporary key: %w",
				err,
			)
		}
		copy(hashInput[:32], temporaryKey[:])
		dataHash := sha256.Sum256(hashInput[:])
		copy(dataWithHash[rsaPaddedDataSize:], dataHash[:])
		clear(dataHash[:])

		block, err := NewAES256(temporaryKey[:])
		if err != nil {
			return output, fmt.Errorf(
				"cryptoutil: initialize RSA_PAD AES: %w",
				err,
			)
		}
		if err := EncryptIGE(
			encryptedData[:],
			dataWithHash[:],
			block,
			zeroIV[:],
		); err != nil {
			return output, fmt.Errorf(
				"cryptoutil: encrypt RSA_PAD data: %w",
				err,
			)
		}

		encryptedHash := sha256.Sum256(encryptedData[:])
		for index := range temporaryKey {
			candidate[index] = temporaryKey[index] ^ encryptedHash[index]
		}
		clear(encryptedHash[:])
		copy(candidate[32:], encryptedData[:])
		clear(temporaryKey[:])

		candidateInteger.SetBytes(candidate[:])
		if candidateInteger.Cmp(publicKey.N) >= 0 {
			continue
		}
		encryptedInteger.Exp(candidateInteger, exponent, publicKey.N)
		encryptedInteger.FillBytes(output[:])
		return output, nil
	}
	return output, ErrRSAPaddingAttempts
}

func validateRSAPublicKey(publicKey *rsa.PublicKey) error {
	if publicKey == nil ||
		publicKey.N == nil ||
		publicKey.N.Sign() <= 0 ||
		publicKey.N.BitLen() != rsaOutputSize*8 ||
		publicKey.N.Bit(0) == 0 ||
		publicKey.E < 3 ||
		publicKey.E%2 == 0 {
		return ErrInvalidRSAPublicKey
	}
	return nil
}
