package cryptoutil

import (
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
)

const knownDHPrimeHex = "C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C3720FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F642477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B"

var (
	ErrInvalidDHPrimeRange = errors.New(
		"cryptoutil: dh_prime must be a 2048-bit value",
	)
	ErrInvalidDHPrime = errors.New(
		"cryptoutil: dh_prime is not prime",
	)
	ErrInvalidDHSafePrime = errors.New(
		"cryptoutil: dh_prime is not a safe prime",
	)
	ErrInvalidDHGenerator = errors.New(
		"cryptoutil: invalid dh generator",
	)
	ErrInvalidDHPublicValue = errors.New(
		"cryptoutil: dh public value is outside the safe range",
	)
	ErrDHRandom = errors.New(
		"cryptoutil: dh prime randomness failed",
	)

	knownDHPrime = mustBigInt(knownDHPrimeHex)
	twoPow2047   = new(big.Int).Lsh(big.NewInt(1), 2047)
	twoPow2048   = new(big.Int).Lsh(big.NewInt(1), 2048)
	twoPow1984   = new(big.Int).Lsh(big.NewInt(1), 1984)
)

// TelegramDHPrime returns a copy of Telegram's current 2048-bit DH prime.
func TelegramDHPrime() *big.Int {
	return new(big.Int).Set(knownDHPrime)
}

// ValidateDHPrime validates Telegram's 2048-bit safe-prime and generator
// requirements. The known Telegram prime uses the protocol's fast path.
func ValidateDHPrime(random io.Reader, prime *big.Int, generator int) error {
	if random == nil {
		return ErrNilRandomSource
	}
	if prime == nil ||
		prime.Sign() <= 0 ||
		prime.Cmp(twoPow2047) <= 0 ||
		prime.Cmp(twoPow2048) >= 0 {
		return ErrInvalidDHPrimeRange
	}

	if prime.Cmp(knownDHPrime) != 0 {
		probablyPrime, err := dhProbablyPrime(random, prime)
		if err != nil {
			return err
		}
		if !probablyPrime {
			return ErrInvalidDHPrime
		}
		safePrime := new(big.Int).Sub(new(big.Int).Set(prime), big.NewInt(1))
		safePrime.Rsh(safePrime, 1)
		probablyPrime, err = dhProbablyPrime(random, safePrime)
		if err != nil {
			return err
		}
		if !probablyPrime {
			return ErrInvalidDHSafePrime
		}
	}

	return validateDHGenerator(prime, generator)
}

func dhProbablyPrime(random io.Reader, prime *big.Int) (bool, error) {
	if !prime.ProbablyPrime(0) {
		return false, nil
	}

	one := big.NewInt(1)
	two := big.NewInt(2)
	three := big.NewInt(3)
	minusOne := new(big.Int).Sub(new(big.Int).Set(prime), one)
	oddPart := new(big.Int).Set(minusOne)
	shift := oddPart.TrailingZeroBits()
	oddPart.Rsh(oddPart, shift)
	upper := new(big.Int).Sub(new(big.Int).Set(prime), three)

	for range 20 {
		base, err := cryptorand.Int(random, upper)
		if err != nil {
			return false, fmt.Errorf("%w: %w", ErrDHRandom, err)
		}
		base.Add(base, two)
		value := new(big.Int).Exp(base, oddPart, prime)
		if value.Cmp(one) == 0 || value.Cmp(minusOne) == 0 {
			continue
		}

		passed := false
		for round := uint(1); round < shift; round++ {
			value.Exp(value, two, prime)
			if value.Cmp(minusOne) == 0 {
				passed = true
				break
			}
			if value.Cmp(one) == 0 {
				return false, nil
			}
		}
		if !passed {
			return false, nil
		}
	}
	return true, nil
}

// ValidateDHPublicValue validates g_a or g_b against the negotiated prime.
func ValidateDHPublicValue(prime, value *big.Int) error {
	if prime == nil || value == nil {
		return ErrInvalidDHPublicValue
	}
	if value.Cmp(big.NewInt(1)) <= 0 || value.Cmp(prime) >= 0 {
		return ErrInvalidDHPublicValue
	}

	upper := new(big.Int).Sub(prime, twoPow1984)
	if value.Cmp(twoPow1984) <= 0 || value.Cmp(upper) >= 0 {
		return ErrInvalidDHPublicValue
	}
	return nil
}

func validateDHGenerator(prime *big.Int, generator int) error {
	if generator <= 1 || new(big.Int).SetInt64(int64(generator)).Cmp(prime) >= 0 {
		return ErrInvalidDHGenerator
	}

	switch generator {
	case 2:
		if new(big.Int).Mod(new(big.Int).Set(prime), big.NewInt(8)).Cmp(big.NewInt(7)) != 0 {
			return ErrInvalidDHGenerator
		}
	case 3:
		if new(big.Int).Mod(new(big.Int).Set(prime), big.NewInt(3)).Cmp(big.NewInt(2)) != 0 {
			return ErrInvalidDHGenerator
		}
	case 4:
	case 5:
		mod := new(big.Int).Mod(new(big.Int).Set(prime), big.NewInt(5)).Int64()
		if mod != 1 && mod != 4 {
			return ErrInvalidDHGenerator
		}
	case 6:
		mod := new(big.Int).Mod(new(big.Int).Set(prime), big.NewInt(24)).Int64()
		if mod != 19 && mod != 23 {
			return ErrInvalidDHGenerator
		}
	case 7:
		mod := new(big.Int).Mod(new(big.Int).Set(prime), big.NewInt(7)).Int64()
		if mod != 3 && mod != 5 && mod != 6 {
			return ErrInvalidDHGenerator
		}
	default:
		return ErrInvalidDHGenerator
	}
	return nil
}

func mustBigInt(value string) *big.Int {
	result, ok := new(big.Int).SetString(value, 16)
	if !ok {
		panic("cryptoutil: invalid DH prime constant")
	}
	return result
}
