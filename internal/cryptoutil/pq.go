package cryptoutil

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
)

const (
	pqFactorAttempts     = 8
	pqFactorMaxSteps     = 1 << 18
	pqFactorBatchSize    = 128
	randomSampleAttempts = 64
)

var (
	ErrInvalidPQ = errors.New(
		"cryptoutil: pq must encode two distinct odd primes within 64 bits",
	)
	ErrPQFactorization = errors.New(
		"cryptoutil: pq factorization work limit exceeded",
	)
	ErrPQRandomSampling = errors.New(
		"cryptoutil: pq random sampling retry limit exceeded",
	)
)

// FactorPQ decomposes Telegram's big-endian pq value into ordered prime
// factors. It returns p < q and performs no output allocation.
func FactorPQ(random io.Reader, encodedPQ []byte) (p, q uint64, err error) {
	if random == nil {
		return 0, 0, ErrNilRandomSource
	}
	pq, err := parsePQ(encodedPQ)
	if err != nil {
		return 0, 0, err
	}

	var randomStorage [8]byte
	factor, err := factorPQBrent(random, pq, &randomStorage)
	if err != nil {
		return 0, 0, err
	}
	other := pq / factor
	if factor > other {
		factor, other = other, factor
	}
	if factor == other ||
		factor*other != pq ||
		!isPrime64(factor) ||
		!isPrime64(other) {
		return 0, 0, ErrInvalidPQ
	}
	return factor, other, nil
}

func parsePQ(encoded []byte) (uint64, error) {
	if len(encoded) == 0 ||
		len(encoded) > 8 {
		return 0, ErrInvalidPQ
	}

	var storage [8]byte
	copy(storage[len(storage)-len(encoded):], encoded)
	pq := binary.BigEndian.Uint64(storage[:])
	if pq < 15 || pq&1 == 0 || isPrime64(pq) {
		return 0, ErrInvalidPQ
	}
	return pq, nil
}

func factorPQBrent(
	random io.Reader,
	pq uint64,
	randomStorage *[8]byte,
) (uint64, error) {
	for _, prime := range [...]uint64{
		3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
	} {
		if pq%prime == 0 {
			return prime, nil
		}
	}

	for range pqFactorAttempts {
		y, err := randomUint64Below(random, pq-1, randomStorage)
		if err != nil {
			return 0, fmt.Errorf("cryptoutil: sample pq factor state: %w", err)
		}
		y++
		c, err := randomUint64Below(random, pq-1, randomStorage)
		if err != nil {
			return 0, fmt.Errorf("cryptoutil: sample pq factor constant: %w", err)
		}
		c++

		var x uint64
		var recovery uint64
		divisor := uint64(1)
		cycleLength := 1
		steps := 0
		for divisor == 1 && steps < pqFactorMaxSteps {
			x = y
			for range cycleLength {
				if steps == pqFactorMaxSteps {
					break
				}
				y = squareAddMod64(y, c, pq)
				steps++
			}

			for offset := 0; offset < cycleLength &&
				divisor == 1 &&
				steps < pqFactorMaxSteps; offset += pqFactorBatchSize {
				recovery = y
				batchSize := min(
					pqFactorBatchSize,
					cycleLength-offset,
					pqFactorMaxSteps-steps,
				)
				product := uint64(1)
				for range batchSize {
					y = squareAddMod64(y, c, pq)
					product = mulMod64(product, difference64(x, y), pq)
					steps++
				}
				divisor = gcd64(product, pq)
			}

			if cycleLength > pqFactorMaxSteps/2 {
				break
			}
			cycleLength *= 2
		}

		if divisor == pq {
			divisor = 1
			for divisor == 1 && steps < pqFactorMaxSteps {
				recovery = squareAddMod64(recovery, c, pq)
				divisor = gcd64(difference64(x, recovery), pq)
				steps++
			}
		}
		if divisor > 1 && divisor < pq {
			return divisor, nil
		}
	}
	return 0, ErrPQFactorization
}

func randomUint64Below(
	random io.Reader,
	upper uint64,
	storage *[8]byte,
) (uint64, error) {
	threshold := -upper % upper
	for range randomSampleAttempts {
		if _, err := io.ReadFull(random, storage[:]); err != nil {
			return 0, err
		}
		value := binary.BigEndian.Uint64(storage[:])
		if value >= threshold {
			return value % upper, nil
		}
	}
	return 0, ErrPQRandomSampling
}

func isPrime64(value uint64) bool {
	if value < 2 {
		return false
	}
	for _, prime := range [...]uint64{
		2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37,
	} {
		if value%prime == 0 {
			return value == prime
		}
	}

	oddPart := value - 1
	twos := bits.TrailingZeros64(oddPart)
	oddPart >>= twos
	for _, base := range [...]uint64{
		2, 325, 9375, 28178, 450775, 9780504, 1795265022,
	} {
		base %= value
		if base == 0 {
			continue
		}
		power := powMod64(base, oddPart, value)
		if power == 1 || power == value-1 {
			continue
		}

		probablyPrime := false
		for round := 1; round < twos; round++ {
			power = mulMod64(power, power, value)
			if power == value-1 {
				probablyPrime = true
				break
			}
		}
		if !probablyPrime {
			return false
		}
	}
	return true
}

func powMod64(base, exponent, modulus uint64) uint64 {
	result := uint64(1)
	for exponent != 0 {
		if exponent&1 != 0 {
			result = mulMod64(result, base, modulus)
		}
		exponent >>= 1
		if exponent != 0 {
			base = mulMod64(base, base, modulus)
		}
	}
	return result
}

func squareAddMod64(value, addend, modulus uint64) uint64 {
	result, carry := bits.Add64(
		mulMod64(value, value, modulus),
		addend,
		0,
	)
	if carry != 0 || result >= modulus {
		result -= modulus
	}
	return result
}

func mulMod64(left, right, modulus uint64) uint64 {
	high, low := bits.Mul64(left, right)
	_, remainder := bits.Div64(high, low, modulus)
	return remainder
}

func difference64(left, right uint64) uint64 {
	if left >= right {
		return left - right
	}
	return right - left
}

func gcd64(left, right uint64) uint64 {
	for right != 0 {
		left, right = right, left%right
	}
	return left
}
