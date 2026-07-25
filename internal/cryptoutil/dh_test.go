package cryptoutil

import (
	"errors"
	"math/big"
	"testing"
)

func TestValidateDHPrimeKnownTelegramPrime(t *testing.T) {
	t.Parallel()

	if err := ValidateDHPrime(&testRandomReader{state: 1}, knownDHPrime, 4); err != nil {
		t.Fatalf("ValidateDHPrime known prime: %v", err)
	}
	if err := ValidateDHPrime(nil, knownDHPrime, 4); !errors.Is(err, ErrNilRandomSource) {
		t.Fatalf("nil random ValidateDHPrime = %v, want ErrNilRandomSource", err)
	}
}

func TestValidateDHPrimeRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	for _, prime := range []*big.Int{
		nil,
		big.NewInt(0),
		new(big.Int).Set(twoPow2047),
		new(big.Int).Set(twoPow2048),
	} {
		if err := ValidateDHPrime(&testRandomReader{state: 1}, prime, 4); !errors.Is(err, ErrInvalidDHPrimeRange) {
			t.Fatalf("ValidateDHPrime(%v) = %v, want range error", prime, err)
		}
	}

	composite := new(big.Int).Add(new(big.Int).Set(twoPow2047), big.NewInt(1))
	if err := ValidateDHPrime(&testRandomReader{state: 1}, composite, 4); !errors.Is(err, ErrInvalidDHPrime) {
		t.Fatalf("composite ValidateDHPrime = %v, want prime error", err)
	}

	for _, generator := range []int{0, 1, 8, -1} {
		if err := ValidateDHPrime(&testRandomReader{state: 1}, knownDHPrime, generator); !errors.Is(err, ErrInvalidDHGenerator) {
			t.Fatalf("generator %d error = %v, want generator error", generator, err)
		}
	}
}

func TestDHProbablyPrimePropagatesRandomError(t *testing.T) {
	t.Parallel()

	if prime, err := dhProbablyPrime(&testRandomReader{state: 1}, knownDHPrime); err != nil || !prime {
		t.Fatalf("known dhProbablyPrime = (%t, %v), want (true, nil)", prime, err)
	}
	safePrime := new(big.Int).Sub(new(big.Int).Set(knownDHPrime), big.NewInt(1))
	safePrime.Rsh(safePrime, 1)
	if prime, err := dhProbablyPrime(&testRandomReader{state: 2}, safePrime); err != nil || !prime {
		t.Fatalf("known safe dhProbablyPrime = (%t, %v), want (true, nil)", prime, err)
	}

	randomError := errors.New("random unavailable")
	if _, err := dhProbablyPrime(errorReader{err: randomError}, knownDHPrime); !errors.Is(err, randomError) {
		t.Fatalf("dhProbablyPrime error = %v, want random error", err)
	}
}

func TestValidateDHPublicValue(t *testing.T) {
	t.Parallel()

	lower := new(big.Int).Set(twoPow1984)
	upper := new(big.Int).Sub(knownDHPrime, twoPow1984)
	validLower := new(big.Int).Add(lower, big.NewInt(1))
	validUpper := new(big.Int).Sub(upper, big.NewInt(1))
	for _, value := range []*big.Int{validLower, validUpper} {
		if err := ValidateDHPublicValue(knownDHPrime, value); err != nil {
			t.Fatalf("valid public value %v: %v", value, err)
		}
	}
	for _, value := range []*big.Int{
		nil,
		big.NewInt(-1),
		big.NewInt(0),
		big.NewInt(1),
		lower,
		upper,
		new(big.Int).Sub(knownDHPrime, big.NewInt(1)),
		knownDHPrime,
	} {
		if err := ValidateDHPublicValue(knownDHPrime, value); !errors.Is(err, ErrInvalidDHPublicValue) {
			t.Fatalf("invalid public value %v: %v", value, err)
		}
	}
}

func TestValidateDHGeneratorResidues(t *testing.T) {
	t.Parallel()

	checks := []struct {
		generator int
		modulus   int64
		allowed   []int64
	}{
		{2, 8, []int64{7}},
		{3, 3, []int64{2}},
		{5, 5, []int64{1, 4}},
		{6, 24, []int64{19, 23}},
		{7, 7, []int64{3, 5, 6}},
	}
	for _, check := range checks {
		prime := new(big.Int).Set(knownDHPrime)
		residue := new(big.Int).Mod(prime, big.NewInt(check.modulus)).Int64()
		allowed := false
		for _, value := range check.allowed {
			allowed = allowed || residue == value
		}
		if allowed {
			if err := validateDHGenerator(prime, check.generator); err != nil {
				t.Fatalf("generator %d residue %d: %v", check.generator, residue, err)
			}
		}
	}
}

func FuzzValidateDHParams(f *testing.F) {
	f.Add(knownDHPrime.Bytes(), 4, knownDHPrime.Bytes())
	f.Add([]byte{1}, 0, []byte{1})
	f.Fuzz(func(t *testing.T, primeBytes []byte, generator int, valueBytes []byte) {
		if len(primeBytes) > 256 || len(valueBytes) > 256 {
			t.Skip()
		}
		prime := new(big.Int).SetBytes(primeBytes)
		value := new(big.Int).SetBytes(valueBytes)
		_ = ValidateDHPrime(&testRandomReader{state: 1}, prime, generator)
		_ = ValidateDHPublicValue(prime, value)
	})
}

func BenchmarkValidateDHPrime(b *testing.B) {
	prime := new(big.Int).Set(knownDHPrime)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := ValidateDHPrime(&testRandomReader{state: 1}, prime, 4); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidateDHPublicValue(b *testing.B) {
	value := new(big.Int).Add(twoPow1984, big.NewInt(1))
	prime := new(big.Int).Set(knownDHPrime)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := ValidateDHPublicValue(prime, value); err != nil {
			b.Fatal(err)
		}
	}
}
