package cryptoutil

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"
)

func TestFactorPQVectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		pq uint64
		p  uint64
		q  uint64
	}{
		{2090522174869285481, 1112973847, 1878321023},
		{1470626929934143021, 1206429347, 1218991343},
		{2804275833720261793, 1555252417, 1803100129},
		{18446743979220271189, 4294967279, 4294967291},
	}
	for _, test := range tests {
		random := &testRandomReader{state: test.pq}
		p, q, err := FactorPQ(random, encodeUint64(test.pq))
		if err != nil {
			t.Fatalf("FactorPQ(%d): %v", test.pq, err)
		}
		if p != test.p || q != test.q {
			t.Fatalf(
				"FactorPQ(%d) = (%d, %d), want (%d, %d)",
				test.pq,
				p,
				q,
				test.p,
				test.q,
			)
		}
	}
}

func TestFactorPQRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		pq   []byte
	}{
		{name: "empty"},
		{name: "too long", pq: make([]byte, 9)},
		{name: "zero", pq: []byte{0}},
		{name: "one", pq: []byte{1}},
		{name: "even", pq: []byte{14}},
		{name: "prime", pq: []byte{17}},
		{name: "same factor", pq: []byte{49}},
		{name: "more than two factors", pq: []byte{45}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := FactorPQ(
				&testRandomReader{state: 1},
				test.pq,
			); !errors.Is(err, ErrInvalidPQ) {
				t.Fatalf("FactorPQ error = %v, want ErrInvalidPQ", err)
			}
		})
	}

	if _, _, err := FactorPQ(
		nil,
		[]byte{15},
	); !errors.Is(err, ErrNilRandomSource) {
		t.Fatalf("nil-random error = %v, want ErrNilRandomSource", err)
	}
}

func TestFactorPQPropagatesRandomError(t *testing.T) {
	t.Parallel()

	randomError := errors.New("random unavailable")
	if _, _, err := FactorPQ(
		errorReader{err: randomError},
		encodeUint64(2090522174869285481),
	); !errors.Is(err, randomError) {
		t.Fatalf("FactorPQ error = %v, want random error", err)
	}
}

func TestFactorPQBoundsWork(t *testing.T) {
	t.Parallel()

	var storage [8]byte
	_, err := factorPQBrent(
		&testRandomReader{state: 1},
		2305843009213693951,
		&storage,
	)
	if !errors.Is(err, ErrPQFactorization) {
		t.Fatalf("factorPQBrent error = %v, want ErrPQFactorization", err)
	}
}

func TestRandomUint64BelowBoundsSampling(t *testing.T) {
	t.Parallel()

	var storage [8]byte
	if _, err := randomUint64Below(
		bytes.NewReader(make([]byte, randomSampleAttempts*8)),
		^uint64(0),
		&storage,
	); !errors.Is(err, ErrPQRandomSampling) {
		t.Fatalf("randomUint64Below error = %v, want ErrPQRandomSampling", err)
	}
}

func TestIsPrime64MatchesBigInt(t *testing.T) {
	t.Parallel()

	values := []uint64{
		0,
		1,
		2,
		3,
		4,
		5,
		9,
		37,
		49,
		341550071728321,
		3825123056546413051,
		^uint64(0),
	}
	state := uint64(0x6a09e667f3bcc909)
	for range 4096 {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		values = append(values, state)
	}
	for _, value := range values {
		want := new(big.Int).SetUint64(value).ProbablyPrime(32)
		if got := isPrime64(value); got != want {
			t.Fatalf("isPrime64(%d) = %t, want %t", value, got, want)
		}
	}
}

func TestMulMod64MatchesBigInt(t *testing.T) {
	t.Parallel()

	for _, modulus := range []uint64{
		1<<63 - 1,
		^uint64(0) - 58,
	} {
		left := modulus - 2
		right := modulus - 3
		product := new(big.Int).Mul(
			new(big.Int).SetUint64(left),
			new(big.Int).SetUint64(right),
		)
		want := new(big.Int).Mod(
			product,
			new(big.Int).SetUint64(modulus),
		).Uint64()
		if got := mulMod64(left, right, modulus); got != want {
			t.Fatalf(
				"mulMod64 modulus %d = %d, want %d",
				modulus,
				got,
				want,
			)
		}
	}
}

func TestSquareAddMod64MatchesBigInt(t *testing.T) {
	t.Parallel()

	modulus := ^uint64(0) - 58
	value := modulus - 2
	addend := modulus - 3
	result := new(big.Int).Mul(
		new(big.Int).SetUint64(value),
		new(big.Int).SetUint64(value),
	)
	result.Add(result, new(big.Int).SetUint64(addend))
	want := result.Mod(
		result,
		new(big.Int).SetUint64(modulus),
	).Uint64()
	if got := squareAddMod64(value, addend, modulus); got != want {
		t.Fatalf("squareAddMod64 = %d, want %d", got, want)
	}
}

func TestFactorPQAllocations(t *testing.T) {
	encodedPQ := encodeUint64(2090522174869285481)
	random := &testRandomReader{state: 1}
	allocations := testing.AllocsPerRun(100, func() {
		if _, _, err := FactorPQ(random, encodedPQ); err != nil {
			panic(err)
		}
	})
	if allocations != 1 {
		t.Fatalf("FactorPQ allocations = %.0f, want 1", allocations)
	}
}

func FuzzFactorPQ(f *testing.F) {
	f.Add(encodeUint64(2090522174869285481))
	f.Add([]byte{15})
	f.Add([]byte{17})
	f.Fuzz(func(t *testing.T, encodedPQ []byte) {
		if len(encodedPQ) > 8 {
			t.Skip()
		}
		random := &testRandomReader{state: 0x510e527fade682d1}
		p, q, err := FactorPQ(random, encodedPQ)
		if err != nil {
			return
		}
		if p >= q || !isPrime64(p) || !isPrime64(q) {
			t.Fatalf("invalid factors (%d, %d)", p, q)
		}
	})
}

type testRandomReader struct {
	state uint64
}

func (r *testRandomReader) Read(output []byte) (int, error) {
	for index := range output {
		r.state ^= r.state << 13
		r.state ^= r.state >> 7
		r.state ^= r.state << 17
		output[index] = byte(r.state >> 56)
	}
	return len(output), nil
}

func encodeUint64(value uint64) []byte {
	var storage [8]byte
	binary.BigEndian.PutUint64(storage[:], value)
	index := 0
	for index < len(storage)-1 && storage[index] == 0 {
		index++
	}
	return bytes.Clone(storage[index:])
}
