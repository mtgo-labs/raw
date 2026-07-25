package cryptoutil

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"testing"
)

func TestEncryptRSAPaddedVector(t *testing.T) {
	t.Parallel()

	publicKey := loadTelegramRSAPublicKey(t)
	data := sequentialBytes(64, 0x20)
	randomTape := deterministicBytes(
		rsaPaddedDataSize-len(data)+rsaPadMaxAttempts*32,
		0x31,
	)
	output, err := EncryptRSAPadded(
		bytes.NewReader(randomTape),
		publicKey,
		data,
	)
	if err != nil {
		t.Fatalf("EncryptRSAPadded: %v", err)
	}
	// Verified independently with OpenSSL raw RSA against the first key in
	// schema/rsa-keys.txt.
	wantCiphertext := decodeHex(t,
		"9e0f4f3a7d8d8b62a771f41790f473f8e7ddc0fd5c54be149d505d39fdf8acea"+
			"2d0a18bfc7f4b5dcd9ba5d3960defa3e28e39b2d22e94a0dd0d07d028d8716cf"+
			"93b2a2131593100d963992a8417d527d2265cc6c98eb16a7fe7909834912a2e553"+
			"0967efc654209774b9ceea1a7294dcff49dfde29120b7d8ad4c409de7476c9767"+
			"64405a86d93e2e9aea86f9c2606e8b393dea211dcf0558e6fe2b43e1f7d34d867"+
			"7a540da017706d77102dc9c8cd86da2da404aea8d1edf377b513976b329a4618f"+
			"4a0f1efdc5a9fdee5ab80c9f730867a95b761e81f850b0dcebceb40bb19d3fb0e"+
			"68ef0e38aae0ead9b15f4208c59a2f2dcdaba1b576020e0664d18947dd",
	)
	if !bytes.Equal(output[:], wantCiphertext) {
		t.Fatalf("ciphertext = %x, want %x", output, wantCiphertext)
	}

	paddingSize := rsaPaddedDataSize - len(data)
	candidate := referenceRSAPadCandidate(
		t,
		data,
		randomTape[:paddingSize],
		array32(randomTape[paddingSize:paddingSize+32]),
	)
	if new(big.Int).SetBytes(candidate[:]).Cmp(publicKey.N) >= 0 {
		t.Fatal("test vector unexpectedly requires a temporary-key retry")
	}
	wantCandidate := decodeHex(t,
		"4b7e1f885a86dd165da462b35d7919abe9cb06c7df266d5a832b0b164f83566c"+
			"51b4f0c79a24b4e17be133c92704f3d1b80b32cf4bbdc8ec584fc5cf687c18ca"+
			"83dd51b40c8a46a7ca779db4ede20ff7e71a9ccef1c4453a6b6f7bbd8cb34a0d9"+
			"2449e999b1febdf044c37e27dad80b480dec448e1c8aa6fa3d086d52a19e41fbf"+
			"a533b86e4f79f95f148e0b34f2fb9cb276f771f05dd0aba1a0d0fb625fcc43c6f"+
			"31b5b976d6b329b05008132787049a3dbb820b597f5d939133f9964580d6c0d1b"+
			"edd7ab7342b25cc75d8544bd4967f48402e23d60c5b1431277db1ba56fe64e264"+
			"4e308b6f4657a0f19acc7913c60fca209aea9ab434609ec9ff9c1abd65c",
	)
	if !bytes.Equal(candidate[:], wantCandidate) {
		t.Fatalf("candidate = %x, want %x", candidate, wantCandidate)
	}
}

func TestEncryptRSAPaddedRetriesCandidate(t *testing.T) {
	t.Parallel()

	publicKey := minimumRSAKey()
	padding := deterministicBytes(rsaPaddedDataSize, 0x41)
	rejectedKey, acceptedKey := candidateKeysForTest(t, padding, publicKey.N)
	randomTape := append(bytes.Clone(padding), rejectedKey[:]...)
	randomTape = append(randomTape, acceptedKey[:]...)
	random := bytes.NewReader(randomTape)

	if _, err := EncryptRSAPadded(random, publicKey, nil); err != nil {
		t.Fatalf("EncryptRSAPadded: %v", err)
	}
	if random.Len() != 0 {
		t.Fatalf("random bytes remaining = %d, want 0", random.Len())
	}
}

func TestEncryptRSAPaddedBoundsCandidateRetries(t *testing.T) {
	t.Parallel()

	publicKey := minimumRSAKey()
	padding := deterministicBytes(rsaPaddedDataSize, 0x41)
	rejectedKey, _ := candidateKeysForTest(t, padding, publicKey.N)
	randomTape := bytes.Clone(padding)
	for range rsaPadMaxAttempts {
		randomTape = append(randomTape, rejectedKey[:]...)
	}

	if _, err := EncryptRSAPadded(
		bytes.NewReader(randomTape),
		publicKey,
		nil,
	); !errors.Is(err, ErrRSAPaddingAttempts) {
		t.Fatalf("retry-limit error = %v, want ErrRSAPaddingAttempts", err)
	}
}

func TestEncryptRSAPaddedRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	validKey := loadTelegramRSAPublicKey(t)
	invalidKeys := []*rsa.PublicKey{
		nil,
		{},
		{N: big.NewInt(-1), E: 65537},
		{N: new(big.Int).Lsh(big.NewInt(1), 2046), E: 65537},
		{N: new(big.Int).Lsh(big.NewInt(1), 2048), E: 65537},
		{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537},
		{N: new(big.Int).Set(validKey.N), E: 1},
		{N: new(big.Int).Set(validKey.N), E: 2},
	}
	for index, publicKey := range invalidKeys {
		if _, err := EncryptRSAPadded(
			bytes.NewReader(nil),
			publicKey,
			nil,
		); !errors.Is(err, ErrInvalidRSAPublicKey) {
			t.Fatalf("invalid key %d error = %v", index, err)
		}
	}

	if _, err := EncryptRSAPadded(
		bytes.NewReader(nil),
		validKey,
		make([]byte, rsaMaxDataSize+1),
	); !errors.Is(err, ErrRSADataTooLarge) {
		t.Fatalf("oversized-data error = %v, want ErrRSADataTooLarge", err)
	}
	if _, err := EncryptRSAPadded(
		nil,
		validKey,
		nil,
	); !errors.Is(err, ErrNilRandomSource) {
		t.Fatalf("nil-random error = %v, want ErrNilRandomSource", err)
	}
}

func TestEncryptRSAPaddedPropagatesRandomErrors(t *testing.T) {
	t.Parallel()

	publicKey := loadTelegramRSAPublicKey(t)
	randomError := errors.New("random unavailable")
	if _, err := EncryptRSAPadded(
		errorReader{err: randomError},
		publicKey,
		nil,
	); !errors.Is(err, randomError) {
		t.Fatalf("padding random error = %v", err)
	}

	padding := make([]byte, rsaPaddedDataSize)
	if _, err := EncryptRSAPadded(
		bytes.NewReader(padding),
		publicKey,
		nil,
	); !errors.Is(err, io.EOF) {
		t.Fatalf("temporary-key random error = %v, want io.EOF", err)
	}
}

func TestEncryptRSAPaddedDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	publicKey := loadTelegramRSAPublicKey(t)
	data := sequentialBytes(rsaMaxDataSize, 0x20)
	before := bytes.Clone(data)
	randomTape := deterministicBytes(
		rsaPaddedDataSize-len(data)+rsaPadMaxAttempts*32,
		0x51,
	)
	if _, err := EncryptRSAPadded(
		bytes.NewReader(randomTape),
		publicKey,
		data,
	); err != nil {
		t.Fatalf("EncryptRSAPadded: %v", err)
	}
	if !bytes.Equal(data, before) {
		t.Fatal("input data changed")
	}
}

func FuzzEncryptRSAPadded(f *testing.F) {
	publicKey := loadTelegramRSAPublicKey(f)
	f.Add([]byte("mtproto rsa"))
	f.Add(sequentialBytes(rsaMaxDataSize, 0x20))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > rsaMaxDataSize+16 {
			t.Skip()
		}
		randomSize := rsaPaddedDataSize + rsaPadMaxAttempts*32
		randomTape := make([]byte, randomSize)
		for index := range randomTape {
			if len(input) == 0 {
				randomTape[index] = byte(index*73 + 19)
			} else {
				randomTape[index] = input[index%len(input)] ^ byte(index*73+19)
			}
		}
		_, _ = EncryptRSAPadded(
			bytes.NewReader(randomTape),
			publicKey,
			input,
		)
	})
}

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

func referenceRSAPadCandidate(
	t *testing.T,
	data, padding []byte,
	temporaryKey [32]byte,
) [rsaOutputSize]byte {
	t.Helper()
	var paddedData [rsaPaddedDataSize]byte
	copy(paddedData[:], data)
	copy(paddedData[len(data):], padding)

	var hashInput [32 + rsaPaddedDataSize]byte
	copy(hashInput[:32], temporaryKey[:])
	copy(hashInput[32:], paddedData[:])
	dataHash := sha256.Sum256(hashInput[:])

	var dataWithHash [rsaPaddedDataSize + sha256.Size]byte
	for index := range paddedData {
		dataWithHash[index] = paddedData[len(paddedData)-1-index]
	}
	copy(dataWithHash[rsaPaddedDataSize:], dataHash[:])

	block := newAES256(t, temporaryKey[:])
	var encrypted [rsaPaddedDataSize + sha256.Size]byte
	if err := EncryptIGE(
		encrypted[:],
		dataWithHash[:],
		block,
		make([]byte, 32),
	); err != nil {
		t.Fatalf("EncryptIGE: %v", err)
	}
	encryptedHash := sha256.Sum256(encrypted[:])

	var candidate [rsaOutputSize]byte
	for index := range temporaryKey {
		candidate[index] = temporaryKey[index] ^ encryptedHash[index]
	}
	copy(candidate[32:], encrypted[:])
	return candidate
}

func candidateKeysForTest(
	t *testing.T,
	padding []byte,
	modulus *big.Int,
) (rejected [32]byte, accepted [32]byte) {
	t.Helper()
	var foundRejected bool
	var foundAccepted bool
	for seed := range 256 {
		keyBytes := deterministicBytes(32, byte(seed))
		var temporaryKey [32]byte
		copy(temporaryKey[:], keyBytes)
		candidate := referenceRSAPadCandidate(
			t,
			nil,
			padding,
			temporaryKey,
		)
		comparison := new(big.Int).SetBytes(candidate[:]).Cmp(modulus)
		if comparison >= 0 && !foundRejected {
			rejected = temporaryKey
			foundRejected = true
		}
		if comparison < 0 && !foundAccepted {
			accepted = temporaryKey
			foundAccepted = true
		}
		if foundRejected && foundAccepted {
			return rejected, accepted
		}
	}
	t.Fatal("failed to find accepted and rejected RSA_PAD candidates")
	return rejected, accepted
}

func minimumRSAKey() *rsa.PublicKey {
	modulus := new(big.Int).Lsh(big.NewInt(1), 2047)
	modulus.Add(modulus, big.NewInt(1))
	return &rsa.PublicKey{N: modulus, E: 3}
}

func loadTelegramRSAPublicKey(t testing.TB) *rsa.PublicKey {
	t.Helper()
	data, err := os.ReadFile("../../schema/rsa-keys.txt")
	if err != nil {
		t.Fatalf("ReadFile RSA keys: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("Decode RSA public key: no PEM block")
		return nil
	}
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS1PublicKey: %v", err)
	}
	return publicKey
}

func deterministicBytes(size int, seed byte) []byte {
	output := make([]byte, size)
	state := uint32(seed) + 1
	for index := range output {
		state = state*1664525 + 1013904223
		output[index] = byte(state >> 24)
	}
	return output
}
