// Command fixturegen writes deterministic protocol fixtures with pinned source
// provenance.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
)

const (
	defaultOutput = "testdata/upstream/tl-primitives/manifest.json"
	repository    = "https://github.com/mtcute/mtcute"
	commit        = "2af1d0d5564a2a5b231c055cda53a7eb19a401eb"
	source        = "packages/tl-runtime/src/writer.ts"
)

type manifest struct {
	Version   int       `json:"version"`
	Upstream  upstream  `json:"upstream"`
	Generator string    `json:"generator"`
	Fixtures  []fixture `json:"fixtures"`
}

type upstream struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Source     string `json:"source"`
}

type fixture struct {
	Name      string `json:"name"`
	Operation string `json:"operation"`
	Input     any    `json:"input"`
	Hex       string `json:"hex"`
}

func main() {
	output := flag.String("output", defaultOutput, "fixture manifest output path")
	flag.Parse()

	fixtures, err := primitiveFixtures()
	if err != nil {
		fatal(err)
	}
	doc := manifest{
		Version: 1,
		Upstream: upstream{
			Repository: repository,
			Commit:     commit,
			Source:     source,
		},
		Generator: "cmd/fixturegen",
		Fixtures:  fixtures,
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fatal(fmt.Errorf("encode manifest: %w", err))
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
		fatal(fmt.Errorf("create output directory: %w", err))
	}
	if err := os.WriteFile(*output, data, 0o644); err != nil {
		fatal(fmt.Errorf("write %s: %w", *output, err))
	}
}

func primitiveFixtures() ([]fixture, error) {
	bytes253 := make([]byte, 253)
	bytes253[0], bytes253[len(bytes253)-1] = 0x01, 0xFF
	bytes254 := make([]byte, 254)
	bytes254[0], bytes254[len(bytes254)-1] = 0x01, 0xFF

	cases := []struct {
		name      string
		operation string
		input     any
		encode    func(*bytes.Buffer) error
	}{
		{"int-min", "int", "-2147483648", int32Encoder(math.MinInt32)},
		{"int-max", "int", "2147483647", int32Encoder(math.MaxInt32)},
		{"uint-max", "uint", "4294967295", uint32Encoder(math.MaxUint32)},
		{"bool-true", "boolean", true, uint32Encoder(0x997275B5)},
		{"bool-false", "boolean", false, uint32Encoder(0xBC799737)},
		{"double-pi", "double", math.Pi, float64Encoder(math.Pi)},
		{"null", "null", nil, uint32Encoder(0x56730BCC)},
		{"bytes-empty", "bytes", "", bytesEncoder(nil)},
		{"bytes-253", "bytes", "01…ff", bytesEncoder(bytes253)},
		{"bytes-254", "bytes", "01…ff", bytesEncoder(bytes254)},
		{"string-utf8", "string", "mtcute 🐈", bytesEncoder([]byte("mtcute 🐈"))},
		{"int128", "int128", "00…0f", rawEncoder(sequence(16))},
		{"int256", "int256", "00…1f", rawEncoder(sequence(32))},
		{
			"vector-int-empty",
			"vector-int",
			[]int32{},
			vectorIntEncoder(nil, true),
		},
		{
			"vector-int-three",
			"vector-int",
			[]int32{math.MinInt32, 0, math.MaxInt32},
			vectorIntEncoder([]int32{math.MinInt32, 0, math.MaxInt32}, true),
		},
		{
			"bare-vector-int",
			"bare-vector-int",
			[]int32{1, -2},
			vectorIntEncoder([]int32{1, -2}, false),
		},
	}

	fixtures := make([]fixture, 0, len(cases))
	for _, tc := range cases {
		var buf bytes.Buffer
		if err := tc.encode(&buf); err != nil {
			return nil, fmt.Errorf("%s: %w", tc.name, err)
		}
		fixtures = append(fixtures, fixture{
			Name:      tc.name,
			Operation: tc.operation,
			Input:     tc.input,
			Hex:       hex.EncodeToString(buf.Bytes()),
		})
	}
	return fixtures, nil
}

func int32Encoder(value int32) func(*bytes.Buffer) error {
	return func(buf *bytes.Buffer) error {
		return binary.Write(buf, binary.LittleEndian, value)
	}
}

func uint32Encoder(value uint32) func(*bytes.Buffer) error {
	return func(buf *bytes.Buffer) error {
		return binary.Write(buf, binary.LittleEndian, value)
	}
}

func float64Encoder(value float64) func(*bytes.Buffer) error {
	return func(buf *bytes.Buffer) error {
		return binary.Write(buf, binary.LittleEndian, value)
	}
}

func rawEncoder(value []byte) func(*bytes.Buffer) error {
	return func(buf *bytes.Buffer) error {
		_, err := buf.Write(value)
		return err
	}
}

func bytesEncoder(value []byte) func(*bytes.Buffer) error {
	return func(buf *bytes.Buffer) error {
		length := len(value)
		switch {
		case length <= 253:
			if err := buf.WriteByte(byte(length)); err != nil {
				return err
			}
		case length <= 0xFFFFFF:
			if _, err := buf.Write([]byte{
				254,
				byte(length),
				byte(length >> 8),
				byte(length >> 16),
			}); err != nil {
				return err
			}
		default:
			return fmt.Errorf("length %d exceeds TL bytes limit", length)
		}

		if _, err := buf.Write(value); err != nil {
			return err
		}
		for buf.Len()%4 != 0 {
			if err := buf.WriteByte(0); err != nil {
				return err
			}
		}
		return nil
	}
}

func vectorIntEncoder(values []int32, boxed bool) func(*bytes.Buffer) error {
	return func(buf *bytes.Buffer) error {
		if boxed {
			if err := binary.Write(
				buf,
				binary.LittleEndian,
				uint32(0x1cb5c415),
			); err != nil {
				return err
			}
		}
		if err := binary.Write(buf, binary.LittleEndian, int32(len(values))); err != nil {
			return err
		}
		for _, value := range values {
			if err := binary.Write(buf, binary.LittleEndian, value); err != nil {
				return err
			}
		}
		return nil
	}
}

func sequence(size int) []byte {
	result := make([]byte, size)
	for i := range result {
		result[i] = byte(i)
	}
	return result
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
