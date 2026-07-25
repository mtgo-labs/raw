package main

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestLoadKeys(t *testing.T) {
	records, err := loadKeys(filepath.Join("..", "..", "schema", "rsa-keys.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 10 || records[0].old || records[1].old || !records[2].old {
		t.Fatalf("unexpected key generations: len=%d firstOld=%v thirdOld=%v", len(records), records[0].old, records[2].old)
	}
	if records[0].fingerprint != 0xb25898df208d2603 ||
		records[1].fingerprint != 0xd09d1d85de64fd85 {
		t.Fatalf("fingerprints = [%016x %016x]", records[0].fingerprint, records[1].fingerprint)
	}
}

func TestRenderDeterministic(t *testing.T) {
	records, err := loadKeys(filepath.Join("..", "..", "schema", "rsa-keys.txt"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := render(records)
	if err != nil {
		t.Fatal(err)
	}
	second, err := render(records)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || !bytes.HasPrefix(first, []byte(generatedPrefix)) {
		t.Fatal("RSA registry rendering is not deterministic or missing generated marker")
	}
}
