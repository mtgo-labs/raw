package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtgo-labs/raw/cmd/tlgen/internal/schema"
)

func TestPinnedUpstreamMetadataAndInventory(t *testing.T) {
	t.Parallel()

	root := projectPath()
	metadata, err := readUpstream(filepath.Join(root, "schema", "UPSTREAM"))
	if err != nil {
		t.Fatalf("readUpstream: %v", err)
	}
	if metadata.commit != "2af1d0d5564a2a5b231c055cda53a7eb19a401eb" {
		t.Fatalf("commit = %q", metadata.commit)
	}
	api, err := schema.LoadAPI(filepath.Join(root, "schema", "api-schema.json"))
	if err != nil {
		t.Fatalf("LoadAPI: %v", err)
	}
	mtp, err := schema.LoadMTP(filepath.Join(root, "schema", "mtp-schema.json"))
	if err != nil {
		t.Fatalf("LoadMTP: %v", err)
	}
	if err := verifyInventory(metadata, api, mtp); err != nil {
		t.Fatalf("verifyInventory: %v", err)
	}
}

func TestReadUpstreamRejectsDuplicateKey(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "UPSTREAM")
	data := "commit=0000000000000000000000000000000000000000\ncommit=duplicate\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := readUpstream(path)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("readUpstream error = %v, want duplicate key", err)
	}
}

func projectPath(parts ...string) string {
	all := append([]string{"..", ".."}, parts...)
	return filepath.Join(all...)
}
