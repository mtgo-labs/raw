package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMemoryStoreCopiesData(t *testing.T) {
	store := NewMemoryStore()
	input := []byte("state")
	if err := store.Save(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	input[0] = 'X'
	output, err := store.Load(context.Background())
	if err != nil || string(output) != "state" {
		t.Fatalf("output=%q err=%v", output, err)
	}
	output[0] = 'Y'
	output, err = store.Load(context.Background())
	if err != nil || string(output) != "state" {
		t.Fatalf("second output=%q err=%v", output, err)
	}
}

func TestStoresHonorCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := NewMemoryStore()
	if err := store.Save(ctx, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("memory save err=%v", err)
	}
	if _, err := store.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("memory load err=%v", err)
	}
}

func TestFileStoreAtomicSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "account.session")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), []byte("versioned-state")); err != nil {
		t.Fatal(err)
	}
	data, err := store.Load(context.Background())
	if err != nil || string(data) != "versioned-state" {
		t.Fatalf("data=%q err=%v", data, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permissions=%o", info.Mode().Perm())
	}
}

func TestFileStoreRejectsEmptySnapshot(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), nil); !errors.Is(err, ErrSessionCorrupt) {
		t.Fatalf("err=%v", err)
	}
}
