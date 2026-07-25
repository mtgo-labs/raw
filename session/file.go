package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var (
	ErrSessionNotFound = os.ErrNotExist
	ErrSessionCorrupt  = errors.New("session: corrupt snapshot")
)

// FileStore persists one session snapshot using a temporary sibling file and
// an atomic rename. The destination is never truncated before a successful
// replacement is ready.
type FileStore struct {
	path string
}

func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, errors.New("session: empty file path")
	}
	return &FileStore{path: path}, nil
}

func (store *FileStore) Load(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.Open(store.path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("session: read %q: %w", store.path, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty file", ErrSessionCorrupt)
	}
	return data, nil
}

func (store *FileStore) Save(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("%w: empty snapshot", ErrSessionCorrupt)
	}
	dir := filepath.Dir(store.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("session: create directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".session-*")
	if err != nil {
		return fmt.Errorf("session: create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("session: set permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("session: write temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("session: sync temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("session: close temporary file: %w", err)
	}
	if err := os.Rename(tmpName, store.path); err != nil {
		return fmt.Errorf("session: replace %q: %w", store.path, err)
	}
	if directory, err := os.Open(dir); err == nil {
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil {
			return fmt.Errorf("session: sync directory: %w", syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("session: close directory: %w", closeErr)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("session: open directory: %w", err)
	}
	return nil
}
