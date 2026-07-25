package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildPinnedCatalog(t *testing.T) {
	t.Parallel()

	source := loadPinnedErrors(t)
	value, err := buildCatalog(source)
	if err != nil {
		t.Fatalf("buildCatalog: %v", err)
	}
	if len(value.Codes) != 8 {
		t.Fatalf("code constants = %d, want 8", len(value.Codes))
	}
	if len(value.Errors) != 818 {
		t.Fatalf("error constants = %d, want 818", len(value.Errors))
	}
	if len(value.Patterns) != 29 {
		t.Fatalf("parameterized patterns = %d, want 29", len(value.Patterns))
	}

	rendered, err := render(value)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, expected := range [][]byte{
		[]byte(`ErrAPIIDInvalid`),
		[]byte(`ErrInterDCCallError`),
		[]byte(`ErrWebAppReqIDInvalid`),
		[]byte(`matchDecimalPattern(message, "FILE_REFERENCE_", "_EMPTY")`),
	} {
		if !bytes.Contains(rendered, expected) {
			t.Errorf("generated catalog does not contain %q", expected)
		}
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	t.Parallel()

	value, err := buildCatalog(loadPinnedErrors(t))
	if err != nil {
		t.Fatalf("buildCatalog: %v", err)
	}
	first, err := render(value)
	if err != nil {
		t.Fatalf("first render: %v", err)
	}
	second, err := render(value)
	if err != nil {
		t.Fatalf("second render: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("identical catalogs generated different source")
	}
}

func TestNormalizeErrorType(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"FLOOD_WAIT_%d":                          "FLOOD_WAIT",
		"FILE_REFERENCE_%d_EMPTY":                "FILE_REFERENCE_EMPTY",
		"PREVIOUS_CHAT_IMPORT_ACTIVE_WAIT_%dMIN": "PREVIOUS_CHAT_IMPORT_ACTIVE_WAIT_MIN",
		"Timedout":                               "Timedout",
	}
	for input, want := range tests {
		got, err := normalizeErrorType(input)
		if err != nil {
			t.Fatalf("normalizeErrorType(%q): %v", input, err)
		}
		if got != want {
			t.Errorf("normalizeErrorType(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestBuildCatalogRejectsGoNameCollision(t *testing.T) {
	t.Parallel()

	_, err := buildCatalog(rawErrors{
		Base: map[string]int{"BAD_REQUEST": 400},
		Errors: map[string]rawErrorDefinition{
			"WEB_VIEW_INVALID": {Code: 400, Name: "WEB_VIEW_INVALID"},
			"WEBVIEW_INVALID":  {Code: 400, Name: "WEBVIEW_INVALID"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "normalize") {
		t.Fatalf("buildCatalog error = %v, want normalized-name collision", err)
	}
}

func TestRunWritesGeneratedCatalog(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	schemaDirectory := filepath.Join(root, "schema")
	if err := os.MkdirAll(schemaDirectory, 0o755); err != nil {
		t.Fatalf("create schema directory: %v", err)
	}
	data, err := json.Marshal(rawErrors{
		Base: map[string]int{"BAD_REQUEST": 400},
		Errors: map[string]rawErrorDefinition{
			"FLOOD_WAIT_%d": {Code: 420, Name: "FLOOD_WAIT_%d"},
		},
	})
	if err != nil {
		t.Fatalf("marshal raw errors: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(schemaDirectory, "raw-errors.json"),
		data,
		0o644,
	); err != nil {
		t.Fatalf("write raw errors: %v", err)
	}
	if err := run(root); err != nil {
		t.Fatalf("run: %v", err)
	}
	output := filepath.Join(root, "tgerr", "errors_gen.go")
	first, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read generated catalog: %v", err)
	}
	if err := run(root); err != nil {
		t.Fatalf("second run: %v", err)
	}
	second, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read regenerated catalog: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("second run changed generated output")
	}
}

func loadPinnedErrors(t *testing.T) rawErrors {
	t.Helper()

	data, err := os.ReadFile(
		filepath.Join("..", "..", "schema", "raw-errors.json"),
	)
	if err != nil {
		t.Fatalf("read pinned raw errors: %v", err)
	}
	var source rawErrors
	if err := json.Unmarshal(data, &source); err != nil {
		t.Fatalf("decode pinned raw errors: %v", err)
	}
	return source
}
