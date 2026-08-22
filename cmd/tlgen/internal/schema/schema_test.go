package schema

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPinnedAPI(t *testing.T) {
	t.Parallel()

	loaded, err := LoadAPI(projectPath("schema", "api-schema.json"))
	if err != nil {
		t.Fatalf("LoadAPI: %v", err)
	}
	if loaded.Layer != 229 {
		t.Fatalf("layer = %d, want 229", loaded.Layer)
	}
	if len(loaded.Entries) != 2471 {
		t.Fatalf("entries = %d, want 2471", len(loaded.Entries))
	}
	if len(loaded.Classes) != 1657 {
		t.Fatalf("classes = %d, want 1657", len(loaded.Classes))
	}
	if len(loaded.Methods) != 814 {
		t.Fatalf("methods = %d, want 814", len(loaded.Methods))
	}
	if len(loaded.Unions) != 613 {
		t.Fatalf("unions = %d, want 613", len(loaded.Unions))
	}

	user := loaded.Unions["User"]
	if user == nil {
		t.Fatal("User union is missing")
	}
	if len(user.Classes) != 2 {
		t.Fatalf("User classes = %d, want 2", len(user.Classes))
	}
	if loaded.Methods["messages.getHistory"] == nil {
		t.Fatal("messages.getHistory method is missing")
	}
}

func TestLoadPinnedMTP(t *testing.T) {
	t.Parallel()

	loaded, err := LoadMTP(projectPath("schema", "mtp-schema.json"))
	if err != nil {
		t.Fatalf("LoadMTP: %v", err)
	}
	if loaded.Layer != 0 {
		t.Fatalf("layer = %d, want 0", loaded.Layer)
	}
	if len(loaded.Classes) != 45 {
		t.Fatalf("classes = %d, want 45", len(loaded.Classes))
	}
	if len(loaded.Methods) != 0 {
		t.Fatalf("methods = %d, want 0", len(loaded.Methods))
	}
}

func TestLoadAPIRejectsInvalidSchema(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"duplicate ID": `{
			"l": 1,
			"u": {},
			"e": [
				{"kind":"class","name":"one","id":1,"type":"One","arguments":[]},
				{"kind":"class","name":"two","id":1,"type":"Two","arguments":[]}
			]
		}`,
		"missing flags": `{
			"l": 1,
			"u": {},
			"e": [{
				"kind":"class",
				"name":"one",
				"id":1,
				"type":"One",
				"arguments":[{
					"name":"value",
					"type":"int",
					"typeModifiers":{"predicate":"flags.0"}
				}]
			}]
		}`,
		"invalid predicate": `{
			"l": 1,
			"u": {},
			"e": [{
				"kind":"class",
				"name":"one",
				"id":1,
				"type":"One",
				"arguments":[
					{"name":"flags","type":"#"},
					{
						"name":"value",
						"type":"int",
						"typeModifiers":{"predicate":"flags.32"}
					}
				]
			}]
		}`,
	}

	for name, input := range tests {
		name, input := name, input
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "schema.json")
			if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
				t.Fatalf("write schema: %v", err)
			}
			if _, err := LoadAPI(path); err == nil {
				t.Fatal("LoadAPI succeeded, want error")
			}
		})
	}
}

func TestLoadAPIRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "schema.json")
	if err := os.WriteFile(path, []byte(`{"l":`), 0o600); err != nil {
		t.Fatalf("write schema: %v", err)
	}
	_, err := LoadAPI(path)
	if err == nil || !strings.Contains(err.Error(), "decode API schema") {
		t.Fatalf("LoadAPI error = %v, want decode error", err)
	}
}

func projectPath(parts ...string) string {
	all := append([]string{"..", "..", "..", ".."}, parts...)
	return filepath.Join(all...)
}
