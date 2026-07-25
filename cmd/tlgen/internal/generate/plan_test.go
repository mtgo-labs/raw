package generate

import (
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/mtgo-labs/raw/cmd/tlgen/internal/naming"
	"github.com/mtgo-labs/raw/cmd/tlgen/internal/schema"
)

func TestBuildPinnedPlan(t *testing.T) {
	t.Parallel()

	api, mtp := loadSchemas(t)
	plan, err := BuildPlan(api, mtp)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Files) != 29 {
		t.Fatalf("planned files = %d, want 29", len(plan.Files))
	}

	var entries, unions int
	paths := make(map[string]struct{}, len(plan.Files))
	for index, file := range plan.Files {
		if _, exists := paths[file.Path]; exists {
			t.Fatalf("duplicate output path %q", file.Path)
		}
		paths[file.Path] = struct{}{}
		if index > 0 && plan.Files[index-1].Path >= file.Path {
			t.Fatalf("files are not strictly ordered at %q", file.Path)
		}
		if !entriesOrdered(file.Entries) {
			t.Fatalf("%q entries are not ordered", file.Path)
		}
		if !slices.IsSortedFunc(file.Unions, func(left, right *schema.Union) int {
			return strings.Compare(left.Name, right.Name)
		}) {
			t.Fatalf("%q unions are not ordered", file.Path)
		}
		entries += len(file.Entries)
		unions += len(file.Unions)
	}

	if entries != len(api.Entries)+len(mtp.Entries) {
		t.Fatalf("planned entries = %d, want %d", entries, len(api.Entries)+len(mtp.Entries))
	}
	if entries != 2497 {
		t.Fatalf("planned entries = %d, want pinned inventory 2497", entries)
	}
	if unions != len(api.Unions)+len(mtp.Unions) {
		t.Fatalf("planned unions = %d, want %d", unions, len(api.Unions)+len(mtp.Unions))
	}
	if unions != 631 || len(mtp.Unions) != 26 {
		t.Fatalf("planned unions = %d (%d MTProto), want 631 (26 MTProto)", unions, len(mtp.Unions))
	}
	for _, path := range []string{
		"tl/api.go",
		"tl/api_account.go",
		"tl/api_messages.go",
		"tl/api_synthetic.go",
		"tl/mtp.go",
	} {
		if _, exists := paths[path]; !exists {
			t.Errorf("planned file %q is missing", path)
		}
	}
}

func TestBuildPinnedPlanKeepsSyntheticTLNamespace(t *testing.T) {
	t.Parallel()

	api, mtp := loadSchemas(t)
	plan, err := BuildPlan(api, mtp)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	for _, file := range plan.Files {
		if file.Path != "tl/api_synthetic.go" {
			continue
		}
		if file.Namespace != naming.SyntheticSchemaNamespace {
			t.Fatalf(
				"synthetic file namespace = %q, want %q",
				file.Namespace,
				naming.SyntheticSchemaNamespace,
			)
		}
		if len(file.Entries) != 4 {
			t.Fatalf("synthetic file entries = %d, want 4", len(file.Entries))
		}
		return
	}
	t.Fatal("synthetic output file is missing")
}

func TestBuildPlanIsDeterministic(t *testing.T) {
	t.Parallel()

	firstAPI, firstMTP := loadSchemas(t)
	first, err := BuildPlan(firstAPI, firstMTP)
	if err != nil {
		t.Fatalf("first BuildPlan: %v", err)
	}
	secondAPI, secondMTP := loadSchemas(t)
	second, err := BuildPlan(secondAPI, secondMTP)
	if err != nil {
		t.Fatalf("second BuildPlan: %v", err)
	}

	firstSnapshot := snapshot(first)
	secondSnapshot := snapshot(second)
	if !reflect.DeepEqual(firstSnapshot, secondSnapshot) {
		t.Fatal("separately loaded schemas produced different generation plans")
	}
}

func TestBuildPlanRejectsOutputCollision(t *testing.T) {
	t.Parallel()

	api := testSchema(
		schema.Entry{Kind: schema.KindClass, Name: "foo.bar.value", Type: "Value", ID: 1},
		schema.Entry{Kind: schema.KindClass, Name: "foo_bar.other", Type: "Value2", ID: 2},
	)
	_, err := BuildPlan(api, testSchema())
	if err == nil || !strings.Contains(err.Error(), "both map") {
		t.Fatalf("BuildPlan error = %v, want output collision", err)
	}
}

func TestBuildPlanRejectsInvalidNamespace(t *testing.T) {
	t.Parallel()

	api := testSchema(
		schema.Entry{Kind: schema.KindClass, Name: "Bad.value", Type: "Value", ID: 1},
	)
	_, err := BuildPlan(api, testSchema())
	if err == nil || !strings.Contains(err.Error(), "unsupported character") {
		t.Fatalf("BuildPlan error = %v, want invalid namespace", err)
	}
}

type fileSnapshot struct {
	Path      string
	Flavor    naming.Flavor
	Namespace string
	Entries   []string
	Unions    []string
}

func snapshot(plan *Plan) []fileSnapshot {
	result := make([]fileSnapshot, len(plan.Files))
	for index, file := range plan.Files {
		item := fileSnapshot{
			Path:      file.Path,
			Flavor:    file.Flavor,
			Namespace: file.Namespace,
			Entries:   make([]string, len(file.Entries)),
			Unions:    make([]string, len(file.Unions)),
		}
		for entryIndex, entry := range file.Entries {
			item.Entries[entryIndex] = fmt.Sprintf("%08x:%s", entry.ID, entry.Name)
		}
		for unionIndex, union := range file.Unions {
			item.Unions[unionIndex] = union.Name
		}
		result[index] = item
	}
	return result
}

func entriesOrdered(entries []*schema.Entry) bool {
	for index := 1; index < len(entries); index++ {
		previous := entries[index-1]
		current := entries[index]
		if previous.ID > current.ID ||
			previous.ID == current.ID && previous.Name >= current.Name {
			return false
		}
	}
	return true
}

func loadSchemas(t *testing.T) (*schema.Schema, *schema.Schema) {
	t.Helper()

	api, err := schema.LoadAPI(projectPath("schema", "api-schema.json"))
	if err != nil {
		t.Fatalf("LoadAPI: %v", err)
	}
	mtp, err := schema.LoadMTP(projectPath("schema", "mtp-schema.json"))
	if err != nil {
		t.Fatalf("LoadMTP: %v", err)
	}
	return api, mtp
}

func testSchema(entries ...schema.Entry) *schema.Schema {
	value := &schema.Schema{
		Entries: entries,
		Classes: make(map[string]*schema.Entry),
		Methods: make(map[string]*schema.Entry),
		Unions:  make(map[string]*schema.Union),
	}
	for index := range value.Entries {
		entry := &value.Entries[index]
		value.Classes[entry.Name] = entry
		union := value.Unions[entry.Type]
		if union == nil {
			union = &schema.Union{Name: entry.Type}
			value.Unions[entry.Type] = union
		}
		union.Classes = append(union.Classes, entry)
	}
	return value
}

func projectPath(parts ...string) string {
	all := append([]string{"..", "..", "..", ".."}, parts...)
	return filepath.Join(all...)
}
