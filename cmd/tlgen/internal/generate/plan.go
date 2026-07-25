// Package generate plans and emits deterministic Go source from TL schemas.
package generate

import (
	"cmp"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/mtgo-labs/raw/cmd/tlgen/internal/naming"
	"github.com/mtgo-labs/raw/cmd/tlgen/internal/schema"
	"github.com/mtgo-labs/raw/cmd/tlgen/internal/types"
)

// File describes one generated Go file and its schema ownership.
type File struct {
	Path      string
	Flavor    naming.Flavor
	Namespace string
	Entries   []*schema.Entry
	Unions    []*schema.Union
}

// Plan is the complete, stably ordered generated-file inventory.
type Plan struct {
	Files []*File
}

type fileKey struct {
	flavor    naming.Flavor
	namespace string
}

// BuildPlan validates both schemas and assigns every entry and union to one
// deterministic output file.
func BuildPlan(api, mtp *schema.Schema) (*Plan, error) {
	if api == nil || mtp == nil {
		return nil, fmt.Errorf("nil API or MTProto schema")
	}
	if err := naming.Audit(api, mtp); err != nil {
		return nil, fmt.Errorf("audit names: %w", err)
	}
	if err := auditTypes(api, naming.API); err != nil {
		return nil, err
	}
	if err := auditTypes(mtp, naming.MTP); err != nil {
		return nil, err
	}

	files := make(map[fileKey]*File)
	if err := assignSchema(files, api, naming.API); err != nil {
		return nil, err
	}
	if err := assignSchema(files, mtp, naming.MTP); err != nil {
		return nil, err
	}

	plan := &Plan{Files: make([]*File, 0, len(files))}
	for _, file := range files {
		sortFile(file)
		plan.Files = append(plan.Files, file)
	}
	slices.SortFunc(plan.Files, func(left, right *File) int {
		if order := cmp.Compare(left.Path, right.Path); order != 0 {
			return order
		}
		if order := cmp.Compare(left.Flavor, right.Flavor); order != 0 {
			return order
		}
		return cmp.Compare(left.Namespace, right.Namespace)
	})
	for index := 1; index < len(plan.Files); index++ {
		previous := plan.Files[index-1]
		current := plan.Files[index]
		if previous.Path == current.Path {
			return nil, fmt.Errorf(
				"namespaces %q and %q both map to %q",
				previous.Namespace,
				current.Namespace,
				current.Path,
			)
		}
	}
	return plan, nil
}

func auditTypes(value *schema.Schema, flavor naming.Flavor) error {
	resolver, err := types.NewResolver(value, flavor)
	if err != nil {
		return fmt.Errorf("build type resolver: %w", err)
	}
	if err := resolver.Audit(); err != nil {
		return fmt.Errorf("audit types: %w", err)
	}
	return nil
}

func assignSchema(
	files map[fileKey]*File,
	value *schema.Schema,
	flavor naming.Flavor,
) error {
	for i := range value.Entries {
		entry := &value.Entries[i]
		namespace, err := namespaceOf(entry.Name)
		if err != nil {
			return fmt.Errorf("entry %q: %w", entry.Name, err)
		}
		file, err := getFile(files, flavor, namespace)
		if err != nil {
			return err
		}
		file.Entries = append(file.Entries, entry)
	}
	for name, union := range value.Unions {
		namespace, err := namespaceOf(name)
		if err != nil {
			return fmt.Errorf("union %q: %w", name, err)
		}
		file, err := getFile(files, flavor, namespace)
		if err != nil {
			return err
		}
		file.Unions = append(file.Unions, union)
	}
	return nil
}

func getFile(
	files map[fileKey]*File,
	flavor naming.Flavor,
	namespace string,
) (*File, error) {
	key := fileKey{flavor: flavor, namespace: namespace}
	if file := files[key]; file != nil {
		return file, nil
	}
	path, err := outputPath(flavor, namespace)
	if err != nil {
		return nil, err
	}
	file := &File{
		Path:      path,
		Flavor:    flavor,
		Namespace: namespace,
	}
	files[key] = file
	return file, nil
}

func outputPath(flavor naming.Flavor, namespace string) (string, error) {
	var stem string
	switch flavor {
	case naming.API:
		stem = "api"
		if namespace == naming.SyntheticSchemaNamespace {
			namespace = "synthetic"
		}
	case naming.MTP:
		stem = "mtp"
	default:
		return "", fmt.Errorf("unknown naming flavor %d", flavor)
	}
	if namespace != "" {
		stem += "_" + strings.ReplaceAll(namespace, ".", "_")
	}
	return path.Join("tl", stem+".go"), nil
}

func namespaceOf(name string) (string, error) {
	index := strings.LastIndexByte(name, '.')
	if index < 0 {
		return "", nil
	}
	namespace := name[:index]
	if namespace == "" || index == len(name)-1 {
		return "", fmt.Errorf("invalid qualified name")
	}
	for _, current := range namespace {
		if current == '.' || current == '_' ||
			current >= 'a' && current <= 'z' ||
			current >= '0' && current <= '9' {
			continue
		}
		return "", fmt.Errorf("namespace %q contains unsupported character %q", namespace, current)
	}
	return namespace, nil
}

func sortFile(file *File) {
	slices.SortFunc(file.Entries, func(left, right *schema.Entry) int {
		if order := cmp.Compare(left.ID, right.ID); order != 0 {
			return order
		}
		return cmp.Compare(left.Name, right.Name)
	})
	slices.SortFunc(file.Unions, func(left, right *schema.Union) int {
		return cmp.Compare(left.Name, right.Name)
	})
}
