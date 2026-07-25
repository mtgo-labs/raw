// Command tlgen generates raw Go TL declarations from the pinned mtcute schema.
package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mtgo-labs/raw/cmd/tlgen/internal/generate"
	"github.com/mtgo-labs/raw/cmd/tlgen/internal/schema"
)

type upstreamMetadata struct {
	commit           string
	apiLayer         int
	apiConstructors  int
	apiMethods       int
	apiUnions        int
	apiUnionComments int
	mtpConstructors  int
}

func main() {
	root := flag.String("root", ".", "module root containing schema and tl directories")
	flag.Parse()

	if err := run(*root); err != nil {
		fmt.Fprintf(os.Stderr, "tlgen: %v\n", err)
		os.Exit(1)
	}
}

func run(root string) error {
	metadata, err := readUpstream(filepath.Join(root, "schema", "UPSTREAM"))
	if err != nil {
		return err
	}
	api, err := schema.LoadAPI(filepath.Join(root, "schema", "api-schema.json"))
	if err != nil {
		return err
	}
	mtp, err := schema.LoadMTP(filepath.Join(root, "schema", "mtp-schema.json"))
	if err != nil {
		return err
	}
	if err := verifyInventory(metadata, api, mtp); err != nil {
		return err
	}
	plan, err := generate.BuildPlan(api, mtp)
	if err != nil {
		return fmt.Errorf("build generation plan: %w", err)
	}
	outputs, err := generate.Render(plan, api, mtp, generate.Metadata{
		Commit: metadata.commit,
		Layer:  metadata.apiLayer,
	})
	if err != nil {
		return fmt.Errorf("render generated source: %w", err)
	}
	if err := generate.Write(root, outputs); err != nil {
		return fmt.Errorf("write generated source: %w", err)
	}
	return nil
}

func readUpstream(path string) (upstreamMetadata, error) {
	file, err := os.Open(path)
	if err != nil {
		return upstreamMetadata{}, fmt.Errorf("open upstream metadata: %w", err)
	}
	defer file.Close()

	values := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" || value == "" {
			return upstreamMetadata{}, fmt.Errorf("invalid upstream metadata line %q", line)
		}
		if _, exists := values[key]; exists {
			return upstreamMetadata{}, fmt.Errorf("duplicate upstream metadata key %q", key)
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return upstreamMetadata{}, fmt.Errorf("read upstream metadata: %w", err)
	}

	commit := values["commit"]
	if len(commit) != 40 {
		return upstreamMetadata{}, fmt.Errorf("invalid upstream commit %q", commit)
	}
	if _, err := hex.DecodeString(commit); err != nil {
		return upstreamMetadata{}, fmt.Errorf("invalid upstream commit %q", commit)
	}
	result := upstreamMetadata{commit: commit}
	required := []struct {
		key    string
		target *int
	}{
		{"api_layer", &result.apiLayer},
		{"api_constructors", &result.apiConstructors},
		{"api_methods", &result.apiMethods},
		{"api_unions", &result.apiUnions},
		{"api_union_comments", &result.apiUnionComments},
		{"mtp_constructors", &result.mtpConstructors},
	}
	for _, item := range required {
		value, err := strconv.Atoi(values[item.key])
		if err != nil || value <= 0 {
			return upstreamMetadata{}, fmt.Errorf(
				"invalid upstream metadata %s=%q",
				item.key,
				values[item.key],
			)
		}
		*item.target = value
	}
	return result, nil
}

func verifyInventory(
	metadata upstreamMetadata,
	api, mtp *schema.Schema,
) error {
	if api.Layer != metadata.apiLayer {
		return fmt.Errorf(
			"API layer = %d, metadata requires %d",
			api.Layer,
			metadata.apiLayer,
		)
	}
	unionComments := 0
	for _, union := range api.Unions {
		if union.Comment != "" {
			unionComments++
		}
	}
	checks := []struct {
		name string
		got  int
		want int
	}{
		{"API constructors", len(api.Classes), metadata.apiConstructors},
		{"API methods", len(api.Methods), metadata.apiMethods},
		{"API unions", len(api.Unions), metadata.apiUnions},
		{"API union comments", unionComments, metadata.apiUnionComments},
		{"MTProto constructors", len(mtp.Classes), metadata.mtpConstructors},
	}
	for _, check := range checks {
		if check.got != check.want {
			return fmt.Errorf("%s = %d, metadata requires %d", check.name, check.got, check.want)
		}
	}
	return nil
}
