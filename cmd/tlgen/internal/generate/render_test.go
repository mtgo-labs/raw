package generate

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"
)

const pinnedCommit = "2af1d0d5564a2a5b231c055cda53a7eb19a401eb"

func TestRenderPinnedSchemas(t *testing.T) {
	t.Parallel()

	api, mtp := loadSchemas(t)
	plan, err := BuildPlan(api, mtp)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	outputs, err := Render(plan, api, mtp, Metadata{
		Commit: pinnedCommit,
		Layer:  api.Layer,
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if len(outputs) != 30 {
		t.Fatalf("outputs = %d, want 30", len(outputs))
	}

	var typeCount, constCount, functionCount int
	files := token.NewFileSet()
	for _, output := range outputs {
		if bytes.Contains(output.Data, []byte("}\nfunc ")) {
			t.Errorf("%q contains adjacent top-level functions", output.Path)
		}
		parsed, err := parser.ParseFile(
			files,
			output.Path,
			output.Data,
			parser.ParseComments,
		)
		if err != nil {
			t.Fatalf("parse %q: %v", output.Path, err)
		}
		for _, declaration := range parsed.Decls {
			switch declaration := declaration.(type) {
			case *ast.GenDecl:
				switch declaration.Tok {
				case token.TYPE:
					typeCount += len(declaration.Specs)
				case token.CONST:
					constCount += len(declaration.Specs)
				}
			case *ast.FuncDecl:
				functionCount++
			}
		}
	}
	if typeCount != 3128 {
		t.Fatalf("generated types = %d, want 3128", typeCount)
	}
	if constCount != 2498 {
		t.Fatalf("generated constants = %d, want 2498", constCount)
	}
	if functionCount != 19803 {
		t.Fatalf("generated functions = %d, want 19803", functionCount)
	}

	assertOutputContains(t, outputs, "tl/api.go", []string{
		"const Layer = 228",
		"type UserClass interface",
		"type InvokeAfterMessageRequest[X any] struct",
		"Query Request[X]",
		"requestResult(X)",
		"func (value *InvokeAfterMessageRequest[X]) encodedSize() (int, error)",
		"func (value *InvokeAfterMessageRequest[X]) encode(output encoder) (encoder, error)",
		"func (value *InvokeAfterMessageRequest[X]) decodeResult(state decoder) (X, decoder, error)",
		"func decodeObject(input *decoder) (Object, error)",
	})
	assertOutputContains(t, outputs, "tl/api_messages.go", []string{
		"type MessagesGetHistoryRequest struct",
		"requestResult(MessagesMessagesClass)",
	})
	assertOutputContains(t, outputs, "tl/api_synthetic.go", []string{
		"type SyntheticDummyUpdate struct",
		"const SyntheticDummyUpdateConstructorID uint32 = 0x24a6b90e",
		"type SyntheticCustomMethodRequest struct",
		"TL method mtcute.customMethod",
	})
	assertOutputContains(t, outputs, "tl/mtp.go", []string{
		"type MTPFutureSalt struct",
		"type MTPFutureSalts struct",
		"Salts",
		"[]MTPFutureSalt",
		"func (value *MTPFutureSalts) encodeBody(output encoder) (encoder, error)",
		"func (value *MTPFutureSalts) decodeBody(input *decoder) error",
		"output.putBareVectorHeader(len(value.Messages))",
		"_field1, err := input.readObject()",
	})
}

func TestRenderIsDeterministic(t *testing.T) {
	t.Parallel()

	api, mtp := loadSchemas(t)
	plan, err := BuildPlan(api, mtp)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	metadata := Metadata{Commit: pinnedCommit, Layer: api.Layer}
	first, err := Render(plan, api, mtp, metadata)
	if err != nil {
		t.Fatalf("first Render: %v", err)
	}
	second, err := Render(plan, api, mtp, metadata)
	if err != nil {
		t.Fatalf("second Render: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("identical generation plans produced different source")
	}
}

func TestRenderRejectsMetadataLayerMismatch(t *testing.T) {
	t.Parallel()

	api, mtp := loadSchemas(t)
	plan, err := BuildPlan(api, mtp)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	_, err = Render(plan, api, mtp, Metadata{
		Commit: pinnedCommit,
		Layer:  api.Layer - 1,
	})
	if err == nil {
		t.Fatal("Render succeeded with mismatched layer")
	}
}

func assertOutputContains(
	t *testing.T,
	outputs []Output,
	path string,
	values []string,
) {
	t.Helper()

	for _, output := range outputs {
		if output.Path != path {
			continue
		}
		for _, value := range values {
			if !bytes.Contains(output.Data, []byte(value)) {
				t.Errorf("%q does not contain %q", path, value)
			}
		}
		return
	}
	t.Errorf("output %q is missing", path)
}
