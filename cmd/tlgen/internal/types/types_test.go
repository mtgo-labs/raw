package types

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtgo-labs/raw/cmd/tlgen/internal/naming"
	"github.com/mtgo-labs/raw/cmd/tlgen/internal/schema"
)

func TestPrimitiveGoTypes(t *testing.T) {
	t.Parallel()

	tests := map[Primitive]string{
		Int:    "int32",
		Long:   "int64",
		Int53:  "int64",
		Int128: "[16]byte",
		Int256: "[32]byte",
		Double: "float64",
		String: "string",
		Bytes:  "[]byte",
		Bool:   "bool",
		Flag:   "bool",
	}
	for primitive, want := range tests {
		got, err := (Type{Kind: PrimitiveKind, Primitive: primitive}).GoType()
		if err != nil {
			t.Fatalf("GoType(%d): %v", primitive, err)
		}
		if got != want {
			t.Fatalf("GoType(%d) = %q, want %q", primitive, got, want)
		}
	}
}

func TestResolvePinnedAPI(t *testing.T) {
	t.Parallel()

	loaded := loadAPI(t)
	resolver := newResolver(t, loaded, naming.API)

	tests := []struct {
		method string
		field  string
		want   Type
		goType string
	}{
		{
			method: "messages.getHistory",
			want: Type{
				Kind:   UnionKind,
				TLName: "messages.Messages",
				GoName: "MessagesMessagesClass",
			},
			goType: "MessagesMessagesClass",
		},
		{
			method: "messages.getOutboxReadDate",
			want: Type{
				Kind:          ConstructorKind,
				TLName:        "outboxReadDate",
				GoName:        "OutboxReadDate",
				Pointer:       true,
				ConstructorID: 1001931436,
			},
			goType: "*OutboxReadDate",
		},
		{
			method: "messages.getMessageReadParticipants",
			want: Type{
				Kind:          ConstructorKind,
				TLName:        "readParticipantDate",
				GoName:        "ReadParticipantDate",
				Vector:        BoxedVector,
				ConstructorID: 1246753138,
			},
			goType: "[]ReadParticipantDate",
		},
		{
			method: "invokeAfterMsg",
			want: Type{
				Kind:   GenericKind,
				TLName: "X",
				GoName: "X",
			},
			goType: "X",
		},
		{
			method: "invokeAfterMsg",
			field:  "query",
			want: Type{
				Kind:         GenericKind,
				TLName:       "X",
				GoName:       "X",
				GenericQuery: true,
			},
			goType: "Request[X]",
		},
	}

	for _, test := range tests {
		t.Run(test.method+"/"+test.field, func(t *testing.T) {
			t.Parallel()

			entry := loaded.Methods[test.method]
			if entry == nil {
				t.Fatalf("method %q is missing", test.method)
			}
			var (
				got Type
				err error
			)
			if test.field == "" {
				got, err = resolver.Result(entry)
			} else {
				got, err = resolver.Argument(entry, findArgument(t, entry, test.field))
			}
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if got != test.want {
				t.Fatalf("resolved type = %+v, want %+v", got, test.want)
			}
			goType, err := got.GoType()
			if err != nil {
				t.Fatalf("GoType: %v", err)
			}
			if goType != test.goType {
				t.Fatalf("GoType = %q, want %q", goType, test.goType)
			}
		})
	}
}

func TestResolvePinnedMTPBareVector(t *testing.T) {
	t.Parallel()

	loaded, err := schema.LoadMTP(projectPath("schema", "mtp-schema.json"))
	if err != nil {
		t.Fatalf("LoadMTP: %v", err)
	}
	resolver := newResolver(t, loaded, naming.MTP)
	entry := loaded.Classes["mt_future_salts"]
	if entry == nil {
		t.Fatal("mt_future_salts is missing")
	}

	got, err := resolver.Argument(entry, findArgument(t, entry, "salts"))
	if err != nil {
		t.Fatalf("Argument: %v", err)
	}
	want := Type{
		Kind:          ConstructorKind,
		TLName:        "mt_future_salt",
		GoName:        "MTPFutureSalt",
		Vector:        BareVector,
		Bare:          true,
		ConstructorID: 155834844,
	}
	if got != want {
		t.Fatalf("resolved type = %+v, want %+v", got, want)
	}
	goType, err := got.GoType()
	if err != nil {
		t.Fatalf("GoType: %v", err)
	}
	if goType != "[]MTPFutureSalt" {
		t.Fatalf("GoType = %q, want []MTPFutureSalt", goType)
	}
}

func TestResolveOptionalAPIArguments(t *testing.T) {
	t.Parallel()

	loaded := loadAPI(t)
	resolver := newResolver(t, loaded, naming.API)
	entry := loaded.Methods["messages.sendMessage"]
	if entry == nil {
		t.Fatal("messages.sendMessage is missing")
	}

	tests := []struct {
		field  string
		want   Type
		goType string
	}{
		{
			field: "no_webpage",
			want: Type{
				Kind:      PrimitiveKind,
				Primitive: Flag,
				TLName:    "true",
				Optional:  true,
			},
			goType: "bool",
		},
		{
			field: "reply_to",
			want: Type{
				Kind:     UnionKind,
				TLName:   "InputReplyTo",
				GoName:   "InputReplyToClass",
				Optional: true,
			},
			goType: "InputReplyToClass",
		},
		{
			field: "entities",
			want: Type{
				Kind:     UnionKind,
				TLName:   "MessageEntity",
				GoName:   "MessageEntityClass",
				Vector:   BoxedVector,
				Optional: true,
			},
			goType: "[]MessageEntityClass",
		},
		{
			field: "schedule_date",
			want: Type{
				Kind:      PrimitiveKind,
				Primitive: Int,
				TLName:    "int",
				Optional:  true,
				Pointer:   true,
			},
			goType: "*int32",
		},
	}

	for _, test := range tests {
		t.Run(test.field, func(t *testing.T) {
			t.Parallel()

			got, err := resolver.Argument(entry, findArgument(t, entry, test.field))
			if err != nil {
				t.Fatalf("Argument: %v", err)
			}
			if got != test.want {
				t.Fatalf("resolved type = %+v, want %+v", got, test.want)
			}
			goType, err := got.GoType()
			if err != nil {
				t.Fatalf("GoType: %v", err)
			}
			if goType != test.goType {
				t.Fatalf("GoType = %q, want %q", goType, test.goType)
			}
		})
	}
}

func TestResolveOptionalPrimitiveVector(t *testing.T) {
	t.Parallel()

	loaded := loadAPI(t)
	resolver := newResolver(t, loaded, naming.API)
	entry := loaded.Classes["invoice"]
	if entry == nil {
		t.Fatal("invoice is missing")
	}

	got, err := resolver.Argument(
		entry,
		findArgument(t, entry, "suggested_tip_amounts"),
	)
	if err != nil {
		t.Fatalf("Argument: %v", err)
	}
	want := Type{
		Kind:      PrimitiveKind,
		Primitive: Long,
		TLName:    "long",
		Vector:    BoxedVector,
		Optional:  true,
	}
	if got != want {
		t.Fatalf("resolved type = %+v, want %+v", got, want)
	}
	goType, err := got.GoType()
	if err != nil {
		t.Fatalf("GoType: %v", err)
	}
	if goType != "[]int64" {
		t.Fatalf("GoType = %q, want []int64", goType)
	}
}

func TestAuditPinnedTypeShapes(t *testing.T) {
	t.Parallel()

	api := loadAPI(t)
	apiResolver := newResolver(t, api, naming.API)
	if err := apiResolver.Audit(); err != nil {
		t.Fatalf("audit API: %v", err)
	}

	mtp, err := schema.LoadMTP(projectPath("schema", "mtp-schema.json"))
	if err != nil {
		t.Fatalf("LoadMTP: %v", err)
	}
	mtpResolver := newResolver(t, mtp, naming.MTP)
	if err := mtpResolver.Audit(); err != nil {
		t.Fatalf("audit MTP: %v", err)
	}
}

func TestRejectsUnknownType(t *testing.T) {
	t.Parallel()

	entry := &schema.Entry{
		Kind: schema.KindMethod,
		Name: "test.call",
		Type: "Missing",
	}
	resolver := newResolver(t, &schema.Schema{
		Entries: []schema.Entry{*entry},
		Classes: map[string]*schema.Entry{},
		Methods: map[string]*schema.Entry{"test.call": entry},
		Unions:  map[string]*schema.Union{},
	}, naming.API)
	_, err := resolver.Result(&resolver.schema.Entries[0])
	if err == nil || !strings.Contains(err.Error(), "unknown TL type") {
		t.Fatalf("Result error = %v, want unknown type", err)
	}
}

func TestRejectsMismatchedConstructor(t *testing.T) {
	t.Parallel()

	constructorID := uint32(1)
	entries := []schema.Entry{
		{Kind: schema.KindClass, Name: "value", Type: "Value", ID: constructorID},
		{
			Kind:          schema.KindMethod,
			Name:          "test.call",
			Type:          "Other",
			TypeModifiers: &schema.Modifiers{Constructor: &constructorID},
			ID:            2,
		},
	}
	value := &schema.Schema{
		Entries: entries,
		Classes: map[string]*schema.Entry{"value": &entries[0]},
		Methods: map[string]*schema.Entry{"test.call": &entries[1]},
		Unions: map[string]*schema.Union{
			"Value": {Name: "Value", Classes: []*schema.Entry{&entries[0]}},
		},
	}
	resolver := newResolver(t, value, naming.API)
	_, err := resolver.Result(&resolver.schema.Entries[1])
	if err == nil || !strings.Contains(err.Error(), "references constructor") {
		t.Fatalf("Result error = %v, want constructor mismatch", err)
	}
}

func loadAPI(t *testing.T) *schema.Schema {
	t.Helper()

	loaded, err := schema.LoadAPI(projectPath("schema", "api-schema.json"))
	if err != nil {
		t.Fatalf("LoadAPI: %v", err)
	}
	return loaded
}

func newResolver(
	t *testing.T,
	value *schema.Schema,
	flavor naming.Flavor,
) *Resolver {
	t.Helper()

	resolver, err := NewResolver(value, flavor)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return resolver
}

func findArgument(t *testing.T, entry *schema.Entry, name string) *schema.Argument {
	t.Helper()

	for i := range entry.Arguments {
		if entry.Arguments[i].Name == name {
			return &entry.Arguments[i]
		}
	}
	t.Fatalf("entry %q argument %q is missing", entry.Name, name)
	return nil
}

func projectPath(parts ...string) string {
	all := append([]string{"..", "..", "..", ".."}, parts...)
	return filepath.Join(all...)
}
