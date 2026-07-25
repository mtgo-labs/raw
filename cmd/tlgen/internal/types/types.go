// Package types resolves TL schema types to deterministic Go representations.
package types

import (
	"fmt"
	"strings"

	"github.com/mtgo-labs/raw/cmd/tlgen/internal/naming"
	"github.com/mtgo-labs/raw/cmd/tlgen/internal/schema"
)

// Kind identifies the resolved category of a TL type.
type Kind uint8

const (
	PrimitiveKind Kind = iota + 1
	ConstructorKind
	UnionKind
	GenericKind
)

// Primitive identifies a TL primitive and its fixed Go representation.
type Primitive uint8

const (
	Int Primitive = iota + 1
	Long
	Int53
	Int128
	Int256
	Double
	String
	Bytes
	Bool
	Flag
)

// Vector identifies whether a value has boxed or bare TL vector framing.
type Vector uint8

const (
	NotVector Vector = iota
	BoxedVector
	BareVector
)

// Type is a fully resolved schema type ready for source generation.
type Type struct {
	Kind          Kind
	Primitive     Primitive
	TLName        string
	GoName        string
	Vector        Vector
	Optional      bool
	Bare          bool
	Pointer       bool
	GenericQuery  bool
	ConstructorID uint32
}

// GoType returns the generated Go type syntax.
func (value Type) GoType() (string, error) {
	var base string
	switch value.Kind {
	case PrimitiveKind:
		base = value.Primitive.goType()
		if base == "" {
			return "", fmt.Errorf("unknown primitive %d", value.Primitive)
		}
	case ConstructorKind, UnionKind:
		if value.GoName == "" {
			return "", fmt.Errorf("empty Go name for %q", value.TLName)
		}
		base = value.GoName
	case GenericKind:
		if value.GoName == "" {
			return "", fmt.Errorf("empty generic name")
		}
		base = value.GoName
		if value.GenericQuery {
			base = "Request[" + base + "]"
		}
	default:
		return "", fmt.Errorf("unknown type kind %d", value.Kind)
	}
	if value.Pointer {
		base = "*" + base
	}
	if value.Vector != NotVector {
		base = "[]" + base
	}
	return base, nil
}

func (value Primitive) goType() string {
	switch value {
	case Int:
		return "int32"
	case Long, Int53:
		return "int64"
	case Int128:
		return "[16]byte"
	case Int256:
		return "[32]byte"
	case Double:
		return "float64"
	case String:
		return "string"
	case Bytes:
		return "[]byte"
	case Bool, Flag:
		return "bool"
	default:
		return ""
	}
}

var primitives = map[string]Primitive{
	"int":    Int,
	"long":   Long,
	"int53":  Int53,
	"int128": Int128,
	"int256": Int256,
	"double": Double,
	"string": String,
	"bytes":  Bytes,
	"Bool":   Bool,
	"true":   Flag,
}

// Resolver resolves types against one validated API or MTProto schema.
type Resolver struct {
	schema       *schema.Schema
	flavor       naming.Flavor
	constructors map[uint32]*schema.Entry
}

// NewResolver builds the indexes needed for type resolution.
func NewResolver(value *schema.Schema, flavor naming.Flavor) (*Resolver, error) {
	if value == nil {
		return nil, fmt.Errorf("nil schema")
	}
	if flavor != naming.API && flavor != naming.MTP {
		return nil, fmt.Errorf("unknown naming flavor %d", flavor)
	}

	constructors := make(map[uint32]*schema.Entry, len(value.Classes))
	for i := range value.Entries {
		entry := &value.Entries[i]
		if entry.Kind != schema.KindClass {
			continue
		}
		if previous := constructors[entry.ID]; previous != nil {
			return nil, fmt.Errorf(
				"constructor ID %#08x is shared by %q and %q",
				entry.ID,
				previous.Name,
				entry.Name,
			)
		}
		constructors[entry.ID] = entry
	}
	return &Resolver{
		schema:       value,
		flavor:       flavor,
		constructors: constructors,
	}, nil
}

// Argument resolves one generated struct field.
func (resolver *Resolver) Argument(
	entry *schema.Entry,
	argument *schema.Argument,
) (Type, error) {
	if entry == nil || argument == nil {
		return Type{}, fmt.Errorf("nil entry or argument")
	}
	if argument.Type == "#" {
		return Type{}, fmt.Errorf("entry %q argument %q is a flags word", entry.Name, argument.Name)
	}
	value, err := resolver.resolve(
		entry,
		argument.Type,
		argument.TypeModifiers,
		false,
	)
	if err != nil {
		return Type{}, fmt.Errorf("entry %q argument %q: %w", entry.Name, argument.Name, err)
	}
	return value, nil
}

// Result resolves the compile-time result type of one RPC method.
func (resolver *Resolver) Result(entry *schema.Entry) (Type, error) {
	if entry == nil {
		return Type{}, fmt.Errorf("nil entry")
	}
	if entry.Kind != schema.KindMethod {
		return Type{}, fmt.Errorf("entry %q is not a method", entry.Name)
	}
	value, err := resolver.resolve(entry, entry.Type, entry.TypeModifiers, true)
	if err != nil {
		return Type{}, fmt.Errorf("entry %q result: %w", entry.Name, err)
	}
	return value, nil
}

// Audit resolves every field and method result in the schema.
func (resolver *Resolver) Audit() error {
	for i := range resolver.schema.Entries {
		entry := &resolver.schema.Entries[i]
		for j := range entry.Arguments {
			argument := &entry.Arguments[j]
			if argument.Type == "#" {
				continue
			}
			if _, err := resolver.Argument(entry, argument); err != nil {
				return err
			}
		}
		if entry.Kind == schema.KindMethod {
			if _, err := resolver.Result(entry); err != nil {
				return err
			}
		}
	}
	return nil
}

func (resolver *Resolver) resolve(
	entry *schema.Entry,
	tlName string,
	modifiers *schema.Modifiers,
	result bool,
) (Type, error) {
	value := Type{
		TLName:   tlName,
		Vector:   vectorKind(modifiers),
		Optional: modifiers != nil && modifiers.Predicate != "",
	}
	if result && value.Optional {
		return Type{}, fmt.Errorf("result type cannot be conditional")
	}

	genericName, genericQuery := generic(tlName)
	if genericName != "" && (genericQuery || hasGeneric(entry, genericName)) {
		if !hasGeneric(entry, genericName) {
			return Type{}, fmt.Errorf("unknown generic %q", genericName)
		}
		if modifiers != nil {
			return Type{}, fmt.Errorf("generic %q has unsupported modifiers", genericName)
		}
		if result && genericQuery {
			return Type{}, fmt.Errorf("result generic %q cannot be a query", genericName)
		}
		value.Kind = GenericKind
		value.TLName = genericName
		value.GoName = genericName
		value.GenericQuery = genericQuery
		return value, nil
	}

	if primitive := primitives[tlName]; primitive != 0 {
		if err := validatePrimitive(tlName, modifiers, result); err != nil {
			return Type{}, err
		}
		value.Kind = PrimitiveKind
		value.Primitive = primitive
		value.Pointer = value.Optional &&
			value.Vector == NotVector &&
			primitive != Bytes &&
			primitive != Flag
		return value, nil
	}
	if tlName == "Object" {
		value.Kind = UnionKind
		value.GoName = "Object"
		return value, nil
	}

	if modifiers != nil && modifiers.Constructor != nil {
		constructor := resolver.constructors[*modifiers.Constructor]
		if constructor == nil {
			return Type{}, fmt.Errorf(
				"type %q references unknown constructor %#08x",
				tlName,
				*modifiers.Constructor,
			)
		}
		if constructor.Name != tlName && constructor.Type != tlName {
			return Type{}, fmt.Errorf(
				"type %q references constructor %q of type %q",
				tlName,
				constructor.Name,
				constructor.Type,
			)
		}
		goName, err := naming.Entry(constructor, resolver.flavor)
		if err != nil {
			return Type{}, err
		}
		value.Kind = ConstructorKind
		value.TLName = constructor.Name
		value.GoName = goName
		value.ConstructorID = constructor.ID
		value.Bare = !result ||
			constructor.Name == tlName ||
			modifiers.IsBareType ||
			modifiers.IsBareUnion
		value.Pointer = value.Vector == NotVector && (value.Optional || result)
		return value, nil
	}

	if constructor := resolver.schema.Classes[tlName]; constructor != nil {
		return Type{}, fmt.Errorf("bare constructor %q is missing its constructor ID", tlName)
	}
	if union := resolver.schema.Unions[tlName]; union != nil {
		if modifiers != nil && (modifiers.IsBareType || modifiers.IsBareUnion) {
			return Type{}, fmt.Errorf("bare union %q is missing its constructor ID", tlName)
		}
		goName, err := naming.Union(union.Name, resolver.flavor)
		if err != nil {
			return Type{}, err
		}
		value.Kind = UnionKind
		value.GoName = goName
		return value, nil
	}
	return Type{}, fmt.Errorf("unknown TL type %q", tlName)
}

func vectorKind(modifiers *schema.Modifiers) Vector {
	if modifiers == nil {
		return NotVector
	}
	if modifiers.IsBareVector {
		return BareVector
	}
	if modifiers.IsVector {
		return BoxedVector
	}
	return NotVector
}

func generic(name string) (string, bool) {
	if after, ok := strings.CutPrefix(name, "!"); ok {
		return after, true
	}
	if len(name) == 1 && name[0] >= 'A' && name[0] <= 'Z' {
		return name, false
	}
	return "", false
}

func hasGeneric(entry *schema.Entry, name string) bool {
	for _, value := range entry.Generics {
		if value.Name == name {
			return true
		}
	}
	return false
}

func validatePrimitive(name string, modifiers *schema.Modifiers, result bool) error {
	if modifiers != nil {
		if modifiers.Constructor != nil || modifiers.IsBareType || modifiers.IsBareUnion {
			return fmt.Errorf("primitive %q has constructor modifiers", name)
		}
		if result && modifiers.Predicate != "" {
			return fmt.Errorf("primitive result %q cannot be conditional", name)
		}
	}
	if name == "true" && (modifiers == nil || modifiers.Predicate == "") {
		return fmt.Errorf("flag-only true must be conditional")
	}
	return nil
}
