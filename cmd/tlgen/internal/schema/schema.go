// Package schema parses and validates the pinned mtcute TL schema inputs.
package schema

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Kind identifies whether a TL entry is a constructor or an RPC method.
type Kind string

const (
	KindClass  Kind = "class"
	KindMethod Kind = "method"
)

// Availability identifies which account types may invoke an RPC method.
type Availability string

const (
	AvailableBoth Availability = "both"
	AvailableBot  Availability = "bot"
	AvailableUser Availability = "user"
)

// Schema is a validated TL schema with indexes used by code generation.
type Schema struct {
	Layer   int
	Entries []Entry
	Classes map[string]*Entry
	Methods map[string]*Entry
	Unions  map[string]*Union
}

// Entry describes a TL constructor or RPC method.
type Entry struct {
	Kind          Kind          `json:"kind"`
	Name          string        `json:"name"`
	Type          string        `json:"type"`
	ID            uint32        `json:"id"`
	TypeModifiers *Modifiers    `json:"typeModifiers,omitempty"`
	Comment       string        `json:"comment,omitempty"`
	Generics      []Generic     `json:"generics,omitempty"`
	Arguments     []Argument    `json:"arguments"`
	Throws        []ThrownError `json:"throws,omitempty"`
	Available     Availability  `json:"available,omitempty"`
}

// Argument describes one field in a constructor or method.
type Argument struct {
	Name          string     `json:"name"`
	Type          string     `json:"type"`
	TypeModifiers *Modifiers `json:"typeModifiers,omitempty"`
	Comment       string     `json:"comment,omitempty"`
}

// Modifiers describes TL vector, bare, and conditional-field modifiers.
type Modifiers struct {
	Predicate    string  `json:"predicate,omitempty"`
	IsVector     bool    `json:"isVector,omitempty"`
	IsBareVector bool    `json:"isBareVector,omitempty"`
	IsBareUnion  bool    `json:"isBareUnion,omitempty"`
	IsBareType   bool    `json:"isBareType,omitempty"`
	Constructor  *uint32 `json:"constructorId,omitempty"`
}

// Generic describes a TL generic type parameter.
type Generic struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// ThrownError describes a documented RPC error.
type ThrownError struct {
	Code    int    `json:"code"`
	Name    string `json:"name"`
	Comment string `json:"comment,omitempty"`
}

// Union groups constructors sharing one result type.
type Union struct {
	Name    string
	Comment string
	Classes []*Entry
}

type packedSchema struct {
	Layer    int               `json:"l"`
	Entries  []Entry           `json:"e"`
	Comments map[string]string `json:"u"`
}

// LoadAPI reads and validates mtcute's packed API schema.
func LoadAPI(path string) (*Schema, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read API schema: %w", err)
	}

	var packed packedSchema
	if err := json.Unmarshal(data, &packed); err != nil {
		return nil, fmt.Errorf("decode API schema: %w", err)
	}
	if packed.Layer <= 0 {
		return nil, fmt.Errorf("invalid API layer %d", packed.Layer)
	}
	return build(packed.Layer, packed.Entries, packed.Comments)
}

// LoadMTP reads and validates the MTProto service schema.
func LoadMTP(path string) (*Schema, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read MTProto schema: %w", err)
	}

	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("decode MTProto schema: %w", err)
	}
	extraPath := strings.TrimSuffix(path, ".json") + "-extra.json"
	if extraData, err := os.ReadFile(extraPath); err == nil {
		var extra []Entry
		if err := json.Unmarshal(extraData, &extra); err != nil {
			return nil, fmt.Errorf("decode MTProto extra schema: %w", err)
		}
		entries = append(entries, extra...)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read MTProto extra schema: %w", err)
	}
	return build(0, entries, nil)
}

func build(layer int, entries []Entry, comments map[string]string) (*Schema, error) {
	result := &Schema{
		Layer:   layer,
		Entries: entries,
		Classes: make(map[string]*Entry, len(entries)),
		Methods: make(map[string]*Entry, len(entries)/2),
		Unions:  make(map[string]*Union),
	}
	ids := make(map[uint32]string, len(entries))

	for i := range result.Entries {
		entry := &result.Entries[i]
		if err := validateEntry(entry); err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		if previous, ok := ids[entry.ID]; ok {
			return nil, fmt.Errorf(
				"constructor ID %#08x is shared by %q and %q",
				entry.ID,
				previous,
				entry.Name,
			)
		}
		ids[entry.ID] = entry.Name

		var index map[string]*Entry
		switch entry.Kind {
		case KindClass:
			index = result.Classes
		case KindMethod:
			index = result.Methods
		default:
			return nil, fmt.Errorf("entry %q has unknown kind %q", entry.Name, entry.Kind)
		}
		if _, ok := index[entry.Name]; ok {
			return nil, fmt.Errorf("duplicate %s name %q", entry.Kind, entry.Name)
		}
		index[entry.Name] = entry

		if entry.Kind == KindClass {
			union := result.Unions[entry.Type]
			if union == nil {
				union = &Union{Name: entry.Type}
				result.Unions[entry.Type] = union
			}
			union.Classes = append(union.Classes, entry)
		}
	}

	for name, comment := range comments {
		if union := result.Unions[name]; union != nil {
			union.Comment = comment
		}
	}
	return result, nil
}

func validateEntry(entry *Entry) error {
	if entry.Name == "" {
		return fmt.Errorf("empty name")
	}
	if entry.Type == "" {
		return fmt.Errorf("%q has empty result type", entry.Name)
	}
	if entry.Kind == KindMethod {
		switch entry.Available {
		case "", AvailableBoth, AvailableBot, AvailableUser:
		default:
			return fmt.Errorf("%q has invalid availability %q", entry.Name, entry.Available)
		}
	}
	if len(entry.Generics) > 1 {
		return fmt.Errorf("%q has %d generics; only one is supported", entry.Name, len(entry.Generics))
	}
	generics := make(map[string]struct{}, len(entry.Generics))
	for _, generic := range entry.Generics {
		if generic.Name == "" || generic.Type != "Type" {
			return fmt.Errorf("%q has invalid generic %+v", entry.Name, generic)
		}
		generics[generic.Name] = struct{}{}
	}

	arguments := make(map[string]struct{}, len(entry.Arguments))
	flags := make(map[string]struct{})
	for i := range entry.Arguments {
		argument := &entry.Arguments[i]
		if argument.Name == "" || argument.Type == "" {
			return fmt.Errorf("%q has invalid argument %d", entry.Name, i)
		}
		if _, ok := arguments[argument.Name]; ok {
			return fmt.Errorf("%q has duplicate argument %q", entry.Name, argument.Name)
		}
		arguments[argument.Name] = struct{}{}
		if argument.Type == "#" {
			flags[argument.Name] = struct{}{}
		}
		if err := validateModifiers(argument.TypeModifiers); err != nil {
			return fmt.Errorf("%q argument %q: %w", entry.Name, argument.Name, err)
		}
	}
	if err := validateModifiers(entry.TypeModifiers); err != nil {
		return fmt.Errorf("%q result: %w", entry.Name, err)
	}
	for _, argument := range entry.Arguments {
		if argument.TypeModifiers == nil || argument.TypeModifiers.Predicate == "" {
			continue
		}
		name, _, _ := strings.Cut(argument.TypeModifiers.Predicate, ".")
		if _, ok := flags[name]; !ok {
			return fmt.Errorf(
				"%q argument %q references missing flags field %q",
				entry.Name,
				argument.Name,
				name,
			)
		}
	}
	return nil
}

func validateModifiers(modifiers *Modifiers) error {
	if modifiers == nil {
		return nil
	}
	if modifiers.IsVector && modifiers.IsBareVector {
		return fmt.Errorf("type cannot be both vector and bare vector")
	}
	if modifiers.IsBareUnion && modifiers.IsBareType {
		return fmt.Errorf("type cannot be both bare union and bare type")
	}
	if modifiers.Predicate == "" {
		return nil
	}
	name, bitText, ok := strings.Cut(modifiers.Predicate, ".")
	if !ok || name == "" || bitText == "" {
		return fmt.Errorf("invalid predicate %q", modifiers.Predicate)
	}
	bit, err := strconv.Atoi(bitText)
	if err != nil || bit < 0 || bit > 31 {
		return fmt.Errorf("invalid predicate %q", modifiers.Predicate)
	}
	return nil
}
