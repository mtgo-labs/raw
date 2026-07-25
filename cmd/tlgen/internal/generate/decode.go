package generate

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"strings"

	"github.com/mtgo-labs/raw/cmd/tlgen/internal/naming"
	"github.com/mtgo-labs/raw/cmd/tlgen/internal/schema"
	"github.com/mtgo-labs/raw/cmd/tlgen/internal/types"
)

type allocationSize struct {
	size32 int
	size64 int
}

type allocationSizer struct {
	resolver     *types.Resolver
	constructors map[uint32]*schema.Entry
	cache        map[uint32]allocationSize
	active       map[uint32]bool
}

func newAllocationSizer(
	value *schema.Schema,
	resolver *types.Resolver,
) *allocationSizer {
	constructors := make(map[uint32]*schema.Entry, len(value.Classes))
	for index := range value.Entries {
		entry := &value.Entries[index]
		if entry.Kind == schema.KindClass {
			constructors[entry.ID] = entry
		}
	}
	return &allocationSizer{
		resolver:     resolver,
		constructors: constructors,
		cache:        make(map[uint32]allocationSize, len(constructors)),
		active:       make(map[uint32]bool),
	}
}

func (sizer *allocationSizer) entry(
	entry *schema.Entry,
) (allocationSize, error) {
	if size, ok := sizer.cache[entry.ID]; ok {
		return size, nil
	}
	if sizer.active[entry.ID] {
		return allocationSize{}, fmt.Errorf(
			"constructor %q contains itself by value",
			entry.Name,
		)
	}
	sizer.active[entry.ID] = true
	defer delete(sizer.active, entry.ID)

	size := allocationSize{}
	for index := range entry.Arguments {
		argument := &entry.Arguments[index]
		if argument.Type == "#" {
			continue
		}
		resolved, err := sizer.resolver.Argument(entry, argument)
		if err != nil {
			return allocationSize{}, err
		}
		field, err := sizer.value(resolved)
		if err != nil {
			return allocationSize{}, err
		}
		size.size32 += alignAllocation(field.size32, 4)
		size.size64 += alignAllocation(field.size64, 8)
	}
	if size.size32 == 0 {
		size.size32 = 4
	}
	if size.size64 == 0 {
		size.size64 = 8
	}
	sizer.cache[entry.ID] = size
	return size, nil
}

func (sizer *allocationSizer) value(
	value types.Type,
) (allocationSize, error) {
	if value.Vector != types.NotVector {
		return allocationSize{size32: 12, size64: 24}, nil
	}
	if value.Pointer {
		return allocationSize{size32: 4, size64: 8}, nil
	}
	switch value.Kind {
	case types.PrimitiveKind:
		return primitiveAllocationSize(value.Primitive), nil
	case types.UnionKind:
		return allocationSize{size32: 8, size64: 16}, nil
	case types.ConstructorKind:
		entry := sizer.constructors[value.ConstructorID]
		if entry == nil {
			return allocationSize{}, fmt.Errorf(
				"missing constructor %#08x for %q",
				value.ConstructorID,
				value.TLName,
			)
		}
		return sizer.entry(entry)
	default:
		return allocationSize{}, fmt.Errorf(
			"unsupported allocation type %q",
			value.TLName,
		)
	}
}

func primitiveAllocationSize(value types.Primitive) allocationSize {
	switch value {
	case types.Int:
		return allocationSize{size32: 4, size64: 4}
	case types.Long, types.Int53, types.Double:
		return allocationSize{size32: 8, size64: 8}
	case types.Int128:
		return allocationSize{size32: 16, size64: 16}
	case types.Int256:
		return allocationSize{size32: 32, size64: 32}
	case types.String:
		return allocationSize{size32: 8, size64: 16}
	case types.Bytes:
		return allocationSize{size32: 12, size64: 24}
	case types.Bool, types.Flag:
		return allocationSize{size32: 1, size64: 1}
	default:
		panic("unsupported primitive allocation size")
	}
}

func alignAllocation(value, alignment int) int {
	return (value + alignment - 1) & -alignment
}

func decodingDecls(
	entry *schema.Entry,
	flavor naming.Flavor,
	resolver *types.Resolver,
	sizer *allocationSizer,
	fset *token.FileSet,
) ([]ast.Decl, error) {
	goName, err := naming.Entry(entry, flavor)
	if err != nil {
		return nil, err
	}
	if entry.Kind == schema.KindMethod {
		return resultDecoderDecls(entry, goName, resolver, sizer, fset)
	}
	arguments, err := resolveEncodingArguments(entry, resolver)
	if err != nil {
		return nil, err
	}
	_, flagLocals, err := encodingPredicates(arguments)
	if err != nil {
		return nil, err
	}
	size, err := sizer.entry(entry)
	if err != nil {
		return nil, err
	}

	var source sourceWriter
	writeConstructorDecoder(&source, entry, goName, size)
	writeDecodeBody(
		&source,
		entry,
		"*"+goName,
		arguments,
		flagLocals,
		sizer,
	)
	return parseDecoderDecls(fset, source.String())
}

func writeConstructorDecoder(
	source *sourceWriter,
	entry *schema.Entry,
	goName string,
	size allocationSize,
) {
	source.line("// decode%s decodes a TL %s.", goName, entry.Type)
	source.line(
		"func decode%s(input *decoder) (*%s, error) {",
		goName,
		goName,
	)
	source.indent++
	source.line(
		"if err := input.reserveAllocation(%q, decodedAllocationSize(%d, %d)); err != nil {",
		entry.Name,
		size.size32,
		size.size64,
	)
	source.indent++
	source.line("return nil, err")
	source.indent--
	source.line("}")
	source.line("value := new(%s)", goName)
	source.line("if err := value.decodeBody(input); err != nil {")
	source.indent++
	source.line("return nil, err")
	source.indent--
	source.line("}")
	source.line("return value, nil")
	source.indent--
	source.line("}")
}

func writeDecodeBody(
	source *sourceWriter,
	entry *schema.Entry,
	receiver string,
	arguments []*encodingArgument,
	flagLocals map[string]string,
	sizer *allocationSizer,
) {
	source.line("func (value %s) decodeBody(input *decoder) error {", receiver)
	source.indent++
	source.line("if err := input.enter(); err != nil {")
	source.indent++
	source.line("return err")
	source.indent--
	source.line("}")

	usedFlags := make(map[string]bool, len(flagLocals))
	for _, argument := range arguments {
		if argument.argument.TypeModifiers == nil ||
			argument.argument.TypeModifiers.Predicate == "" {
			continue
		}
		flag, _ := predicateParts(argument.argument.TypeModifiers.Predicate)
		usedFlags[flag] = true
	}
	temporary := 0
	for _, argument := range arguments {
		if argument.argument.Type == "#" {
			local := flagLocals[argument.argument.Name]
			source.line("%s, err := input.readUint32()", local)
			writeDecodeErrorCheck(source, true)
			if !usedFlags[argument.argument.Name] {
				source.line("_ = %s", local)
			}
			continue
		}
		if argument.resolved.Primitive == types.Flag {
			flag, bit := predicateParts(argument.argument.TypeModifiers.Predicate)
			source.line(
				"value.%s = %s&(uint32(1)<<%d) != 0",
				argument.field,
				flagLocals[flag],
				bit,
			)
			continue
		}
		if argument.resolved.Optional {
			flag, bit := predicateParts(argument.argument.TypeModifiers.Predicate)
			source.line(
				"if %s&(uint32(1)<<%d) != 0 {",
				flagLocals[flag],
				bit,
			)
			source.indent++
		}
		if isMTProtoMessageBody(entry, argument) {
			index := nextTemporary(&temporary)
			source.line("_field%d, err := input.readMessageBody(value.Bytes)", index)
			writeDecodeErrorCheck(source, true)
			source.line("value.%s = _field%d", argument.field, index)
		} else {
			writeDecodedValue(
				source,
				entry,
				argument.argument.Name,
				argument.resolved,
				"value."+argument.field,
				&temporary,
				sizer,
				true,
			)
		}
		if argument.resolved.Optional {
			source.indent--
			source.line("}")
		}
	}
	source.line("input.leave()")
	source.line("return nil")
	source.indent--
	source.line("}")
}

func resultDecoderDecls(
	entry *schema.Entry,
	goName string,
	resolver *types.Resolver,
	sizer *allocationSizer,
	fset *token.FileSet,
) ([]ast.Decl, error) {
	result, err := resolver.Result(entry)
	if err != nil {
		return nil, err
	}
	resultType, err := result.GoType()
	if err != nil {
		return nil, err
	}
	var source sourceWriter
	receiver := encodingReceiver(goName, entry.Generics)
	if result.Kind == types.GenericKind {
		source.line(
			"func (value %s) decodeResult(state decoder) (%s, decoder, error) {",
			receiver,
			resultType,
		)
		source.indent++
		source.line("var zero %s", resultType)
		source.line("if value == nil || value.Query == nil {")
		source.indent++
		source.line("return zero, state, ErrNilObject")
		source.indent--
		source.line("}")
		source.line("return value.Query.decodeResult(state)")
		source.indent--
		source.line("}")
		return parseDecoderDecls(fset, source.String())
	}

	source.line(
		"func (request %s) decodeResult(state decoder) (%s, decoder, error) {",
		receiver,
		resultType,
	)
	source.indent++
	source.line("var zero %s", resultType)
	source.line("if request == nil {")
	source.indent++
	source.line("return zero, state, ErrNilObject")
	source.indent--
	source.line("}")
	source.line("input := &state")
	source.line("var result %s", resultType)
	temporary := 0
	writeDecodedValue(
		&source,
		entry,
		"result",
		result,
		"result",
		&temporary,
		sizer,
		false,
	)
	source.line("return result, state, nil")
	source.indent--
	source.line("}")
	return parseDecoderDecls(fset, source.String())
}

func writeDecodedValue(
	source *sourceWriter,
	entry *schema.Entry,
	field string,
	value types.Type,
	target string,
	temporary *int,
	sizer *allocationSizer,
	body bool,
) {
	if value.Vector != types.NotVector {
		writeDecodedVector(
			source,
			entry,
			field,
			value,
			target,
			temporary,
			sizer,
			body,
		)
		return
	}
	switch value.Kind {
	case types.PrimitiveKind:
		writeDecodedPrimitive(
			source,
			entry,
			field,
			value,
			target,
			temporary,
			body,
		)
	case types.ConstructorKind:
		writeDecodedConstructor(
			source,
			entry,
			field,
			value,
			target,
			temporary,
			sizer,
			body,
		)
	case types.UnionKind:
		index := nextTemporary(temporary)
		if value.GoName == "Object" {
			source.line("_field%d, err := input.readObject()", index)
		} else {
			source.line(
				"_field%d, err := decode%s(input)",
				index,
				value.GoName,
			)
		}
		writeDecodeErrorCheck(source, body)
		source.line("%s = _field%d", target, index)
	default:
		panic("unsupported decoded value")
	}
}

func writeDecodedPrimitive(
	source *sourceWriter,
	entry *schema.Entry,
	field string,
	value types.Type,
	target string,
	temporary *int,
	body bool,
) {
	method := primitiveReadMethod(value.Primitive)
	index := nextTemporary(temporary)
	source.line("_field%d, err := input.%s()", index, method)
	writeDecodeErrorCheck(source, body)
	if value.Pointer {
		size := primitiveAllocationSize(value.Primitive)
		source.line(
			"if err := input.reserveAllocation(%q, decodedAllocationSize(%d, %d)); err != nil {",
			entry.Name+"."+field,
			size.size32,
			size.size64,
		)
		writeDecodeErrorBody(source, body)
		source.line("}")
		source.line("%s = &_field%d", target, index)
		return
	}
	source.line("%s = _field%d", target, index)
}

func writeDecodedConstructor(
	source *sourceWriter,
	entry *schema.Entry,
	field string,
	value types.Type,
	target string,
	temporary *int,
	sizer *allocationSizer,
	body bool,
) {
	if !value.Bare {
		writeExpectedConstructor(
			source,
			value.GoName,
			value.ConstructorID,
			temporary,
			body,
		)
	}
	if value.Pointer {
		constructor := sizer.constructors[value.ConstructorID]
		size, err := sizer.entry(constructor)
		if err != nil {
			panic(err)
		}
		source.line(
			"if err := input.reserveAllocation(%q, decodedAllocationSize(%d, %d)); err != nil {",
			entry.Name+"."+field,
			size.size32,
			size.size64,
		)
		writeDecodeErrorBody(source, body)
		source.line("}")
		index := nextTemporary(temporary)
		source.line("_field%d := new(%s)", index, value.GoName)
		source.line("if err := _field%d.decodeBody(input); err != nil {", index)
		writeDecodeErrorBody(source, body)
		source.line("}")
		source.line("%s = _field%d", target, index)
		return
	}
	source.line("if err := %s.decodeBody(input); err != nil {", target)
	writeDecodeErrorBody(source, body)
	source.line("}")
}

func writeDecodedVector(
	source *sourceWriter,
	entry *schema.Entry,
	field string,
	value types.Type,
	target string,
	temporary *int,
	sizer *allocationSizer,
	body bool,
) {
	header := "readVectorHeader"
	if value.Vector == types.BareVector {
		header = "readBareVectorHeader"
	}
	index := nextTemporary(temporary)
	source.line("_count%d, err := input.%s()", index, header)
	writeDecodeErrorCheck(source, body)

	element := value
	element.Vector = types.NotVector
	element.Optional = false
	element.Pointer = false
	size, err := sizer.value(element)
	if err != nil {
		panic(err)
	}
	source.line(
		"if err := input.reserveAllocationProduct(%q, _count%d, decodedAllocationSize(%d, %d)); err != nil {",
		entry.Name+"."+field,
		index,
		size.size32,
		size.size64,
	)
	writeDecodeErrorBody(source, body)
	source.line("}")
	source.line("%s = make(%s, _count%d)", target, mustGoType(value), index)
	source.line("for _index%d := range %s {", index, target)
	source.indent++
	writeDecodedValue(
		source,
		entry,
		field,
		element,
		fmt.Sprintf("%s[_index%d]", target, index),
		temporary,
		sizer,
		body,
	)
	source.indent--
	source.line("}")
}

func writeExpectedConstructor(
	source *sourceWriter,
	expected string,
	constructorID uint32,
	temporary *int,
	body bool,
) {
	index := nextTemporary(temporary)
	source.line("_start%d := input.offset", index)
	source.line("_constructor%d, err := input.readUint32()", index)
	writeDecodeErrorCheck(source, body)
	source.line(
		"if _constructor%d != %#08x {",
		index,
		constructorID,
	)
	source.indent++
	source.line(
		"err := input.unexpectedConstructor(_start%d, %q, _constructor%d)",
		index,
		expected,
		index,
	)
	writeDecodeErrorBody(source, body)
	source.indent--
	source.line("}")
}

func writeDecodeErrorCheck(source *sourceWriter, body bool) {
	source.line("if err != nil {")
	writeDecodeErrorBody(source, body)
	source.line("}")
}

func writeDecodeErrorBody(source *sourceWriter, body bool) {
	source.indent++
	if body {
		source.line("input.leave()")
		source.line("return err")
	} else {
		source.line("return zero, state, err")
	}
	source.indent--
}

func primitiveReadMethod(value types.Primitive) string {
	switch value {
	case types.Int:
		return "readInt32"
	case types.Long, types.Int53:
		return "readInt64"
	case types.Int128:
		return "readInt128"
	case types.Int256:
		return "readInt256"
	case types.Double:
		return "readFloat64"
	case types.String:
		return "readString"
	case types.Bytes:
		return "readBytes"
	case types.Bool:
		return "readBool"
	default:
		panic("unsupported decoded primitive")
	}
}

func predicateParts(predicate string) (string, uint64) {
	flag, bitText, ok := strings.Cut(predicate, ".")
	if !ok {
		panic("invalid predicate")
	}
	bit, err := strconv.ParseUint(bitText, 10, 5)
	if err != nil {
		panic(err)
	}
	return flag, bit
}

func nextTemporary(value *int) int {
	current := *value
	*value = current + 1
	return current
}

func mustGoType(value types.Type) string {
	result, err := value.GoType()
	if err != nil {
		panic(err)
	}
	return result
}

func parseDecoderDecls(fset *token.FileSet, source string) ([]ast.Decl, error) {
	file, err := parser.ParseFile(
		fset,
		"",
		"package tl\n"+source,
		parser.ParseComments,
	)
	if err != nil {
		return nil, fmt.Errorf("parse generated decoding methods: %w", err)
	}
	return file.Decls, nil
}

func unionDecoderDecl(
	union *schema.Union,
	flavor naming.Flavor,
	fset *token.FileSet,
) (ast.Decl, error) {
	unionName, err := naming.Union(union.Name, flavor)
	if err != nil {
		return nil, err
	}
	classes := slices.Clone(union.Classes)
	slices.SortFunc(classes, func(left, right *schema.Entry) int {
		if left.ID < right.ID {
			return -1
		}
		if left.ID > right.ID {
			return 1
		}
		return strings.Compare(left.Name, right.Name)
	})

	var source sourceWriter
	source.line("// decode%s decodes the TL union %s.", unionName, union.Name)
	source.line(
		"func decode%s(input *decoder) (%s, error) {",
		unionName,
		unionName,
	)
	source.indent++
	source.line("start := input.offset")
	source.line("constructor, err := input.readUint32()")
	source.line("if err != nil {")
	source.indent++
	source.line("return nil, err")
	source.indent--
	source.line("}")
	source.line("switch constructor {")
	for _, class := range classes {
		className, err := naming.Entry(class, flavor)
		if err != nil {
			return nil, err
		}
		source.line("case %sConstructorID:", className)
		source.indent++
		source.line("value, err := decode%s(input)", className)
		source.line("if err != nil {")
		source.indent++
		source.line("return nil, err")
		source.indent--
		source.line("}")
		source.line("return value, nil")
		source.indent--
	}
	source.line("default:")
	source.indent++
	source.line(
		"return nil, input.unexpectedConstructor(start, %q, constructor)",
		unionName,
	)
	source.indent--
	source.line("}")
	source.indent--
	source.line("}")
	declarations, err := parseDecoderDecls(fset, source.String())
	if err != nil {
		return nil, err
	}
	return declarations[0], nil
}

func objectDecoderDecl(
	api, mtp *schema.Schema,
	fset *token.FileSet,
) (ast.Decl, error) {
	type dispatchEntry struct {
		entry  *schema.Entry
		flavor naming.Flavor
	}
	entries := make([]dispatchEntry, 0, len(api.Classes)+len(mtp.Classes))
	for index := range api.Entries {
		if api.Entries[index].Kind == schema.KindClass {
			entries = append(entries, dispatchEntry{
				entry:  &api.Entries[index],
				flavor: naming.API,
			})
		}
	}
	for index := range mtp.Entries {
		if mtp.Entries[index].Kind == schema.KindClass {
			entries = append(entries, dispatchEntry{
				entry:  &mtp.Entries[index],
				flavor: naming.MTP,
			})
		}
	}
	slices.SortFunc(entries, func(left, right dispatchEntry) int {
		if left.entry.ID < right.entry.ID {
			return -1
		}
		if left.entry.ID > right.entry.ID {
			return 1
		}
		return strings.Compare(left.entry.Name, right.entry.Name)
	})

	var source sourceWriter
	source.line("// decodeObject decodes any TL object from its constructor ID.")
	source.line("func decodeObject(input *decoder) (Object, error) {")
	source.indent++
	source.line("start := input.offset")
	source.line("constructor, err := input.readUint32()")
	source.line("if err != nil {")
	source.indent++
	source.line("return nil, err")
	source.indent--
	source.line("}")
	source.line("switch constructor >> 24 {")
	for start := 0; start < len(entries); {
		prefix := entries[start].entry.ID >> 24
		end := start + 1
		for end < len(entries) && entries[end].entry.ID>>24 == prefix {
			end++
		}
		source.line("case %#02x:", prefix)
		source.indent++
		source.line("switch constructor {")
		for _, item := range entries[start:end] {
			goName, err := naming.Entry(item.entry, item.flavor)
			if err != nil {
				return nil, err
			}
			source.line("case %sConstructorID:", goName)
			source.indent++
			source.line("return decode%s(input)", goName)
			source.indent--
		}
		source.line("}")
		source.indent--
		start = end
	}
	source.line("}")
	source.line(
		"return nil, input.unexpectedConstructor(start, %q, constructor)",
		"object",
	)
	source.indent--
	source.line("}")
	declarations, err := parseDecoderDecls(fset, source.String())
	if err != nil {
		return nil, err
	}
	return declarations[0], nil
}

func renderDispatchBenchmark(
	api, mtp *schema.Schema,
	apiSizes, mtpSizes *allocationSizer,
	metadata Metadata,
) ([]byte, error) {
	ids := make([]uint32, 0, len(api.Classes)+len(mtp.Classes))
	for index := range api.Entries {
		if api.Entries[index].Kind == schema.KindClass {
			ids = append(ids, api.Entries[index].ID)
		}
	}
	for index := range mtp.Entries {
		if mtp.Entries[index].Kind == schema.KindClass {
			ids = append(ids, mtp.Entries[index].ID)
		}
	}
	slices.Sort(ids)

	var source sourceWriter
	source.line("package tl")
	source.line("")
	source.line("import (")
	source.indent++
	source.line("%q", "reflect")
	source.line("%q", "testing")
	source.indent--
	source.line(")")
	source.line("")
	source.line("var benchmarkConstructorIDs = [...]uint32{")
	source.indent++
	for _, id := range ids {
		source.line("%#08x,", id)
	}
	source.indent--
	source.line("}")
	source.line("")
	source.line("func benchmarkConstructorSwitch(constructor uint32) bool {")
	source.indent++
	source.line("switch constructor {")
	for _, id := range ids {
		source.line("case %#08x:", id)
		source.indent++
		source.line("return true")
		source.indent--
	}
	source.line("default:")
	source.indent++
	source.line("return false")
	source.indent--
	source.line("}")
	source.indent--
	source.line("}")
	source.line("")
	source.line("func benchmarkConstructorSplit(constructor uint32) bool {")
	source.indent++
	source.line("switch constructor >> 24 {")
	for prefix := uint32(0); prefix <= 0xff; prefix++ {
		start, _ := slices.BinarySearch(ids, prefix<<24)
		end, _ := slices.BinarySearch(ids, (prefix+1)<<24)
		if prefix == 0xff {
			end = len(ids)
		}
		if start == end {
			continue
		}
		source.line("case %#02x:", prefix)
		source.indent++
		source.line("switch constructor {")
		for _, id := range ids[start:end] {
			source.line("case %#08x:", id)
			source.indent++
			source.line("return true")
			source.indent--
		}
		source.line("}")
		source.indent--
	}
	source.line("}")
	source.line("return false")
	source.indent--
	source.line("}")
	source.line("")
	source.line("func TestGeneratedAllocationSizeBounds(t *testing.T) {")
	source.indent++
	source.line("tests := []struct {")
	source.indent++
	source.line("name string")
	source.line("actual uintptr")
	source.line("limit int")
	source.indent--
	source.line("}{")
	source.indent++
	for index := range api.Entries {
		entry := &api.Entries[index]
		if entry.Kind != schema.KindClass {
			continue
		}
		goName, err := naming.Entry(entry, naming.API)
		if err != nil {
			return nil, err
		}
		size, err := apiSizes.entry(entry)
		if err != nil {
			return nil, err
		}
		source.line(
			"{%q, reflect.TypeFor[%s]().Size(), decodedAllocationSize(%d, %d)},",
			entry.Name,
			goName,
			size.size32,
			size.size64,
		)
	}
	for index := range mtp.Entries {
		entry := &mtp.Entries[index]
		if entry.Kind != schema.KindClass {
			continue
		}
		goName, err := naming.Entry(entry, naming.MTP)
		if err != nil {
			return nil, err
		}
		size, err := mtpSizes.entry(entry)
		if err != nil {
			return nil, err
		}
		source.line(
			"{%q, reflect.TypeFor[%s]().Size(), decodedAllocationSize(%d, %d)},",
			entry.Name,
			goName,
			size.size32,
			size.size64,
		)
	}
	source.indent--
	source.line("}")
	source.line("for _, test := range tests {")
	source.indent++
	source.line("if test.actual > uintptr(test.limit) {")
	source.indent++
	source.line(
		"t.Errorf(%q, test.name, test.actual, test.limit)",
		"%s size = %d, generated bound = %d",
	)
	source.indent--
	source.line("}")
	source.indent--
	source.line("}")
	source.indent--
	source.line("}")

	generated := fmt.Appendf(
		nil,
		"// Code generated by cmd/tlgen (%s); DO NOT EDIT.\n"+
			"//\n"+
			"// Sources: schema/api-schema.json, schema/mtp-schema.json\n"+
			"// Telegram API layer: %d\n\n",
		generatorVersion,
		metadata.Layer,
	)
	generated = append(generated, source.String()...)
	formatted, err := format.Source(generated)
	if err != nil {
		return nil, fmt.Errorf("format dispatch benchmark: %w", err)
	}
	return bytes.Clone(formatted), nil
}
