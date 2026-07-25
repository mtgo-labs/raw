package generate

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"

	"github.com/mtgo-labs/raw/cmd/tlgen/internal/naming"
	"github.com/mtgo-labs/raw/cmd/tlgen/internal/schema"
	"github.com/mtgo-labs/raw/cmd/tlgen/internal/types"
)

type encodingArgument struct {
	argument *schema.Argument
	field    string
	resolved types.Type
}

func isMTProtoMessageBody(entry *schema.Entry, argument *encodingArgument) bool {
	return entry.Name == "mt_message" && argument.argument.Name == "body"
}

type predicateGroup struct {
	predicate string
	flag      string
	bit       uint64
	members   []*encodingArgument
}

type sourceWriter struct {
	strings.Builder
	indent int
}

func (writer *sourceWriter) line(format string, values ...any) {
	for range writer.indent {
		writer.WriteByte('\t')
	}
	fmt.Fprintf(&writer.Builder, format, values...)
	writer.WriteByte('\n')
}

func encodingDecls(
	entry *schema.Entry,
	flavor naming.Flavor,
	resolver *types.Resolver,
	fset *token.FileSet,
) ([]ast.Decl, error) {
	goName, err := naming.Entry(entry, flavor)
	if err != nil {
		return nil, err
	}
	arguments, err := resolveEncodingArguments(entry, resolver)
	if err != nil {
		return nil, err
	}
	groups, flagLocals, err := encodingPredicates(arguments)
	if err != nil {
		return nil, fmt.Errorf("entry %q predicates: %w", entry.Name, err)
	}

	var source sourceWriter
	receiver := encodingReceiver(goName, entry.Generics)
	writeEncodedSizeMethod(&source, entry, receiver)
	writeEncodedBodySizeMethod(
		&source,
		entry,
		receiver,
		arguments,
		groups,
	)
	writeEncodeMethod(&source, entry, receiver, goName+"ConstructorID")
	writeEncodeBodyMethod(
		&source,
		entry,
		receiver,
		arguments,
		groups,
		flagLocals,
	)

	file, err := parser.ParseFile(
		fset,
		"",
		"package tl\n"+source.String(),
		parser.ParseComments,
	)
	if err != nil {
		return nil, fmt.Errorf("parse generated encoding methods: %w", err)
	}
	return file.Decls, nil
}

func resolveEncodingArguments(
	entry *schema.Entry,
	resolver *types.Resolver,
) ([]*encodingArgument, error) {
	arguments := make([]*encodingArgument, 0, len(entry.Arguments))
	for index := range entry.Arguments {
		argument := &entry.Arguments[index]
		value := &encodingArgument{argument: argument}
		if argument.Type != "#" {
			field, err := naming.Field(argument.Name)
			if err != nil {
				return nil, err
			}
			resolved, err := resolver.Argument(entry, argument)
			if err != nil {
				return nil, err
			}
			value.field = field
			value.resolved = resolved
		}
		arguments = append(arguments, value)
	}
	return arguments, nil
}

func encodingPredicates(
	arguments []*encodingArgument,
) ([]*predicateGroup, map[string]string, error) {
	flagLocals := make(map[string]string)
	for _, argument := range arguments {
		if argument.argument.Type != "#" {
			continue
		}
		flagLocals[argument.argument.Name] = fmt.Sprintf(
			"_flags%d",
			len(flagLocals),
		)
	}

	groupsByName := make(map[string]*predicateGroup)
	groups := make([]*predicateGroup, 0)
	for _, argument := range arguments {
		modifiers := argument.argument.TypeModifiers
		if modifiers == nil || modifiers.Predicate == "" {
			continue
		}
		flag, bitText, ok := strings.Cut(modifiers.Predicate, ".")
		if !ok {
			return nil, nil, fmt.Errorf(
				"invalid predicate %q",
				modifiers.Predicate,
			)
		}
		if flagLocals[flag] == "" {
			return nil, nil, fmt.Errorf(
				"predicate %q has no flags argument",
				modifiers.Predicate,
			)
		}
		bit, err := strconv.ParseUint(bitText, 10, 5)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"invalid predicate %q",
				modifiers.Predicate,
			)
		}
		group := groupsByName[modifiers.Predicate]
		if group == nil {
			group = &predicateGroup{
				predicate: modifiers.Predicate,
				flag:      flag,
				bit:       bit,
			}
			groupsByName[modifiers.Predicate] = group
			groups = append(groups, group)
		}
		group.members = append(group.members, argument)
	}
	return groups, flagLocals, nil
}

func encodingReceiver(goName string, generics []schema.Generic) string {
	if len(generics) == 0 {
		return "*" + goName
	}
	names := make([]string, len(generics))
	for index, generic := range generics {
		names[index] = generic.Name
	}
	return "*" + goName + "[" + strings.Join(names, ", ") + "]"
}

func writeEncodedSizeMethod(
	source *sourceWriter,
	entry *schema.Entry,
	receiver string,
) {
	source.line("func (value %s) encodedSize() (int, error) {", receiver)
	source.indent++
	writeNilReceiverCheck(source, entry, true)
	source.line("body, err := value.encodedBodySize()")
	source.line("if err != nil {")
	source.indent++
	source.line("return 0, err")
	source.indent--
	source.line("}")
	source.line("return checkedEncodedSizeAdd(4, body)")
	source.indent--
	source.line("}")
}

func writeEncodedBodySizeMethod(
	source *sourceWriter,
	entry *schema.Entry,
	receiver string,
	arguments []*encodingArgument,
	groups []*predicateGroup,
) {
	source.line("func (value %s) encodedBodySize() (int, error) {", receiver)
	source.indent++
	writeNilReceiverCheck(source, entry, true)
	presence := writePredicateValidation(source, entry, groups, false, nil)
	source.line("size := 0")
	temporary := 0
	for _, argument := range arguments {
		if argument.argument.Type == "#" {
			source.line("size += 4")
			continue
		}
		if argument.resolved.Primitive == types.Flag {
			continue
		}
		if argument.resolved.Optional {
			condition := presence[argument.resolvedPredicate()]
			if condition == "" {
				condition = argumentPresence(argument, "value."+argument.field)
			}
			source.line("if %s {", condition)
			source.indent++
		}
		writeValueSize(
			source,
			entry,
			argument,
			"value."+argument.field,
			&temporary,
		)
		if argument.resolved.Optional {
			source.indent--
			source.line("}")
		}
	}
	source.line("return size, nil")
	source.indent--
	source.line("}")
}

func writeEncodeMethod(
	source *sourceWriter,
	entry *schema.Entry,
	receiver string,
	constructor string,
) {
	source.line("func (value %s) encode(output encoder) (encoder, error) {", receiver)
	source.indent++
	writeNilReceiverCheck(source, entry, false)
	source.line("output.putUint32(%s)", constructor)
	source.line("return value.encodeBody(output)")
	source.indent--
	source.line("}")
}

func writeEncodeBodyMethod(
	source *sourceWriter,
	entry *schema.Entry,
	receiver string,
	arguments []*encodingArgument,
	groups []*predicateGroup,
	flagLocals map[string]string,
) {
	source.line("func (value %s) encodeBody(output encoder) (encoder, error) {", receiver)
	source.indent++
	writeNilReceiverCheck(source, entry, false)
	for _, local := range orderedFlagLocals(arguments, flagLocals) {
		source.line("var %s uint32", local)
	}
	presence := writePredicateValidation(
		source,
		entry,
		groups,
		true,
		flagLocals,
	)
	temporary := 0
	for _, argument := range arguments {
		if argument.argument.Type == "#" {
			source.line("output.putUint32(%s)", flagLocals[argument.argument.Name])
			continue
		}
		if argument.resolved.Primitive == types.Flag {
			continue
		}
		if argument.resolved.Optional {
			condition := presence[argument.resolvedPredicate()]
			if condition == "" {
				condition = argumentPresence(argument, "value."+argument.field)
			}
			source.line("if %s {", condition)
			source.indent++
		}
		writeValueEncode(
			source,
			entry,
			argument,
			"value."+argument.field,
			&temporary,
		)
		if argument.resolved.Optional {
			source.indent--
			source.line("}")
		}
	}
	source.line("return output, nil")
	source.indent--
	source.line("}")
}

func orderedFlagLocals(
	arguments []*encodingArgument,
	flagLocals map[string]string,
) []string {
	locals := make([]string, 0, len(flagLocals))
	for _, argument := range arguments {
		if argument.argument.Type == "#" {
			locals = append(locals, flagLocals[argument.argument.Name])
		}
	}
	return locals
}

func writePredicateValidation(
	source *sourceWriter,
	entry *schema.Entry,
	groups []*predicateGroup,
	buildFlags bool,
	flagLocals map[string]string,
) map[string]string {
	presence := make(map[string]string, len(groups))
	for index, group := range groups {
		if !buildFlags &&
			len(group.members) == 1 &&
			group.members[0].resolved.Primitive == types.Flag {
			continue
		}
		local := fmt.Sprintf("_present%d", index)
		presence[group.predicate] = local
		first := group.members[0]
		source.line(
			"%s := %s",
			local,
			argumentPresence(first, "value."+first.field),
		)
		for _, member := range group.members[1:] {
			source.line(
				"if %s != %s {",
				argumentPresence(member, "value."+member.field),
				local,
			)
			source.indent++
			if buildFlags {
				source.line(
					"return output, encodeError(%q, %q, ErrInconsistentFlags)",
					entry.Name,
					group.predicate,
				)
			} else {
				source.line(
					"return 0, encodeError(%q, %q, ErrInconsistentFlags)",
					entry.Name,
					group.predicate,
				)
			}
			source.indent--
			source.line("}")
		}
		if buildFlags {
			source.line("if %s {", local)
			source.indent++
			source.line(
				"%s |= uint32(1) << %d",
				flagLocals[group.flag],
				group.bit,
			)
			source.indent--
			source.line("}")
		}
	}
	return presence
}

func writeNilReceiverCheck(
	source *sourceWriter,
	entry *schema.Entry,
	size bool,
) {
	source.line("if value == nil {")
	source.indent++
	if size {
		source.line(
			"return 0, encodeError(%q, %q, ErrNilObject)",
			entry.Name,
			"",
		)
	} else {
		source.line(
			"return output, encodeError(%q, %q, ErrNilObject)",
			entry.Name,
			"",
		)
	}
	source.indent--
	source.line("}")
}

func (argument *encodingArgument) resolvedPredicate() string {
	if argument.argument.TypeModifiers == nil {
		return ""
	}
	return argument.argument.TypeModifiers.Predicate
}

func argumentPresence(argument *encodingArgument, expression string) string {
	if argument.resolved.Primitive == types.Flag {
		return expression
	}
	if argument.resolved.Pointer ||
		argument.resolved.Vector != types.NotVector ||
		argument.resolved.Primitive == types.Bytes ||
		argument.resolved.Kind == types.UnionKind {
		return expression + " != nil"
	}
	panic("optional argument has no presence representation")
}

func writeValueSize(
	source *sourceWriter,
	entry *schema.Entry,
	argument *encodingArgument,
	expression string,
	temporary *int,
) {
	if argument.resolved.Vector != types.NotVector {
		writeVectorSize(source, entry, argument, expression, temporary)
		return
	}
	if size := fixedPrimitiveSize(argument.resolved.Primitive); size != 0 {
		source.line("size += %d", size)
		return
	}
	switch argument.resolved.Kind {
	case types.PrimitiveKind:
		writeBytesLikeSize(
			source,
			entry,
			argument,
			primitiveExpression(argument.resolved, expression),
			temporary,
		)
	case types.ConstructorKind, types.UnionKind, types.GenericKind:
		writeObjectSize(source, entry, argument, expression, temporary, "size")
	default:
		panic("unsupported encoding type kind")
	}
}

func writeVectorSize(
	source *sourceWriter,
	entry *schema.Entry,
	argument *encodingArgument,
	expression string,
	temporary *int,
) {
	index := *temporary
	*temporary = index + 1
	headerSize := 8
	if argument.resolved.Vector == types.BareVector {
		headerSize = 4
	}
	source.line("if err := validateVectorLength(len(%s)); err != nil {", expression)
	source.indent++
	source.line(
		"return 0, encodeError(%q, %q, err)",
		entry.Name,
		argument.argument.Name,
	)
	source.indent--
	source.line("}")
	source.line("_vectorSize%d := %d", index, headerSize)

	if elementSize := fixedPrimitiveSize(argument.resolved.Primitive); elementSize != 0 {
		source.line(
			"_elementsSize%d, err := checkedEncodedSizeProduct(len(%s), %d)",
			index,
			expression,
			elementSize,
		)
		source.line("if err != nil {")
		source.indent++
		source.line(
			"return 0, encodeError(%q, %q, err)",
			entry.Name,
			argument.argument.Name,
		)
		source.indent--
		source.line("}")
		source.line(
			"_vectorSize%d, err = checkedEncodedSizeAdd(_vectorSize%d, _elementsSize%d)",
			index,
			index,
			index,
		)
		source.line("if err != nil {")
		source.indent++
		source.line(
			"return 0, encodeError(%q, %q, err)",
			entry.Name,
			argument.argument.Name,
		)
		source.indent--
		source.line("}")
	} else {
		source.line("for _index%d := range %s {", index, expression)
		source.indent++
		element := fmt.Sprintf("%s[_index%d]", expression, index)
		switch argument.resolved.Kind {
		case types.PrimitiveKind:
			writeBytesLikeSizeInto(
				source,
				entry,
				argument,
				element,
				temporary,
				fmt.Sprintf("_vectorSize%d", index),
			)
		case types.ConstructorKind, types.UnionKind:
			writeObjectSize(
				source,
				entry,
				argument,
				element,
				temporary,
				fmt.Sprintf("_vectorSize%d", index),
			)
		default:
			panic("unsupported vector element type")
		}
		source.indent--
		source.line("}")
	}
	source.line(
		"_totalSize%d, err := checkedEncodedSizeAdd(size, _vectorSize%d)",
		index,
		index,
	)
	source.line("if err != nil {")
	source.indent++
	source.line(
		"return 0, encodeError(%q, %q, err)",
		entry.Name,
		argument.argument.Name,
	)
	source.indent--
	source.line("}")
	source.line("size = _totalSize%d", index)
}

func writeBytesLikeSize(
	source *sourceWriter,
	entry *schema.Entry,
	argument *encodingArgument,
	expression string,
	temporary *int,
) {
	writeBytesLikeSizeInto(
		source,
		entry,
		argument,
		expression,
		temporary,
		"size",
	)
}

func writeBytesLikeSizeInto(
	source *sourceWriter,
	entry *schema.Entry,
	argument *encodingArgument,
	expression string,
	temporary *int,
	target string,
) {
	index := *temporary
	*temporary = index + 1
	source.line(
		"_fieldSize%d, err := bytesEncodedSize(len(%s))",
		index,
		expression,
	)
	source.line("if err != nil {")
	source.indent++
	source.line(
		"return 0, encodeError(%q, %q, err)",
		entry.Name,
		argument.argument.Name,
	)
	source.indent--
	source.line("}")
	source.line(
		"%s, err = checkedEncodedSizeAdd(%s, _fieldSize%d)",
		target,
		target,
		index,
	)
	source.line("if err != nil {")
	source.indent++
	source.line(
		"return 0, encodeError(%q, %q, err)",
		entry.Name,
		argument.argument.Name,
	)
	source.indent--
	source.line("}")
}

func writeObjectSize(
	source *sourceWriter,
	entry *schema.Entry,
	argument *encodingArgument,
	expression string,
	temporary *int,
	target string,
) {
	index := *temporary
	*temporary = index + 1
	if !argument.resolved.Optional &&
		(argument.resolved.Pointer ||
			argument.resolved.Kind == types.UnionKind ||
			argument.resolved.Kind == types.GenericKind) {
		source.line("if %s == nil {", expression)
		source.indent++
		source.line(
			"return 0, encodeError(%q, %q, ErrNilObject)",
			entry.Name,
			argument.argument.Name,
		)
		source.indent--
		source.line("}")
	}
	method := "encodedSize"
	if argument.resolved.Bare {
		method = "encodedBodySize"
	}
	source.line("_fieldSize%d, err := %s.%s()", index, expression, method)
	source.line("if err != nil {")
	source.indent++
	source.line(
		"return 0, encodeError(%q, %q, err)",
		entry.Name,
		argument.argument.Name,
	)
	source.indent--
	source.line("}")
	if isMTProtoMessageBody(entry, argument) {
		source.line("if err := validateMessageBodyLength(value.Bytes, _fieldSize%d); err != nil {", index)
		source.indent++
		source.line(
			"return 0, encodeError(%q, %q, err)",
			entry.Name,
			argument.argument.Name,
		)
		source.indent--
		source.line("}")
	}
	source.line(
		"%s, err = checkedEncodedSizeAdd(%s, _fieldSize%d)",
		target,
		target,
		index,
	)
	source.line("if err != nil {")
	source.indent++
	source.line(
		"return 0, encodeError(%q, %q, err)",
		entry.Name,
		argument.argument.Name,
	)
	source.indent--
	source.line("}")
}

func writeValueEncode(
	source *sourceWriter,
	entry *schema.Entry,
	argument *encodingArgument,
	expression string,
	temporary *int,
) {
	if argument.resolved.Vector != types.NotVector {
		writeVectorEncode(source, entry, argument, expression, temporary)
		return
	}
	switch argument.resolved.Kind {
	case types.PrimitiveKind:
		writePrimitiveEncode(
			source,
			entry,
			argument,
			primitiveExpression(argument.resolved, expression),
		)
	case types.ConstructorKind, types.UnionKind, types.GenericKind:
		writeObjectEncode(source, entry, argument, expression, temporary)
	default:
		panic("unsupported encoding type kind")
	}
}

func writeVectorEncode(
	source *sourceWriter,
	entry *schema.Entry,
	argument *encodingArgument,
	expression string,
	temporary *int,
) {
	method := "putVectorHeader"
	if argument.resolved.Vector == types.BareVector {
		method = "putBareVectorHeader"
	}
	source.line("if err := output.%s(len(%s)); err != nil {", method, expression)
	source.indent++
	source.line(
		"return output, encodeError(%q, %q, err)",
		entry.Name,
		argument.argument.Name,
	)
	source.indent--
	source.line("}")
	source.line("for _index := range %s {", expression)
	source.indent++
	element := expression + "[_index]"
	switch argument.resolved.Kind {
	case types.PrimitiveKind:
		writePrimitiveEncode(source, entry, argument, element)
	case types.ConstructorKind, types.UnionKind:
		writeObjectEncode(source, entry, argument, element, temporary)
	default:
		panic("unsupported vector element type")
	}
	source.indent--
	source.line("}")
}

func writePrimitiveEncode(
	source *sourceWriter,
	entry *schema.Entry,
	argument *encodingArgument,
	expression string,
) {
	var method string
	switch argument.resolved.Primitive {
	case types.Int:
		method = "putInt32"
	case types.Long, types.Int53:
		method = "putInt64"
	case types.Int128:
		method = "putInt128"
	case types.Int256:
		method = "putInt256"
	case types.Double:
		method = "putFloat64"
	case types.String:
		method = "putString"
	case types.Bytes:
		method = "putBytes"
	case types.Bool:
		method = "putBool"
	case types.Flag:
		return
	default:
		panic("unsupported primitive")
	}
	if argument.resolved.Primitive == types.String ||
		argument.resolved.Primitive == types.Bytes {
		source.line("if err := output.%s(%s); err != nil {", method, expression)
		source.indent++
		source.line(
			"return output, encodeError(%q, %q, err)",
			entry.Name,
			argument.argument.Name,
		)
		source.indent--
		source.line("}")
		return
	}
	source.line("output.%s(%s)", method, expression)
}

func writeObjectEncode(
	source *sourceWriter,
	entry *schema.Entry,
	argument *encodingArgument,
	expression string,
	temporary *int,
) {
	index := *temporary
	*temporary = index + 1
	if !argument.resolved.Optional &&
		(argument.resolved.Pointer ||
			argument.resolved.Kind == types.UnionKind ||
			argument.resolved.Kind == types.GenericKind) {
		source.line("if %s == nil {", expression)
		source.indent++
		source.line(
			"return output, encodeError(%q, %q, ErrNilObject)",
			entry.Name,
			argument.argument.Name,
		)
		source.indent--
		source.line("}")
	}
	if isMTProtoMessageBody(entry, argument) {
		source.line("_fieldStart%d := len(output.buffer)", index)
	}
	method := "encode"
	if argument.resolved.Bare {
		method = "encodeBody"
	}
	source.line("_output%d, err := %s.%s(output)", index, expression, method)
	source.line("if err != nil {")
	source.indent++
	source.line(
		"return output, encodeError(%q, %q, err)",
		entry.Name,
		argument.argument.Name,
	)
	source.indent--
	source.line("}")
	source.line("output = _output%d", index)
	if isMTProtoMessageBody(entry, argument) {
		source.line(
			"if err := validateMessageBodyLength(value.Bytes, len(output.buffer)-_fieldStart%d); err != nil {",
			index,
		)
		source.indent++
		source.line(
			"return output, encodeError(%q, %q, err)",
			entry.Name,
			argument.argument.Name,
		)
		source.indent--
		source.line("}")
	}
}

func primitiveExpression(value types.Type, expression string) string {
	if value.Pointer {
		return "*" + expression
	}
	return expression
}

func fixedPrimitiveSize(primitive types.Primitive) int {
	switch primitive {
	case types.Int, types.Bool:
		return 4
	case types.Long, types.Int53, types.Double:
		return 8
	case types.Int128:
		return 16
	case types.Int256:
		return 32
	default:
		return 0
	}
}
