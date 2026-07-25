// Package naming maps TL schema identifiers to deterministic Go identifiers.
package naming

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/mtgo-labs/raw/cmd/tlgen/internal/schema"
)

// Flavor selects API or MTProto naming rules.
type Flavor uint8

const (
	API Flavor = iota
	MTP
)

// SyntheticSchemaNamespace is the TL namespace for local pseudo schema entries.
const SyntheticSchemaNamespace = "mtcute"

var initialisms = map[string]string{
	"aes":    "AES",
	"api":    "API",
	"cdn":    "CDN",
	"cpu":    "CPU",
	"dc":     "DC",
	"dcs":    "DCs",
	"dh":     "DH",
	"gif":    "GIF",
	"html":   "HTML",
	"http":   "HTTP",
	"https":  "HTTPS",
	"id":     "ID",
	"ids":    "IDs",
	"ip":     "IP",
	"ipv4":   "IPv4",
	"ipv6":   "IPv6",
	"jpeg":   "JPEG",
	"json":   "JSON",
	"mp4":    "MP4",
	"mtp":    "MTP",
	"p2p":    "P2P",
	"pbkdf2": "PBKDF2",
	"pdf":    "PDF",
	"pfs":    "PFS",
	"png":    "PNG",
	"pq":     "PQ",
	"pts":    "PTS",
	"qts":    "QTS",
	"rtmp":   "RTMP",
	"rpc":    "RPC",
	"rsa":    "RSA",
	"sha1":   "SHA1",
	"sha256": "SHA256",
	"sms":    "SMS",
	"srp":    "SRP",
	"tcp":    "TCP",
	"tcpo":   "TCPO",
	"tls":    "TLS",
	"ttl":    "TTL",
	"udp":    "UDP",
	"ui":     "UI",
	"uid":    "UID",
	"uids":   "UIDs",
	"url":    "URL",
	"urls":   "URLs",
	"utf8":   "UTF8",
	"webp":   "WebP",
}

var aliases = map[string]string{
	"msg":  "Message",
	"msgs": "Messages",
}

var reservedFields = map[string]struct{}{
	"ConstructorID": {},
	"DecodeResult":  {},
	"Encode":        {},
}

// Entry returns the generated Go type name for a constructor or method.
func Entry(entry *schema.Entry, flavor Flavor) (string, error) {
	if entry == nil {
		return "", fmt.Errorf("nil entry")
	}
	name := entry.Name
	switch flavor {
	case API:
	case MTP:
		name = strings.TrimPrefix(name, "mt_")
	default:
		return "", fmt.Errorf("entry %q: unknown naming flavor %d", entry.Name, flavor)
	}
	goName, err := qualified(name)
	if err != nil {
		return "", fmt.Errorf("entry %q: %w", entry.Name, err)
	}
	if flavor == MTP {
		goName = "MTP" + goName
	}
	if entry.Kind == schema.KindMethod {
		goName += "Request"
	}
	return goName, nil
}

// Union returns the generated Go interface name for an abstract TL type.
func Union(name string, flavor Flavor) (string, error) {
	if flavor != API && flavor != MTP {
		return "", fmt.Errorf("union %q: unknown naming flavor %d", name, flavor)
	}
	goName, err := qualified(name)
	if err != nil {
		return "", fmt.Errorf("union %q: %w", name, err)
	}
	if flavor == MTP {
		goName = "MTP" + goName
	}
	return goName + "Class", nil
}

// Field returns the exported Go field name for a TL argument.
func Field(name string) (string, error) {
	goName, err := identifier(name)
	if err != nil {
		return "", fmt.Errorf("field %q: %w", name, err)
	}
	return goName, nil
}

// Audit checks every generated type and field name for collisions.
func Audit(api, mtp *schema.Schema) error {
	symbols := make(map[string]string, len(api.Entries)+len(mtp.Entries))
	if err := auditSchema(symbols, api, API); err != nil {
		return err
	}
	if err := auditSchema(symbols, mtp, MTP); err != nil {
		return err
	}
	return nil
}

func auditSchema(symbols map[string]string, value *schema.Schema, flavor Flavor) error {
	for i := range value.Entries {
		entry := &value.Entries[i]
		name, err := Entry(entry, flavor)
		if err != nil {
			return err
		}
		if err := addSymbol(symbols, name, string(entry.Kind)+" "+entry.Name); err != nil {
			return err
		}

		fields := make(map[string]string, len(entry.Arguments))
		for _, argument := range entry.Arguments {
			if argument.Type == "#" {
				continue
			}
			field, err := Field(argument.Name)
			if err != nil {
				return fmt.Errorf("entry %q: %w", entry.Name, err)
			}
			if _, reserved := reservedFields[field]; reserved {
				return fmt.Errorf(
					"entry %q field %q collides with generated method %s",
					entry.Name,
					argument.Name,
					field,
				)
			}
			if previous, exists := fields[field]; exists {
				return fmt.Errorf(
					"entry %q fields %q and %q both normalize to %s",
					entry.Name,
					previous,
					argument.Name,
					field,
				)
			}
			fields[field] = argument.Name
		}
	}
	for name := range value.Unions {
		goName, err := Union(name, flavor)
		if err != nil {
			return err
		}
		if err := addSymbol(symbols, goName, "union "+name); err != nil {
			return err
		}
	}
	return nil
}

func addSymbol(symbols map[string]string, name, source string) error {
	if previous, exists := symbols[name]; exists {
		return fmt.Errorf("%s and %s both normalize to %s", previous, source, name)
	}
	symbols[name] = source
	return nil
}

func qualified(name string) (string, error) {
	parts := strings.Split(name, ".")
	var result strings.Builder
	for index, part := range parts {
		if index == 0 && len(parts) > 1 && part == SyntheticSchemaNamespace {
			result.WriteString("Synthetic")
			continue
		}
		value, err := identifier(part)
		if err != nil {
			return "", err
		}
		result.WriteString(value)
	}
	return result.String(), nil
}

func identifier(name string) (string, error) {
	words, err := splitWords(name)
	if err != nil {
		return "", err
	}
	var result strings.Builder
	result.Grow(len(name))
	for _, word := range words {
		lower := strings.ToLower(word)
		if initialism := normalizedInitialism(lower); initialism != "" {
			result.WriteString(initialism)
			continue
		}
		if alias := aliases[lower]; alias != "" {
			result.WriteString(alias)
			continue
		}
		runes := []rune(lower)
		result.WriteRune(unicode.ToUpper(runes[0]))
		result.WriteString(string(runes[1:]))
	}
	if result.Len() == 0 {
		return "", fmt.Errorf("empty identifier")
	}
	first, _ := utf8.DecodeRuneInString(result.String())
	if !unicode.IsLetter(first) {
		return "", fmt.Errorf("identifier %q starts with a non-letter", name)
	}
	return result.String(), nil
}

func normalizedInitialism(word string) string {
	if value := initialisms[word]; value != "" {
		return value
	}
	end := len(word)
	for end > 0 && word[end-1] >= '0' && word[end-1] <= '9' {
		end--
	}
	if end == len(word) || end == 0 {
		return ""
	}
	if value := initialisms[word[:end]]; value != "" {
		return value + word[end:]
	}
	return ""
}

func splitWords(name string) ([]string, error) {
	if name == "" {
		return nil, fmt.Errorf("empty identifier")
	}
	runes := []rune(name)
	words := make([]string, 0, 4)
	start := 0
	appendWord := func(end int) {
		if end > start {
			words = append(words, string(runes[start:end]))
		}
	}

	for i, current := range runes {
		if current == '_' || current == '-' {
			if i == start {
				return nil, fmt.Errorf("identifier %q contains an empty word", name)
			}
			appendWord(i)
			start = i + 1
			continue
		}
		if !unicode.IsLetter(current) && !unicode.IsDigit(current) {
			return nil, fmt.Errorf("identifier %q contains unsupported character %q", name, current)
		}
		if i == start || i == 0 || !unicode.IsUpper(current) {
			continue
		}

		previous := runes[i-1]
		nextIsLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
		if unicode.IsLower(previous) || unicode.IsDigit(previous) || nextIsLower {
			appendWord(i)
			start = i
		}
	}
	if start == len(runes) {
		return nil, fmt.Errorf("identifier %q contains an empty word", name)
	}
	appendWord(len(runes))
	if len(words) == 0 {
		return nil, fmt.Errorf("identifier %q has no words", name)
	}
	return words, nil
}
