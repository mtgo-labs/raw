// Command doccheck validates repository Markdown without external tooling.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var markdownLink = regexp.MustCompile(`\[[^]]*]\(([^)]+)\)`)

func main() {
	files, err := markdownFiles(".")
	if err != nil {
		fatal(err)
	}

	var problems []string
	for _, path := range files {
		found, err := check(path)
		if err != nil {
			fatal(err)
		}
		problems = append(problems, found...)
	}
	if len(problems) != 0 {
		for _, problem := range problems {
			fmt.Fprintln(os.Stderr, problem)
		}
		os.Exit(1)
	}
}

func markdownFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path != root && strings.HasPrefix(entry.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.EqualFold(filepath.Ext(entry.Name()), ".md") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func check(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	var problems []string
	inCode := false
	lineNumber := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inCode = !inCode
		}
		if strings.TrimRight(line, " \t") != line {
			problems = append(problems, position(path, lineNumber, "trailing whitespace"))
		}
		isLink := strings.Contains(line, "](") || strings.Contains(line, "]:")
		if !inCode &&
			!isLink &&
			!strings.HasPrefix(trimmed, "|") &&
			len([]rune(line)) > 80 {
			problems = append(
				problems,
				position(path, lineNumber, "line exceeds 80 characters"),
			)
		}
		for _, match := range markdownLink.FindAllStringSubmatch(line, -1) {
			target, _, _ := strings.Cut(match[1], "#")
			if target == "" ||
				strings.HasPrefix(target, "http://") ||
				strings.HasPrefix(target, "https://") ||
				strings.HasPrefix(target, "mailto:") {
				continue
			}
			resolved := filepath.Clean(filepath.Join(filepath.Dir(path), target))
			if _, err := os.Stat(resolved); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					problems = append(
						problems,
						position(path, lineNumber, "missing link target "+target),
					)
					continue
				}
				return nil, fmt.Errorf("stat %s: %w", resolved, err)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	if inCode {
		problems = append(problems, position(path, lineNumber, "unclosed code fence"))
	}
	return problems, nil
}

func position(path string, line int, message string) string {
	return fmt.Sprintf("%s:%d: %s", path, line, message)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
