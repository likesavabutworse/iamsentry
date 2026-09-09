package rules

import (
	"embed"
	"io/fs"
	"sort"
	"strings"
)

//go:embed builtin
var builtinFS embed.FS

// BuiltinSources returns the embedded built-in rule bundle as Engine
// Sources — see builtin/README.md for the rule list.
func BuiltinSources() ([]Source, error) {
	var files []string
	err := fs.WalkDir(builtinFS, "builtin", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".rego") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	sources := make([]Source, 0, len(files))
	for _, f := range files {
		b, err := builtinFS.ReadFile(f)
		if err != nil {
			return nil, err
		}
		sources = append(sources, Source{Name: f, Body: string(b)})
	}
	return sources, nil
}
