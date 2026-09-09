// Package denylist loads CheckAccessNotGranted deny-list entries. Purely
// opt-in: unlike the Rego built-in bundle, there is no default deny list —
// what's forbidden is an org policy decision, not a universal best
// practice. See denylist/examples/example.yaml for the format and a
// worked example of each Access shape.
package denylist

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Entry is one CheckAccessNotGranted check: does the scanned policy grant
// any of Actions on any resource, any action on any of Resources, or (if
// both are set) the specific combination? At least one of Actions/
// Resources must be set.
type Entry struct {
	ID        string   `yaml:"id"`
	Actions   []string `yaml:"actions,omitempty"`
	Resources []string `yaml:"resources,omitempty"`
	Reason    string   `yaml:"reason,omitempty"`
}

type file struct {
	Deny []Entry `yaml:"deny"`
}

// Load reads and validates a single deny-list file.
func Load(path string) ([]Entry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading deny-list file %s: %w", path, err)
	}
	var f file
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parsing deny-list file %s: %w", path, err)
	}
	if err := validate(path, f.Deny); err != nil {
		return nil, err
	}
	return f.Deny, nil
}

// LoadDir reads and merges every *.yaml/*.yml file under dir (recursively),
// rejecting duplicate ids across the merged set.
func LoadDir(dir string) ([]Entry, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking deny-list dir %s: %w", dir, err)
	}
	sort.Strings(files)

	var all []Entry
	seen := map[string]string{} // id -> source file
	for _, f := range files {
		entries, err := Load(f)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if src, ok := seen[e.ID]; ok {
				return nil, fmt.Errorf("duplicate deny-list id %q in %s (already defined in %s)", e.ID, f, src)
			}
			seen[e.ID] = f
		}
		all = append(all, entries...)
	}
	return all, nil
}

func validate(path string, entries []Entry) error {
	for i, e := range entries {
		if e.ID == "" {
			return fmt.Errorf("%s: entry #%d has no id", path, i+1)
		}
		if len(e.Actions) == 0 && len(e.Resources) == 0 {
			return fmt.Errorf("%s: entry %q has neither actions nor resources", path, e.ID)
		}
	}
	return nil
}
