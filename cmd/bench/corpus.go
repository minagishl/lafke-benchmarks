package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// corpus is one entry of corpora.json. Which fields apply depends on Kind.
type corpus struct {
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	Repo    string   `json:"repo"`
	Rev     string   `json:"rev"`
	Path    string   `json:"path,omitempty"`
	Sparse  []string `json:"sparse,omitempty"`
	Command []string `json:"command"`
	// Timing overrides whether wall time and memory are measured. The default is true for a
	// corpus that analyzes one tree, and false for a corpus made of many units.
	Timing *bool `json:"timing,omitempty"`

	Labels         *labels  `json:"labels,omitempty"`          // owasp-csv
	SkipCategories []string `json:"skip_categories,omitempty"` // cwe-csv
	// Queries maps a KICS query directory (relative to assets/queries) to the lafke rules that
	// count as finding it. A query that is not listed is not scored.
	Queries      map[string][]string   `json:"queries,omitempty"`       // kics
	QueryFilters map[string]kicsFilter `json:"query_filters,omitempty"` // kics
}

type corporaFile struct {
	CWEGroups [][]int  `json:"cwe_groups"`
	Corpora   []corpus `json:"corpora"`
}

func loadCorpora(path string) (*corporaFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f corporaFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	seen := map[string]bool{}
	for _, c := range f.Corpora {
		if seen[c.Name] {
			return nil, fmt.Errorf("%s: duplicate corpus %q", path, c.Name)
		}
		seen[c.Name] = true
		if _, ok := suites[c.Kind]; !ok {
			return nil, fmt.Errorf("%s: corpus %q has unknown kind %q", path, c.Name, c.Kind)
		}
		if len(c.Rev) != 40 {
			return nil, fmt.Errorf("%s: corpus %q: rev must be a full 40-character commit hash", path, c.Name)
		}
	}
	return &f, nil
}

// unit is one directory that lafke analyzes on its own.
type unit struct {
	Name string // unique within the corpus
	Dir  string // absolute directory handed to lafke
	// Prefix is prepended to the file names lafke reports, so they are relative to the
	// repository root when Dir is a subdirectory of it.
	Prefix string
	Meta   any // suite-specific data
}

type unitResult struct {
	findings   []finding
	incomplete int
	timedOut   bool // lafke did not finish in time; the unit has no findings
}

// suite fetches a corpus, splits it into units and scores the findings of every unit.
type suite interface {
	prepare(e *env, c *corpus) ([]unit, error)
	score(e *env, c *corpus, units []unit, res map[string]*unitResult) (*accuracy, error)
}

var suites = map[string]suite{
	"owasp-csv": owaspSuite{},
	"cwe-csv":   cweCSVSuite{},
	"juliet":    julietSuite{},
	"vulnbench": vulnbenchSuite{},
	"kics":      kicsSuite{},
}

// env is what the suites share.
type env struct {
	cache  string
	groups cweGroups
	sem    chan struct{} // limits concurrent git operations
}
