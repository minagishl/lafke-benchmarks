package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// kicsSuite scores the query tests of Checkmarx KICS. Every query has a test directory with
// positive files, listed in positive_expected_result.json, and negative files. This is lafke's own
// reading of them, not a KICS scorer: KICS has thousands of queries and lafke has a few dozen
// rules, so only the queries that corpora.json maps to lafke rules are scored.
//
// Each file is one case. A finding has to match its rule ID and any query-specific filter.
// The same criteria apply to positive and negative files.
//
// lafke finds a Dockerfile, a Compose file or a workflow by its name, so every case is copied to
// a directory of its own under the cache, with the name lafke expects. The corpus itself is not
// changed.
type kicsSuite struct{}

type kicsCase struct {
	file  string          // slash-separated, relative to the staging directory
	rules map[string]bool // the rules that count as a hit
	real  bool
	cat   string // the first mapped rule, without the sast: prefix
	match kicsMatcher
}

type kicsMeta struct {
	cases    []kicsCase
	excluded int // cases of a mapped query that could not be staged
}

// kicsExt is the file extensions that a platform's cases can have, and kicsStaged the name a case
// is analyzed under ("" keeps its own name).
var kicsExt = map[string][]string{
	"terraform":     {".tf"},
	"dockerfile":    {".dockerfile"},
	"dockerCompose": {".yaml", ".yml"},
	"k8s":           {".yaml", ".yml"},
	"cicd":          {".yaml", ".yml"},
}

var kicsStaged = map[string]string{
	"dockerfile":    "Dockerfile",
	"dockerCompose": "docker-compose.yml",
	"cicd":          ".github/workflows/workflow.yml",
}

func (kicsSuite) prepare(e *env, c *corpus) ([]unit, error) {
	dest := filepath.Join(e.cache, c.Name)
	if err := e.fetchRepo(dest, c.Repo, c.Rev, c.Sparse); err != nil {
		return nil, err
	}
	if len(c.Queries) == 0 {
		return nil, fmt.Errorf("queries are missing")
	}
	filters, err := compileKICSFilters(dest, c.Queries, c.QueryFilters)
	if err != nil {
		return nil, err
	}
	stage := filepath.Join(e.cache, c.Name+"-stage")
	if err := os.RemoveAll(stage); err != nil {
		return nil, err
	}
	meta := map[string]*kicsMeta{}
	var excluded int
	for _, query := range sortedKeys(c.Queries) {
		top, _, _ := strings.Cut(query, "/")
		exts, ok := kicsExt[top]
		if !ok {
			return nil, fmt.Errorf("query %s: unknown platform %q", query, top)
		}
		testDir := filepath.Join(dest, "assets", "queries", filepath.FromSlash(query), "test")
		keyData, err := os.ReadFile(filepath.Join(testDir, "positive_expected_result.json"))
		if err != nil {
			return nil, fmt.Errorf("query %s: %w", query, err)
		}
		var expected []struct {
			FileName string `json:"fileName"`
		}
		if err := json.Unmarshal(keyData, &expected); err != nil {
			return nil, fmt.Errorf("query %s: %w", query, err)
		}
		files := map[string]bool{} // file name -> positive
		for _, x := range expected {
			files[x.FileName] = true
		}
		entries, err := os.ReadDir(testDir)
		if err != nil {
			return nil, err
		}
		for _, en := range entries {
			if strings.HasPrefix(en.Name(), "negative") {
				files[en.Name()] = files[en.Name()] || false
			}
		}
		rules := map[string]bool{}
		for _, r := range c.Queries[query] {
			rules[r] = true
		}
		cat := strings.TrimPrefix(c.Queries[query][0], "sast:")
		if meta[top] == nil {
			meta[top] = &kicsMeta{}
		}
		for _, name := range sortedKeys(files) {
			src := filepath.Join(testDir, name)
			// A case that is a directory of files, or in another format, is left out.
			if info, err := os.Stat(src); err != nil || !info.Mode().IsRegular() || !slices.Contains(exts, strings.ToLower(filepath.Ext(name))) {
				excluded++
				continue
			}
			target := name
			if s := kicsStaged[top]; s != "" {
				target = s
			}
			caseDir := path.Join(query, strings.TrimSuffix(name, filepath.Ext(name)))
			rel := path.Join(caseDir, target)
			if err := copyFile(src, filepath.Join(stage, filepath.FromSlash(rel))); err != nil {
				return nil, err
			}
			meta[top].cases = append(meta[top].cases, kicsCase{file: rel, rules: rules, real: files[name], cat: cat, match: filters[query]})
		}
	}
	var units []unit
	for _, top := range sortedKeys(meta) {
		if len(meta[top].cases) == 0 {
			continue
		}
		units = append(units, unit{Name: top, Dir: filepath.Join(stage, top), Prefix: top, Meta: &kicsMeta{cases: meta[top].cases}})
	}
	if len(units) > 0 {
		units[0].Meta.(*kicsMeta).excluded = excluded
	}
	return units, nil
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
}

func (kicsSuite) score(e *env, c *corpus, units []unit, res map[string]*unitResult) (*accuracy, error) {
	t := newTally(true)
	for _, u := range units {
		m := u.Meta.(*kicsMeta)
		r := res[u.Name]
		t.acc.AnalysisIncomplete += r.incomplete
		t.acc.Excluded += m.excluded
		findings := map[string][]finding{}
		for _, f := range r.findings {
			findings[f.File] = append(findings[f.File], f)
		}
		for _, cs := range m.cases {
			hit := slices.ContainsFunc(findings[cs.file], func(f finding) bool {
				return cs.rules[f.ID] && cs.match.matches(f)
			})
			t.add(cs.cat, cs.real, hit)
		}
	}
	return t.result(), nil
}
