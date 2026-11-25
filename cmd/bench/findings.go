package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type loc struct {
	File string
	Line int
}

// finding is a lafke finding reduced to what the scorers use.
type finding struct {
	ID      string
	Detail  string
	Subject string
	CWEs    []int
	File    string // slash-separated, relative to the repository root
	Line    int
	Trace   []loc
}

var cweRe = regexp.MustCompile(`CWE-(\d+)`)

// parseFindings reads a lafke json report. prefix is prepended to every file name. Findings that
// are not reports of a vulnerability (analysis-incomplete and secrets-unchecked) are not
// returned; the number of analysis-incomplete findings is.
func parseFindings(report []byte, prefix string) ([]finding, int, error) {
	var rep struct {
		Findings []struct {
			ID       string `json:"id"`
			Title    string `json:"title"`
			Detail   string `json:"detail"`
			Subject  string `json:"subject"`
			Location struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"location"`
			Trace []struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"trace"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(report, &rep); err != nil {
		return nil, 0, fmt.Errorf("parse the lafke report: %w", err)
	}
	norm := func(f string) string {
		f = filepath.ToSlash(f)
		if prefix != "" {
			f = strings.TrimSuffix(prefix, "/") + "/" + f
		}
		return f
	}
	var out []finding
	incomplete := 0
	for _, f := range rep.Findings {
		switch f.ID {
		case "sast:analysis-incomplete":
			incomplete++
			continue
		case "sast:secrets-unchecked":
			continue
		}
		fd := finding{ID: f.ID, Detail: f.Detail, Subject: f.Subject, File: norm(f.Location.File), Line: f.Location.Line}
		for _, m := range cweRe.FindAllStringSubmatch(f.Title, -1) {
			n, _ := strconv.Atoi(m[1])
			fd.CWEs = append(fd.CWEs, n)
		}
		for _, t := range f.Trace {
			fd.Trace = append(fd.Trace, loc{norm(t.File), t.Line})
		}
		out = append(out, fd)
	}
	return out, incomplete, nil
}

// ruleName is the part of a rule id after the language, such as sql-injection.
func ruleName(id string) string {
	if i := strings.LastIndex(id, "/"); i >= 0 {
		return id[i+1:]
	}
	return id
}

// cweGroups says which CWEs mean the same weakness. lafke reports one generic CWE per rule
// (CWE-327 for every weak cipher or hash, CWE-338 for weak randomness), while the benchmarks use
// more specific ones.
type cweGroups map[int]int // cwe -> group number, 1-based

func newCWEGroups(groups [][]int) cweGroups {
	g := cweGroups{}
	for i, grp := range groups {
		for _, c := range grp {
			g[c] = i + 1
		}
	}
	return g
}

// same reports whether found is expected or in the same group as it.
func (g cweGroups) same(expected, found int) bool {
	if expected == found {
		return true
	}
	a, ok := g[expected]
	return ok && a == g[found]
}

// inScope reports whether a CWE is in some group, which is how a corpus declares that lafke
// attempts it.
func (g cweGroups) inScope(cwe int) bool { _, ok := g[cwe]; return ok }

func (g cweGroups) matchAny(expected int, found []int) bool {
	for _, c := range found {
		if g.same(expected, c) {
			return true
		}
	}
	return false
}
